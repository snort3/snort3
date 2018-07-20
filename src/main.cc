//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// main.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main.h"

#include <thread>

#include "control/idle_processing.h"
#include "framework/module.h"
#include "helpers/process.h"
#include "helpers/ring.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/request.h"
#include "main/shell.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/snort_module.h"
#include "main/swapper.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "target_based/sftarget_reader.h"
#include "time/periodic.h"
#include "utils/util.h"
#include "utils/safec.h"

#ifdef UNIT_TEST
#include "catch/unit_test.h"
#endif

#ifdef PIGLET
#include "piglet/piglet.h"
#endif

#ifdef SHELL
#include "main/control_mgmt.h"
#endif

//-------------------------------------------------------------------------

using namespace snort;

static bool exit_requested = false;
static int main_exit_code = 0;
static bool paused = false;
static std::queue<AnalyzerCommand*> orphan_commands;

static std::mutex poke_mutex;
static Ring<unsigned>* pig_poke = nullptr;

const struct timespec main_sleep = { 0, 1000000 }; // 0.001 sec

static const char* prompt = "o\")~ ";

const char* get_prompt()
{ return prompt; }

static bool use_shell(SnortConfig* sc)
{
#ifdef SHELL
    return ( sc->run_flags & RUN_FLAG__SHELL );
#else
    UNUSED(sc);
    return false;
#endif
}

// FIXIT-L X Replace main_poke()/main_read() usage with command objects
void main_poke(unsigned id)
{
    std::lock_guard<std::mutex> lock(poke_mutex);
    pig_poke->put(id);
}

static int main_read()
{
    std::lock_guard<std::mutex> lock(poke_mutex);
    return pig_poke->get(-1);
}

static Request request;
static Request* current_request = &request;
#ifdef SHELL
static int current_fd = -1;
#endif

//-------------------------------------------------------------------------
// pig foo
//-------------------------------------------------------------------------

class Pig
{
public:
    Analyzer* analyzer;
    bool awaiting_privilege_change = false;

    Pig() { analyzer = nullptr; athread = nullptr; idx = (unsigned)-1; }

    void set_index(unsigned index) { idx = index; }

    void prep(const char* source);
    void start();
    void stop();

    bool queue_command(AnalyzerCommand*, bool orphan = false);
    void reap_commands();

private:
    void reap_command(AnalyzerCommand* ac);

    std::thread* athread;
    unsigned idx;
};

void Pig::prep(const char* source)
{
    analyzer = new Analyzer(idx, source);
}

void Pig::start()
{
    static uint16_t run_num = 0;
    assert(!athread);
    LogMessage("++ [%u] %s\n", idx, analyzer->get_source());

    Swapper* ps = new Swapper(SnortConfig::get_conf(), SFAT_GetConfig());
    athread = new std::thread(std::ref(*analyzer), ps, ++run_num);
}

void Pig::stop()
{
    assert(analyzer);
    assert(athread);

    athread->join();
    delete athread;
    athread = nullptr;

    LogMessage("-- [%u] %s\n", idx, analyzer->get_source());

    // Reap all analyzer commands, completed or not.
    // FIXIT-L X Add concept of finalizing commands differently based on whether they were
    //  completed or not when we have commands that care about that.
    while (!analyzer->completed_work_queue.empty())
    {
        reap_command(analyzer->completed_work_queue.front());
        analyzer->completed_work_queue.pop();
    }
    while (!analyzer->pending_work_queue.empty())
    {
        reap_command(analyzer->pending_work_queue.front());
        analyzer->pending_work_queue.pop();
    }
    delete analyzer;
    analyzer = nullptr;
}

bool Pig::queue_command(AnalyzerCommand* ac, bool orphan)
{
    if (!analyzer || !athread)
    {
        if (orphan)
            orphan_commands.push(ac);
        return false;
    }

#ifdef DEBUG_MSGS
    unsigned ac_ref_count = ac->get();
    trace_logf(snort, "[%u] Queuing command %s for execution (refcount %u)\n",
            idx, ac->stringify(), ac_ref_count);
#else
    ac->get();
#endif
    analyzer->execute(ac);
    return true;
}

void Pig::reap_command(AnalyzerCommand* ac)
{
    unsigned ac_ref_count = ac->put();
    if (ac_ref_count == 0)
    {
        trace_logf(snort, "[%u] Destroying completed command %s\n",
                idx, ac->stringify());
        delete ac;
    }
#ifdef DEBUG_MSGS
    else
        trace_logf(snort, "[%u] Reaped ongoing command %s (refcount %u)\n",
                idx, ac->stringify(), ac_ref_count);
#endif
}

void Pig::reap_commands()
{
    if (!analyzer)
        return;
    size_t commands_to_reap;
    do
    {
        AnalyzerCommand* ac = nullptr;
        analyzer->completed_work_queue_mutex.lock();
        commands_to_reap = analyzer->completed_work_queue.size();
        if (commands_to_reap)
        {
            ac = analyzer->completed_work_queue.front();
            analyzer->completed_work_queue.pop();
        }
        analyzer->completed_work_queue_mutex.unlock();
        if (ac)
            reap_command(ac);
    } while (commands_to_reap > 1);
}

static Pig* pigs = nullptr;
static unsigned max_pigs = 0;

static Pig* get_lazy_pig(unsigned max)
{
    for ( unsigned i = 0; i < max; ++i )
        if ( !pigs[i].analyzer )
            return pigs + i;

    assert(false);
    return nullptr;
}

//-------------------------------------------------------------------------
// main commands
//-------------------------------------------------------------------------

static AnalyzerCommand* get_command(AnalyzerCommand* ac, bool from_shell)
{
#ifndef SHELL
    UNUSED(from_shell);
#else
    if ( from_shell )
        return ( new ACShellCmd(current_fd, ac) );
    else
#endif
        return ac;
}

void snort::main_broadcast_command(AnalyzerCommand* ac, bool from_shell)
{
    unsigned dispatched = 0;
    
    ac = get_command(ac, from_shell);
    trace_logf(snort, "Broadcasting %s command\n", ac->stringify());

    for (unsigned idx = 0; idx < max_pigs; ++idx)
    {
        if (pigs[idx].queue_command(ac))
            dispatched++;
    }

    if (!dispatched)
        orphan_commands.push(ac);
}

int main_dump_stats(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    current_request->respond("== dumping stats\n", from_shell);
    main_broadcast_command(new ACGetStats(), from_shell);
    return 0;
}

int main_rotate_stats(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    current_request->respond("== rotating stats\n", from_shell);
    main_broadcast_command(new ACRotate(), from_shell);
    return 0;
}

int main_reload_config(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        current_request->respond("== reload pending; retry\n");
        return 0;
    }
    const char* fname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        fname = luaL_checkstring(L, 1);
    }

    current_request->respond(".. reloading configuration\n");
    SnortConfig* old = SnortConfig::get_conf();
    SnortConfig* sc = Snort::get_reload_config(fname);

    if ( !sc )
    {
        current_request->respond("== reload failed\n");
        return 0;
    }

    tTargetBasedConfig* old_tc = SFAT_GetConfig();
    tTargetBasedConfig* tc = SFAT_Swap();

    if ( !tc )
    {
        current_request->respond("== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.conf_reloads++;

    bool from_shell = ( L != nullptr );
    current_request->respond(".. swapping configuration\n", from_shell);
    main_broadcast_command(new ACSwap(new Swapper(old, sc, old_tc, tc)), from_shell);

    return 0;
}

int main_reload_policy(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        current_request->respond("== reload pending; retry\n");
        return 0;
    }
    const char* fname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        fname = luaL_checkstring(L, 1);
    }

    if ( fname and *fname )
        current_request->respond(".. reloading policy\n");
    else
    {
        current_request->respond("== filename required\n");
        return 0;
    }

    SnortConfig* old = SnortConfig::get_conf();
    SnortConfig* sc = Snort::get_updated_policy(old, fname, nullptr);

    if ( !sc )
    {
        current_request->respond("== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.policy_reloads++;

    bool from_shell = ( L != nullptr );
    current_request->respond(".. swapping policy\n", from_shell);
    main_broadcast_command(new ACSwap(new Swapper(old, sc)), from_shell);

    return 0;
}

int main_reload_module(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        current_request->respond("== reload pending; retry\n");
        return 0;
    }
    const char* fname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        fname = luaL_checkstring(L, 1);
    }

    if ( fname and *fname )
        current_request->respond(".. reloading module\n");
    else
    {
        current_request->respond("== module name required\n");
        return 0;
    }

    SnortConfig* old = SnortConfig::get_conf();
    SnortConfig* sc = Snort::get_updated_module(old, fname);

    if ( !sc )
    {
        current_request->respond("== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.policy_reloads++;

    bool from_shell = ( L != nullptr );
    current_request->respond(".. swapping module\n", from_shell);
    main_broadcast_command(new ACSwap(new Swapper(old, sc)), from_shell);

    return 0;
}

int main_reload_daq(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    current_request->respond(".. reloading daq module\n", from_shell);
    main_broadcast_command(new ACDAQSwap(), from_shell);
    proc_stats.daq_reloads++;

    return 0;
}

int main_reload_hosts(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        current_request->respond("== reload pending; retry\n");
        return 0;
    }
    Lua::ManageStack(L, 1);
    const char* fname = luaL_checkstring(L, 1);

    if ( fname and *fname )
        current_request->respond(".. reloading hosts table\n");
    else
    {
        current_request->respond("== filename required\n");
        return 0;
    }

    Shell sh = Shell(fname);
    sh.configure(SnortConfig::get_conf());

    tTargetBasedConfig* old = SFAT_GetConfig();
    tTargetBasedConfig* tc = SFAT_Swap();

    if ( !tc )
    {
        current_request->respond("== reload failed\n");
        return 0;
    }

    bool from_shell = ( L != nullptr );
    current_request->respond(".. swapping hosts table\n", from_shell);
    main_broadcast_command(new ACSwap(new Swapper(old, tc)), from_shell);

    return 0;
}

int main_delete_inspector(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        current_request->respond("== delete pending; retry\n");
        return 0;
    }
    const char* iname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        iname = luaL_checkstring(L, 1);
    }

    if ( iname and *iname )
        current_request->respond(".. deleting inspector\n");
    else
    {
        current_request->respond("== inspector name required\n");
        return 0;
    }

    SnortConfig* old = SnortConfig::get_conf();
    SnortConfig* sc = Snort::get_updated_policy(old, nullptr, iname);

    if ( !sc )
    {
        current_request->respond("== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.inspector_deletions++;

    bool from_shell = ( L != nullptr );
    current_request->respond(".. deleted inspector\n", from_shell);
    main_broadcast_command(new ACSwap(new Swapper(old, sc)), from_shell);

    return 0;
}

int main_process(lua_State* L)
{
    const char* f = lua_tostring(L, 1);
    if ( !f )
    {
        current_request->respond("== pcap filename required\n");
        return 0;
    }
    current_request->respond("== queuing pcap\n");
    Trough::add_source(Trough::SOURCE_LIST, f);
    return 0;
}

int main_pause(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    current_request->respond("== pausing\n", from_shell);
    main_broadcast_command(new ACPause(), from_shell);
    paused = true;
    return 0;
}

int main_resume(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    current_request->respond("== resuming\n", from_shell);
    main_broadcast_command(new ACResume(), from_shell);
    paused = false;
    return 0;
}

#ifdef SHELL
int main_detach(lua_State*)
{
    current_request->respond("== detaching\n");
    return 0;
}

int main_dump_plugins(lua_State*)
{
    ModuleManager::dump_modules();
    PluginManager::dump_plugins();
    return 0;
}
#endif

int main_quit(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    current_request->respond("== stopping\n", from_shell);
    main_broadcast_command(new ACStop(), from_shell);
    exit_requested = true;
    return 0;
}

int main_help(lua_State*)
{
    const Command* cmd = get_snort_module()->get_commands();

    while ( cmd->name )
    {
        std::string info = cmd->name;
        info += cmd->get_arg_list();
        info += ": ";
        info += cmd->help;
        info += "\n";
        current_request->respond(info.c_str());
        ++cmd;
    }
    return 0;
}

//-------------------------------------------------------------------------
// housekeeping foo
//-------------------------------------------------------------------------

static int signal_check()
{
    PigSignal s = get_pending_signal();

    if ( s == PIG_SIG_NONE or s >= PIG_SIG_MAX )
        return 0;

    LogMessage("** caught %s signal\n", get_signal_name(s));

    switch ( s )
    {
    case PIG_SIG_QUIT:
    case PIG_SIG_TERM:
        main_quit();
        break;

    case PIG_SIG_INT:
        if ( paused )
            main_resume(nullptr);
        else
            main_quit();
        break;

    case PIG_SIG_RELOAD_CONFIG:
        main_reload_config();
        break;

    case PIG_SIG_RELOAD_HOSTS:
        main_reload_hosts();
        break;

    case PIG_SIG_DUMP_STATS:
        main_dump_stats();
        break;

    case PIG_SIG_ROTATE_STATS:
        main_rotate_stats();
        break;
    default:
        break;
    }
    proc_stats.signals++;
    return 1;
}

static void reap_commands()
{
    for (unsigned idx = 0; idx < max_pigs; ++idx)
        pigs[idx].reap_commands();

    while (!orphan_commands.empty())
    {
        AnalyzerCommand* ac = orphan_commands.front();
        orphan_commands.pop();
        trace_logf(snort, "Destroying orphan command %s\n", ac->stringify());
        delete ac;
    }
}

// FIXIT-L return true if something was done to avoid sleeping
static bool house_keeping()
{
    signal_check();

    reap_commands();

    IdleProcessing::execute();

    Periodic::check();

    InspectorManager::empty_trash();

    return false;
}

static void service_check()
{
#ifdef SHELL
    if ( ControlMgmt::service_users(current_fd, current_request) )
        return;
#endif

    if ( house_keeping() )
        return;

    nanosleep(&main_sleep, nullptr);
}

//-------------------------------------------------------------------------
// main foo
//-------------------------------------------------------------------------

static bool just_validate()
{
    if ( SnortConfig::test_mode() )
        return true;

    if ( use_shell(SnortConfig::get_conf()) )
        return false;

    /* FIXIT-L X This should really check if the DAQ module was unset as it could be explicitly
        set to the default value */
    if ( !strcmp(SFDAQ::get_type(), SFDAQ::default_type()) )
    {
        if ( SnortConfig::read_mode() && !Trough::get_queue_size() )
            return true;

        if ( !SnortConfig::read_mode() && !SFDAQ::get_input_spec(SnortConfig::get_conf(), 0) )
            return true;
    }

    return false;
}

static bool set_mode()
{
#ifdef PIGLET
    if ( Piglet::piglet_mode() )
    {
        // FIXIT-L the early return means that piglet and catch tests cannot
        // be run in the same process
        main_exit_code = Piglet::main();
        return false;
    }
#endif
#ifdef UNIT_TEST
    // FIXIT-M X we should move this out of set_mode and not do Snort bring up/teardown at all
    if ( catch_enabled() )
    {
        main_exit_code = catch_test();
        return false;
    }
#endif

    unsigned warnings = get_parse_warnings();

    if ( unsigned k = get_parse_errors() )
        FatalError("see prior %u errors (%u warnings)\n", k, warnings);

    if ( SnortConfig::conf_error_out() )
    {
        if ( warnings )
            FatalError("see prior %u warnings\n", warnings);
    }

    if ( just_validate() )
    {
        LogMessage("\nSnort successfully validated the configuration (with %u warnings).\n",
            warnings);

        // force test mode to exit w/o stats
        SnortConfig::get_conf()->run_flags |= RUN_FLAG__TEST;
        return false;
    }

    if ( SnortConfig::get_conf()->run_flags & RUN_FLAG__PAUSE )
    {
        LogMessage("Paused; resume to start packet processing\n");
        paused = true;
    }
    else
        LogMessage("Commencing packet processing\n");

#ifdef SHELL
    if ( use_shell(SnortConfig::get_conf()) )
    {
        LogMessage("Entering command shell\n");
        ControlMgmt::add_control(STDOUT_FILENO, true);
    }
#endif

    return true;
}

static void handle(Pig& pig, unsigned& swine, unsigned& pending_privileges)
{
    switch (pig.analyzer->get_state())
    {
    case Analyzer::State::NEW:
        pig.start();
        break;

    case Analyzer::State::INITIALIZED:
        if (pig.analyzer->requires_privileged_start() && pending_privileges &&
            !Snort::has_dropped_privileges())
        {
            if (!pig.awaiting_privilege_change)
            {
                pig.awaiting_privilege_change = true;
                pending_privileges--;
            }
            if (pending_privileges)
                break;
            // FIXIT-L Make this call and the one below exit more gracefully upon error
            if (!Snort::drop_privileges())
                FatalError("Failed to drop privileges!\n");

            Snort::do_pidfile();
            main_broadcast_command(new ACStart());
        }
        else
        {
            Snort::do_pidfile();
            pig.queue_command(new ACStart(), true);
        }
        break;

    case Analyzer::State::STARTED:
        if (!pig.analyzer->requires_privileged_start() && pending_privileges &&
            !Snort::has_dropped_privileges())
        {
            if (!pig.awaiting_privilege_change)
            {
                pig.awaiting_privilege_change = true;
                pending_privileges--;
            }
            if (pending_privileges)
                break;

            if (!Snort::drop_privileges())
                FatalError("Failed to drop privileges!\n");

            Snort::do_pidfile();
            main_broadcast_command(new ACRun(paused));
        }
        else
        {
            Snort::do_pidfile();
            pig.queue_command(new ACRun(paused), true);
        }
        break;

    case Analyzer::State::STOPPED:
        pig.stop();
        --swine;
        break;

    default:
        break;
    }
}

static void main_loop()
{
    unsigned swine = 0, pending_privileges = 0;

    if (SnortConfig::change_privileges())
        pending_privileges = max_pigs;

    // Preemptively prep all pigs in live traffic mode
    if (!SnortConfig::read_mode())
    {
        for (swine = 0; swine < max_pigs; swine++)
            pigs[swine].prep(SFDAQ::get_input_spec(SnortConfig::get_conf(), swine));
    }

    // Iterate over the drove, spawn them as allowed, and handle their deaths.
    // FIXIT-L X - If an exit has been requested, we might want to have some mechanism
    //             for forcing inconsiderate pigs to die in timely fashion.
    while ( swine or paused or (Trough::has_next() and !exit_requested) )
    {
        const char* src;
        int idx = main_read();

        if ( idx >= 0 )
        {
            Pig& pig = pigs[idx];

            if ( pig.analyzer )
                handle(pig, swine, pending_privileges);

            else if ( pending_privileges )
                pending_privileges--;

            if ( !swine and exit_requested )
                break;

            continue;
        }
        if ( !exit_requested and (swine < max_pigs) and (src = Trough::get_next()) )
        {
            Pig* pig = get_lazy_pig(max_pigs);
            pig->prep(src);
            ++swine;
            continue;
        }
        service_check();
    }
}

static void snort_main()
{
#ifdef SHELL
    ControlMgmt::socket_init();
#endif

    max_pigs = ThreadConfig::get_instance_max();
    assert(max_pigs > 0);

    pig_poke = new Ring<unsigned>(max_pigs+2);
    pigs = new Pig[max_pigs];

    for (unsigned idx = 0; idx < max_pigs; idx++)
    {
        Pig& pig = pigs[idx];
        pig.set_index(idx);
    }

    main_loop();

    delete pig_poke;
    delete[] pigs;
    pigs = nullptr;

#ifdef SHELL
    ControlMgmt::socket_term();
#endif
}

int main(int argc, char* argv[])
{
    set_mem_constraint_handler_s(log_safec_error);
    set_str_constraint_handler_s(log_safec_error);

    const char* s = getenv("SNORT_PROMPT");

    if ( s )
        prompt = s;

    Snort::setup(argc, argv);

    if ( set_mode() )
        snort_main();

    Snort::cleanup();

    return main_exit_code;
}

