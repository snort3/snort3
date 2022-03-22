//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "control/control.h"
#include "detection/signature.h"
#include "framework/module.h"
#include "helpers/process.h"
#include "helpers/ring.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/reload_tracker.h"
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
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/trough.h"
#include "target_based/host_attributes.h"
#include "time/periodic.h"
#include "trace/trace_api.h"
#include "trace/trace_config.h"
#include "trace/trace_logger.h"
#include "utils/util.h"
#include "utils/safec.h"

#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
#include "catch/unit_test.h"
#endif

#ifdef PIGLET
#include "piglet/piglet.h"
#endif

#ifdef SHELL
#include "control/control_mgmt.h"
#include "main/ac_shell_cmd.h"
#endif

//-------------------------------------------------------------------------

using namespace snort;

static bool exit_requested = false;
static int main_exit_code = 0;
static bool paused = false;
static bool all_pthreads_started = false;
static std::queue<AnalyzerCommand*> orphan_commands;

static std::mutex poke_mutex;
static Ring<unsigned>* pig_poke = nullptr;

const struct timespec main_sleep = { 0, 1000000 }; // 0.001 sec

static const char* prompt = "o\")~ ";

const char* get_prompt()
{ return prompt; }
static bool use_shell(const SnortConfig* sc)
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

//-------------------------------------------------------------------------
// pig foo
//-------------------------------------------------------------------------

class Pig
{
public:
    Pig() = default;

    void set_index(unsigned index) { idx = index; }

    bool prep(const char* source);
    void start();
    void stop();

    bool queue_command(AnalyzerCommand*, bool orphan = false);
    void reap_commands();

    Analyzer* analyzer = nullptr;
    bool awaiting_privilege_change = false;
    bool requires_privileged_start = true;

private:
    void reap_command(AnalyzerCommand* ac);

    // we could just let the analyzer own this pointer and delete
    // immediately after getting the data but that creates memory
    // count mismatches between main and packet threads. since the
    // startup swapper has no old config to delete only 32 bytes
    // after held.
    Swapper* swapper = nullptr;

    std::thread* athread = nullptr;
    unsigned idx = (unsigned)-1;
};

bool Pig::prep(const char* source)
{
    const SnortConfig* sc = SnortConfig::get_conf();
    SFDAQInstance *instance = new SFDAQInstance(source, idx, sc->daq_config);

    if (!SFDAQ::init_instance(instance, sc->bpf_filter))
    {
        delete instance;
        return false;
    }
    requires_privileged_start = instance->can_start_unprivileged();
    analyzer = new Analyzer(instance, idx, source, sc->pkt_cnt);
    analyzer->set_skip_cnt(sc->pkt_skip);
#ifdef REG_TEST
    analyzer->set_pause_after_cnt(sc->pkt_pause_cnt);
#endif
    return true;
}

void Pig::start()
{
    static uint16_t run_num = 0;
    assert(!athread);
    LogMessage("++ [%u] %s\n", idx, analyzer->get_source());

    swapper = new Swapper(SnortConfig::get_main_conf());
    athread = new std::thread(std::ref(*analyzer), swapper, ++run_num);
}

void Pig::stop()
{
    assert(analyzer);
    assert(athread);

    delete swapper;
    swapper = nullptr;

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
    debug_logf(snort_trace, TRACE_MAIN, nullptr, "[%u] Queuing command %s for execution (refcount %u)\n",
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
        debug_logf(snort_trace, TRACE_MAIN, nullptr, "[%u] Destroying completed command %s\n",
            idx, ac->stringify());
        delete ac;
    }
#ifdef DEBUG_MSGS
    else
        debug_logf(snort_trace, TRACE_MAIN, nullptr, "[%u] Reaped ongoing command %s (refcount %u)\n",
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


static bool* pigs_started = nullptr;
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

static AnalyzerCommand* get_command(AnalyzerCommand* ac, ControlConn* ctrlcon)
{
#ifndef SHELL
    UNUSED(ctrlcon);
#else
    if (ctrlcon)
        return ( new ACShellCmd(ctrlcon, ac) );
    else
#endif
        return ac;
}

static void send_response(ControlConn* ctrlcon, const char* response)
{
    if (ctrlcon)
        ctrlcon->respond("%s", response);
    else
        LogMessage("%s", response);
}

void snort::main_broadcast_command(AnalyzerCommand* ac, ControlConn* ctrlcon)
{
    unsigned dispatched = 0;

    ac = get_command(ac, ctrlcon);
    debug_logf(snort_trace, TRACE_MAIN, nullptr, "Broadcasting %s command\n", ac->stringify());
    if (ac->need_update_reload_id())
        SnortConfig::get_main_conf()->update_reload_id();

    for (unsigned idx = 0; idx < max_pigs; ++idx)
    {
        if (pigs[idx].queue_command(ac))
            dispatched++;
    }

    if (!dispatched)
        orphan_commands.push(ac);
}

#ifdef REG_TEST
void snort::main_unicast_command(AnalyzerCommand* ac, unsigned target,  ControlConn* ctrlcon)
{
    assert(target < max_pigs);
    ac = get_command(ac, ctrlcon);
    if (!pigs[target].queue_command(ac))
        orphan_commands.push(ac);
}
#endif

int main_dump_stats(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    send_response(ctrlcon, "== dumping stats\n");
    main_broadcast_command(new ACGetStats(ctrlcon), ctrlcon);
    return 0;
}

int main_reset_stats(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    int type = luaL_optint(L, 1, 0);
    ctrlcon->respond("== clearing stats\n");
    main_broadcast_command(new ACResetStats(static_cast<clear_counter_type_t>(type)), ctrlcon);
    return 0;
}

int main_rotate_stats(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    send_response(ctrlcon, "== rotating stats\n");
    main_broadcast_command(new ACRotate(), ctrlcon);
    return 0;
}

int main_reload_config(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    const char* fname =  nullptr;
    const char* plugin_path =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        if (lua_gettop(L) >= 1)
            fname = luaL_checkstring(L, 1);

        if (lua_gettop(L) > 1)
        {
            plugin_path = luaL_checkstring(L, 2);
            std::ostringstream plugin_path_msg;
            plugin_path_msg << "-- reload plugin_path: " << plugin_path << "\n";
            send_response(ctrlcon, plugin_path_msg.str().c_str());
        }
    }

    if ( !ReloadTracker::start(ctrlcon) )
    {
        send_response(ctrlcon, "== reload pending; retry\n");
        return 0;
    }
    send_response(ctrlcon, ".. reloading configuration\n");
    ReloadTracker::update(ctrlcon,"start loading ...");
    const SnortConfig* old = SnortConfig::get_conf();
    SnortConfig* sc = Snort::get_reload_config(fname, plugin_path, old);

    if ( !sc )
    {
        if (get_reload_errors())
        {
            std::string response_message = "== reload failed - restart required - ";
            response_message += get_reload_errors_description() + "\n";
            ReloadTracker::failed(ctrlcon, "restart required");
            send_response(ctrlcon, response_message.c_str());
            reset_reload_errors();
        }
        else
        {
            ReloadTracker::failed(ctrlcon, "bad config");
            send_response(ctrlcon, "== reload failed - bad config\n");
        }


        HostAttributesManager::load_failure_cleanup();
        return 0;
    }

    int32_t num_hosts = HostAttributesManager::get_num_host_entries();
    if ( num_hosts >= 0 )
        LogMessage( "host attribute table: %d hosts loaded\n", num_hosts);
    else
        LogMessage("No host attribute table loaded\n");

    if ( !old or !old->trace_config or !old->trace_config->initialized )
    {
        LogMessage("== WARNING: Trace module was not configured during "
            "initial startup. Ignoring the new trace configuration.\n");
        sc->trace_config->clear();
    }

    PluginManager::reload_so_plugins_cleanup(sc);
    SnortConfig::set_conf(sc);
    TraceApi::thread_reinit(sc->trace_config);
    proc_stats.conf_reloads++;

    ReloadTracker::update(ctrlcon, "start swapping configuration ...");
    send_response(ctrlcon, ".. swapping configuration\n");
    main_broadcast_command(new ACSwap(new Swapper(old, sc), ctrlcon), ctrlcon);

    return 0;
}

int main_reload_policy(lua_State* L)
{
    const char* fname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        if (lua_gettop(L) >= 1)
            fname = luaL_checkstring(L, 1);
    }

    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( !fname or *fname == '\0' )
    {
        send_response(ctrlcon, "== filename required\n");
        return 0;
    }

    if ( !ReloadTracker::start(ctrlcon) )
    {
        send_response(ctrlcon, "== reload pending; retry\n");
        return 0;
    }

    send_response(ctrlcon, ".. reloading policy\n");

    SnortConfig* old = SnortConfig::get_main_conf();
    SnortConfig* sc = Snort::get_updated_policy(old, fname, nullptr);

    if ( !sc )
    {
        ReloadTracker::failed(ctrlcon, "failed to update policy");
        send_response(ctrlcon, "== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.policy_reloads++;

    ReloadTracker::update(ctrlcon, "start swapping configuration ...");
    send_response(ctrlcon, ".. swapping policy\n");
    main_broadcast_command(new ACSwap(new Swapper(old, sc), ctrlcon), ctrlcon);

    return 0;
}

int main_reload_module(lua_State* L)
{
    const char* fname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        if (lua_gettop(L) >= 1)
            fname = luaL_checkstring(L, 1);
    }

    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( !fname or *fname == '\0' )
    {
        send_response(ctrlcon, "== module name required\n");
        return 0;
    }

    if ( !ReloadTracker::start(ctrlcon) )
    {
        send_response(ctrlcon, "== reload pending; retry\n");
        return 0;
    }

    send_response(ctrlcon, ".. reloading module\n");

    SnortConfig* old = SnortConfig::get_main_conf();
    SnortConfig* sc = Snort::get_updated_module(old, fname);

    if ( !sc )
    {
        ReloadTracker::failed(ctrlcon, "failed to update module");
        send_response(ctrlcon, "== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.policy_reloads++;

    ReloadTracker::update(ctrlcon, "start swapping configuration ...");
    send_response(ctrlcon, ".. swapping module\n");
    main_broadcast_command(new ACSwap(new Swapper(old, sc), ctrlcon), ctrlcon);

    return 0;
}

int main_reload_daq(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    send_response(ctrlcon, ".. reloading daq module\n");
    main_broadcast_command(new ACDAQSwap(), ctrlcon);
    proc_stats.daq_reloads++;

    return 0;
}

int main_reload_hosts(lua_State* L)
{
    SnortConfig* sc = SnortConfig::get_main_conf();
    const char* fname;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        fname = luaL_optstring(L, 1, sc->attribute_hosts_file.c_str());
    }
    else
        fname = sc->attribute_hosts_file.c_str();

    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( !fname or *fname == '\0' )
    {
        send_response(ctrlcon, "== filename required\n");
        return 0;
    }

    if ( !ReloadTracker::start(ctrlcon) )
    {
        send_response(ctrlcon, "== reload pending; retry\n");
        return 0;
    }

    std::string msg = "Reloading Host attribute table from ";
    msg += fname;
    ReloadTracker::update(ctrlcon, msg.c_str());
    send_response(ctrlcon, ".. reloading hosts table\n");

    if ( !HostAttributesManager::load_hosts_file(sc, fname) )
    {
        ReloadTracker::failed(ctrlcon, "failed to load host table.");
        send_response(ctrlcon, "== reload failed\n");
        return 0;
    }

    proc_stats.attribute_table_reloads++;
    int32_t num_hosts = HostAttributesManager::get_num_host_entries();
    assert( num_hosts >= 0 );
    LogMessage("Host attribute table: %d hosts loaded successfully.\n", num_hosts);

    ReloadTracker::update(ctrlcon, "start swapping configuration ...");
    send_response(ctrlcon, ".. swapping hosts table\n");
    main_broadcast_command(new ACHostAttributesSwap(ctrlcon), ctrlcon);

    return 0;
}

int main_delete_inspector(lua_State* L)
{
    const char* iname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        if (lua_gettop(L) >= 1)
            iname = luaL_checkstring(L, 1);
    }

    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( !iname or *iname == '\0' )
    {
        send_response(ctrlcon, "== inspector name required\n");
        return 0;
    }

    if ( !ReloadTracker::start(ctrlcon) )
    {
        send_response(ctrlcon, "== delete pending; retry\n");
        return 0;
    }

    send_response(ctrlcon, ".. deleting inspector\n");

    SnortConfig* old = SnortConfig::get_main_conf();
    SnortConfig* sc = Snort::get_updated_policy(old, nullptr, iname);

    if ( !sc )
    {
        ReloadTracker::failed(ctrlcon, "failed to update policy");
        send_response(ctrlcon, "== reload failed\n");
        return 0;
    }
    SnortConfig::set_conf(sc);
    proc_stats.inspector_deletions++;

    ReloadTracker::update(ctrlcon, "start swapping configuration ...");
    send_response(ctrlcon, ".. deleted inspector\n");
    main_broadcast_command(new ACSwap(new Swapper(old, sc), ctrlcon), ctrlcon);

    return 0;
}

int main_process(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    const char* f = lua_tostring(L, 1);
    if ( !f )
    {
        send_response(ctrlcon, "== pcap filename required\n");
        return 0;
    }
    send_response(ctrlcon, "== queuing pcap\n");
    Trough::add_source(Trough::SOURCE_LIST, f);
    return 0;
}

int main_pause(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    send_response(ctrlcon, "== pausing\n");
    main_broadcast_command(new ACPause(), ctrlcon);
    paused = true;
    return 0;
}

int main_resume(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    uint64_t pkt_num = 0;

    #ifdef REG_TEST
    int target = -1;
    #endif

    if (L)
    {
        const int num_of_args = lua_gettop(L);
        if (num_of_args)
        {
            pkt_num = lua_tointeger(L, 1);
            if (pkt_num < 1)
            {
                send_response(ctrlcon, "Invalid usage of resume(n), n should be a number > 0\n");
                return 0;
            }
            #ifdef REG_TEST
            if (num_of_args > 1)
            {
                target = lua_tointeger(L, 2);
                if (target < 0 or unsigned(target) >= max_pigs)
                {
                    send_response(ctrlcon,
                        "Invalid usage of resume(n,m), m should be a number >= 0 and less than number of threads\n");
                    return 0;
                }
            }
            #endif
        }
    }
    send_response(ctrlcon, "== resuming\n");

    #ifdef REG_TEST
    if (target >= 0)
        main_unicast_command(new ACResume(pkt_num), target, ctrlcon);
    else
        main_broadcast_command(new ACResume(pkt_num), ctrlcon);
    #else
    main_broadcast_command(new ACResume(pkt_num), ctrlcon);
    #endif
    paused = false;
    return 0;
}

#ifdef SHELL
int main_detach(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    send_response(ctrlcon, "== detaching\n");
    ctrlcon->shutdown();
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
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    send_response(ctrlcon, "== stopping\n");
    main_broadcast_command(new ACStop(), ctrlcon);
    exit_requested = true;
    return 0;
}

int main_help(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    std::list<Module*> modules = ModuleManager::get_all_modules();
    for (const auto& m : modules)
    {
        const Command* cmd = m->get_commands();
        if (!cmd)
            continue;
        std::string prefix;
        if (strcmp(m->get_name(), "snort"))
        {
            prefix = m->get_name();
            prefix += '.';
        }
        while (cmd->name)
        {
            std::string info = prefix;
            info += cmd->name;
            info += cmd->get_arg_list();
            info += ": ";
            info += cmd->help;
            info += "\n";
            send_response(ctrlcon, info.c_str());
            ++cmd;
        }
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
        debug_logf(snort_trace, TRACE_MAIN, nullptr, "Destroying orphan command %s\n", ac->stringify());
        delete ac;
    }
}

// FIXIT-L return true if something was done to avoid sleeping
static bool house_keeping()
{
    if (all_pthreads_started)
        signal_check();

    reap_commands();

    Periodic::check();

    InspectorManager::empty_trash();

    return false;
}

static void service_check()
{
#ifdef SHELL
    if (all_pthreads_started && ControlMgmt::service_users() )
        return;
#endif

    if ( house_keeping() )
        return;

    nanosleep(&main_sleep, nullptr);
}

//-------------------------------------------------------------------------
// main foo
//-------------------------------------------------------------------------

static bool just_validate(const SnortConfig* sc)
{
    if ( sc->test_mode() )
        return true;

    if ( use_shell(sc) )
        return false;

    if ( sc->daq_config->module_configs.empty() )
    {
        if ( sc->read_mode() && !Trough::get_queue_size() )
            return true;

        if ( !sc->read_mode() && !SFDAQ::get_input_spec(sc->daq_config, 0) )
            return true;
    }

    return false;
}

static bool set_mode()
{
#ifdef PIGLET
    if ( Piglet::piglet_mode() )
    {
        main_exit_code = Piglet::main();
        return false;
    }
#endif
#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
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

    SnortConfig* sc = SnortConfig::get_main_conf();

    if ( sc->conf_error_out() )
    {
        if ( warnings )
            FatalError("see prior %u warnings\n", warnings);
    }

    if ( sc->dump_msg_map() )
    {
        dump_msg_map(sc);
        return false;
    }

    if ( sc->dump_rule_deps() )
    {
        dump_rule_deps(sc);
        return false;
    }

    if ( sc->dump_rule_meta() )
    {
        dump_rule_meta(sc);
        return false;
    }

    if ( sc->dump_rule_state() )
    {
        dump_rule_state(sc);
        return false;
    }

    if ( just_validate(sc) )
    {
        LogMessage("\nSnort successfully validated the configuration (with %u warnings).\n",
            warnings);

        // force test mode to exit w/o stats
        sc->run_flags |= RUN_FLAG__TEST;
        return false;
    }

    if ( sc->run_flags & RUN_FLAG__PAUSE )
    {
        LogMessage("Paused; resume to start packet processing\n");
        paused = true;
    }
    else
        LogMessage("Commencing packet processing\n");

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
        if (pig.requires_privileged_start && pending_privileges &&
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
        if (!pig.requires_privileged_start && pending_privileges &&
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

    if (SnortConfig::get_conf()->change_privileges())
        pending_privileges = max_pigs;

    // Preemptively prep all pigs in live traffic mode
    if (!SnortConfig::get_conf()->read_mode())
    {
        for (unsigned i = 0; i < max_pigs; i++)
        {
            if (pigs[i].prep(SFDAQ::get_input_spec(SnortConfig::get_conf()->daq_config, i)))
                swine++;
        }
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
            {
                handle(pig, swine, pending_privileges);
                if (!pigs_started[idx] && pig.analyzer && (pig.analyzer->get_state() ==
                    Analyzer::State::STARTED))
                    pigs_started[idx] = true;
            }
            else if ( pending_privileges )
                pending_privileges--;

            if ( !swine and exit_requested )
                break;

            continue;
        }

        if (!all_pthreads_started)
        {
            all_pthreads_started = true;
            const unsigned num_threads = (!Trough::has_next()) ? swine : max_pigs;
            for (unsigned i = 0; i < num_threads; i++)
                all_pthreads_started &= pigs_started[i];
            if (all_pthreads_started)
            {
#ifdef REG_TEST
                LogMessage("All pthreads started\n");
#endif
#ifdef SHELL
                if (use_shell(SnortConfig::get_conf()))
                {
                    LogMessage("Entering command shell\n");
                    ControlMgmt::add_control(STDOUT_FILENO, true);
                }
#endif
            }
        }

        if ( !exit_requested and (swine < max_pigs) and (src = Trough::get_next()) )
        {
            Pig* pig = get_lazy_pig(max_pigs);
            if (pig->prep(src))
                ++swine;
            continue;
        }
        service_check();
    }
}

static void snort_main()
{
#ifdef SHELL
    ControlMgmt::socket_init(SnortConfig::get_conf());
#endif

    SnortConfig::get_conf()->thread_config->implement_thread_affinity(
        STHREAD_TYPE_MAIN, get_instance_id());

    max_pigs = ThreadConfig::get_instance_max();
    assert(max_pigs > 0);
    ThreadConfig::start_watchdog();

    // maximum number of state change notifications per pig
    constexpr unsigned max_grunts = static_cast<unsigned>(Analyzer::State::NUM_STATES);

    pig_poke = new Ring<unsigned>((max_pigs*max_grunts)+1);
    pigs = new Pig[max_pigs];
    pigs_started = new bool[max_pigs];

    for (unsigned idx = 0; idx < max_pigs; idx++)
    {
        Pig& pig = pigs[idx];
        pig.set_index(idx);
        pigs_started[idx] = false;
    }

    main_loop();

    delete pig_poke;
    delete[] pigs;
    pigs = nullptr;
    delete[] pigs_started;
    pigs_started = nullptr;

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

    set_thread_type(STHREAD_TYPE_MAIN);

    Snort::setup(argc, argv);

    if ( set_mode() )
        snort_main();

    Snort::cleanup();

    return main_exit_code;
}

