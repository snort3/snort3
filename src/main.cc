//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
#include "memory/memory_cap.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "target_based/sftarget_reader.h"
#include "time/periodic.h"
#include "utils/util.h"
#include "utils/safec.h"

#ifdef UNIT_TEST
#include "catch/unit_test_main.h"
#endif

#ifdef PIGLET
#include "piglet/piglet.h"
#endif

//-------------------------------------------------------------------------

static bool exit_requested = false;
static int main_exit_code = 0;
static bool paused = false;
static std::queue<AnalyzerCommand*> orphan_commands;

#ifdef SHELL
static bool shell_enabled = false;
#endif

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

//-------------------------------------------------------------------------
// request foo
//-------------------------------------------------------------------------

class Request
{
public:
    void set(int, const char* = "");
    const char* get() const { return buf; }

    bool read(int&);
    void respond(const char*) const;
    void show_prompt() const;

private:
    int fd;
    char buf[1024];
};

void Request::set(int f, const char* s)
{
    fd = f;
    strncpy(buf, s, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
}

// FIXIT-L ignoring partial reads for now
// using simple text for now so can use telnet as client
// but must parse commands out of stream (ending with \n)
bool Request::read(int& f)
{
    fd = f;
    buf[0] = '\0';
    ssize_t n = ::read(fd, buf, sizeof(buf)-1);

    if ( n <= 0 and errno != EAGAIN and errno != EINTR )
    {
        f = -1;
        return false;
    }

    bool ok = n > 0;

    while ( n > 0 and isspace(buf[--n]) )
        buf[n] = '\0';

    return ok;
}

// FIXIT-L supporting only simple strings for now
// could support var args formats
void Request::respond(const char* s) const
{
    if ( fd < 1 )
    {
        LogMessage("%s", s);
        return;
    }
    // FIXIT-L count errors?
    (void)write(fd, s, strlen(s));  // FIXIT-W ignoring return value
}

// FIXIT-L would like to flush prompt w/o \n
void Request::show_prompt() const
{
    std::string s = prompt;
    s += "\n";
    respond(s.c_str());
}

static Request request;

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

    bool queue_command(AnalyzerCommand*);
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
    assert(!athread);
    LogMessage("++ [%u] %s\n", idx, analyzer->get_source());

    Swapper* ps = new Swapper(snort_conf, SFAT_GetConfig());
    athread = new std::thread(std::ref(*analyzer), ps);
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

bool Pig::queue_command(AnalyzerCommand* ac)
{
    if (!analyzer || !athread)
        return false;

#ifdef DEBUG_MSGS
    unsigned ac_ref_count = ac->get();
    DebugFormat(DEBUG_ANALYZER, "[%u] Queuing command %s for execution (refcount %u)\n",
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
        DebugFormat(DEBUG_ANALYZER, "[%u] Destroying completed command %s\n",
                idx, ac->stringify());
        delete ac;
    }
#ifdef DEBUG_MSGS
    else
        DebugFormat(DEBUG_ANALYZER, "[%u] Reaped ongoing command %s (refcount %u)\n",
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

static void broadcast(AnalyzerCommand* ac)
{
    unsigned dispatched = 0;

    DebugFormat(DEBUG_ANALYZER, "Broadcasting %s command\n", ac->stringify());

    for (unsigned idx = 0; idx < max_pigs; ++idx)
    {
        if (pigs[idx].queue_command(ac))
            dispatched++;
    }

    if (!dispatched)
        orphan_commands.push(ac);
}

int main_dump_stats(lua_State*)
{
    broadcast(new ACGetStats());
    return 0;
}

int main_rotate_stats(lua_State*)
{
    request.respond("== rotating stats\n");
    broadcast(new ACRotate());
    return 0;
}

int main_reload_config(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        request.respond("== reload pending; retry\n");
        return 0;
    }
    const char* fname =  nullptr;

    if ( L )
    {
        Lua::ManageStack(L, 1);
        fname = luaL_checkstring(L, 1);
    }

    request.respond(".. reloading configuration\n");
    SnortConfig* old = snort_conf;
    SnortConfig* sc = Snort::get_reload_config(fname);

    if ( !sc )
    {
        request.respond("== reload failed\n");
        return 0;
    }
    snort_conf = sc;
    proc_stats.conf_reloads++;
    request.respond(".. swapping configuration\n");
    broadcast(new ACSwap(new Swapper(old, sc)));

    return 0;
}

int main_reload_hosts(lua_State* L)
{
    if ( Swapper::get_reload_in_progress() )
    {
        request.respond("== reload pending; retry\n");
        return 0;
    }
    Lua::ManageStack(L, 1);
    const char* fname = luaL_checkstring(L, 1);

    if ( fname and *fname )
        request.respond(".. reloading hosts table\n");
    else
    {
        request.respond("== filename required\n");
        return 0;
    }

    Shell sh = Shell(fname);
    sh.configure(snort_conf);

    tTargetBasedConfig* old = SFAT_GetConfig();
    tTargetBasedConfig* tc = SFAT_Swap();

    if ( !tc )
    {
        request.respond("== reload failed\n");
        return 0;
    }
    request.respond(".. swapping hosts table\n");
    broadcast(new ACSwap(new Swapper(old, tc)));

    return 0;
}

int main_process(lua_State* L)
{
    const char* f = lua_tostring(L, 1);
    if ( !f )
    {
        request.respond("== pcap filename required\n");
        return 0;
    }
    request.respond("== queuing pcap\n");
    Trough::add_source(Trough::SOURCE_LIST, f);
    return 0;
}

int main_pause(lua_State*)
{
    request.respond("== pausing\n");
    broadcast(new ACPause());
    paused = true;
    return 0;
}

int main_resume(lua_State*)
{
    request.respond("== resuming\n");
    broadcast(new ACResume());
    paused = false;
    return 0;
}

#ifdef SHELL
int main_detach(lua_State*)
{
    shell_enabled = false;
    request.respond("== detaching\n");
    return 0;
}

int main_dump_plugins(lua_State*)
{
    ModuleManager::dump_modules();
    PluginManager::dump_plugins();
    return 0;
}
#endif

int main_quit(lua_State*)
{
    request.respond("== stopping\n");
    broadcast(new ACStop());
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
        request.respond(info.c_str());
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
        DebugFormat(DEBUG_ANALYZER, "Destroying orphan command %s\n", ac->stringify());
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

//-------------------------------------------------------------------------
// socket foo
//-------------------------------------------------------------------------

#ifdef SHELL
// FIXIT-M make these non-blocking
// FIXIT-M allow at least 2 remote controls
// FIXIT-M bind to configured ip including INADDR_ANY
// (default is loopback if enabled)
// FIXIT-M block on asynchronous analyzer commands until they complete
static int listener = -1;
static int local_control = STDIN_FILENO;
static int remote_control = -1;

static int socket_init()
{
    if ( !snort_conf->remote_control )
        return -1;

    listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0)
        FatalError("socket failed: %s\n", get_error(errno));

    // FIXIT-M want to disable time wait
    int on = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7F000001);
    addr.sin_port = htons(snort_conf->remote_control);

    if ( ::bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
        FatalError("bind failed: %s\n", get_error(errno));

    // FIXIT-M configure max conns
    if ( listen(listener, 0) < 0 )
        FatalError("listen failed: %s\n", get_error(errno));

    return 0;
}

static int socket_term()
{
    if ( remote_control >= 0 )
        close(remote_control);

    if ( listener >= 0 )
        close(listener);

    listener = remote_control = -1;

    return 0;
}

static int socket_conn()
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    remote_control = accept(listener, (struct sockaddr*)&addr, &len);

    if ( remote_control < 0 )
        return -1;

    // FIXIT-L authenticate, use ssl ?
    return 0;
}

static void shell(int& fd)
{
    std::string rsp;

    if ( !request.read(fd) )
        return;

    SnortConfig* sc = snort_conf;
    sc->policy_map->get_shell()->execute(request.get(), rsp);

    if ( rsp.size() )
        request.respond(rsp.c_str());

    if ( fd >= 0 )
        request.show_prompt();
}

static bool service_users()
{
    fd_set inputs;
    FD_ZERO(&inputs);
    int max_fd = -1;

    if ( shell_enabled and local_control >= 0 )
    {
        FD_SET(local_control, &inputs);
        max_fd = local_control;
    }

    if ( remote_control >= 0 )
    {
        FD_SET(remote_control, &inputs);
        if ( remote_control > max_fd )
            max_fd = remote_control;
    }
    // one remote at a time; the else prevents a new remote
    // from taking control from an existing remote
    else if ( listener >= 0 )
    {
        FD_SET(listener, &inputs);
        if ( listener > max_fd )
            max_fd = listener;
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if ( select(max_fd+1, &inputs, NULL, NULL, &timeout) > 0 )
    {
        if ( FD_ISSET(local_control, &inputs) )
        {
            shell(local_control);
            proc_stats.local_commands++;
            return true;
        }
        else if ( FD_ISSET(remote_control, &inputs) )
        {
            shell(remote_control);
            proc_stats.remote_commands++;
            return true;
        }
        else if ( FD_ISSET(listener, &inputs) )
        {
            if ( !socket_conn() )
            {
                request.set(remote_control);
                request.show_prompt();
                return true;
            }
        }
    }
    return false;
}
#endif

static void service_check()
{
#ifdef SHELL
    if ( service_users() )
        return;
#endif

    if ( house_keeping() )
        return;

    nanosleep(&main_sleep, NULL);
}

//-------------------------------------------------------------------------
// main foo
//-------------------------------------------------------------------------

static bool just_validate()
{
    if ( SnortConfig::test_mode() )
        return true;

    if ( use_shell(snort_conf) )
        return false;

    /* FIXIT-L X This should really check if the DAQ module was unset as it could be explicitly
        set to the default value */
    if ( !strcmp(SFDAQ::get_type(), SFDAQ::default_type()) )
    {
        if ( SnortConfig::read_mode() && !Trough::get_queue_size() )
            return true;

        if ( !SnortConfig::read_mode() && !SFDAQ::get_input_spec(snort_conf, 0) )
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
    // FIXIT-M X we should move this out of set_mode and not do Snort bringup/teardown at all
    if ( catch_enabled() )
    {
        main_exit_code = catch_test();
        return false;
    }
#endif

    if ( int k = get_parse_errors() )
        FatalError("see prior %d errors\n", k);

    if ( SnortConfig::conf_error_out() )
    {
        if ( int k = get_parse_warnings() )
            FatalError("see prior %d warnings\n", k);
    }

    if ( just_validate() )
    {
        LogMessage("\nSnort successfully validated the configuration.\n");

        // force test mode to exit w/o stats
        snort_conf->run_flags |= RUN_FLAG__TEST;
        return false;
    }

    if ( snort_conf->run_flags & RUN_FLAG__PAUSE )
    {
        LogMessage("Paused; resume to start packet processing\n");
        paused = true;
    }
    else
        LogMessage("Commencing packet processing\n");

#ifdef SHELL
    if ( use_shell(snort_conf) )
    {
        LogMessage("Entering command shell\n");
        shell_enabled = true;
        request.set(STDOUT_FILENO, "");
        request.show_prompt();
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
            broadcast(new ACStart());
        }
        else
            pig.queue_command(new ACStart());
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
            broadcast(new ACRun());
        }
        else
            pig.queue_command(new ACRun());
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
            pigs[swine].prep(SFDAQ::get_input_spec(snort_conf, swine));
    }

    // Iterate over the drove, spawn them as allowed, and handle their deaths.
    // FIXIT-L X - If an exit has been requested, we might want to have some mechanism
    //             for forcing inconsiderate pigs to die in timely fashion.
    while ( swine or paused or (Trough::has_next() and !exit_requested) )
    {
        const char* src;
        int idx = paused ? -1 : main_read();

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
        if ( !exit_requested and !paused and (swine < max_pigs) and (src = Trough::get_next()) )
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
    socket_init();
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

    memory::MemoryCap::calculate(max_pigs);
    if ( SnortConfig::log_verbose() )
        memory::MemoryCap::print();

    main_loop();

    delete pig_poke;
    delete[] pigs;
    pigs = nullptr;

#ifdef SHELL
    socket_term();
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

