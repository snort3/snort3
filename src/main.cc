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

#include "main.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#ifdef SHELL
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <string>
#include <thread>

#include "log/messages.h"
#include "main/analyzer.h"
#include "main/shell.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/snort_module.h"
#include "main/thread_config.h"
#include "framework/module.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/inspector_manager.h"
#include "memory/memory_cap.h"
#include "utils/util.h"
#include "parser/parser.h"
#include "packet_io/trough.h"
#include "packet_io/intf.h"
#include "packet_io/sfdaq.h"
#include "control/idle_processing.h"
#include "target_based/sftarget_reader.h"
#include "flow/flow_control.h"
#include "lua/lua.h"
#include "helpers/process.h"
#include "helpers/swapper.h"
#include "time/periodic.h"
#include "utils/safec.h"

#ifdef UNIT_TEST
#include "catch/unit_test.h"
#endif

#ifdef PIGLET
#include "piglet/piglet.h"
#endif

//-------------------------------------------------------------------------

std::mutex Swapper::mutex;
static Swapper* swapper = NULL;

static int exit_requested = 0;
static int main_exit_code = 0;
static bool paused = false;

#ifdef SHELL
static bool shell_enabled = false;
#endif

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

//-------------------------------------------------------------------------
// swap foo
//-------------------------------------------------------------------------

Swapper::Swapper(SnortConfig* s, tTargetBasedConfig* t)
{
    old_conf = nullptr;
    new_conf = s;

    old_attribs = nullptr;
    new_attribs = t;
}

Swapper::Swapper(SnortConfig* sold, SnortConfig* snew)
{
    old_conf = sold;
    new_conf = snew;

    old_attribs = nullptr;
    new_attribs = nullptr;
}

Swapper::Swapper(tTargetBasedConfig* told, tTargetBasedConfig* tnew)
{
    old_conf = nullptr;
    new_conf = nullptr;

    old_attribs = told;
    new_attribs = tnew;
}

Swapper::~Swapper()
{
    std::lock_guard<std::mutex> lock(mutex);

    if ( old_conf )
        delete old_conf;

    if ( old_attribs )
        SFAT_Free(old_attribs);
}

void Swapper::apply()
{
    std::lock_guard<std::mutex> lock(mutex);

    if ( new_conf )
        snort_conf = new_conf;

    if ( new_attribs )
        SFAT_SetConfig(new_attribs);
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

    Pig() { analyzer = nullptr; athread = nullptr; idx = (unsigned) -1; }

    void set_index(unsigned index) { idx = index; }

    void prep(const char* source);
    void start();
    void stop();

    bool attentive();
    bool execute(AnalyzerCommand);
    void swap(Swapper*);

private:
    std::thread* athread;
    unsigned idx;
};

void Pig::prep(const char* source)
{
    analyzer = new Analyzer(idx, source);
}

void Pig::start()
{
    if (!athread)
    {
        Swapper* ps = new Swapper(snort_conf, SFAT_GetConfig());
        LogMessage("++ [%u] %s\n", idx, analyzer->get_source());
        athread = new std::thread(std::ref(*analyzer), ps);
    }
}

void Pig::stop()
{
    if (analyzer)
    {
        if (athread)
        {
            if (analyzer->get_state() != Analyzer::State::STOPPED)
                execute(AC_STOP);

            athread->join();
            delete athread;
            athread = nullptr;

            LogMessage("-- [%u] %s\n", idx, analyzer->get_source());
        }

        delete analyzer;
        analyzer = nullptr;
    }
}

bool Pig::attentive()
{
    return analyzer && athread && analyzer->get_current_command() == AC_NONE;
}

bool Pig::execute(AnalyzerCommand ac)
{
    if (attentive())
    {
        DebugFormat(DEBUG_ANALYZER, "[%u] Executing command %s\n",
            idx, Analyzer::get_command_string(ac));
        analyzer->execute(ac);
        return true;
    }
    return false;
}

void Pig::swap(Swapper* ps)
{
    if ( !analyzer )
        return;

    analyzer->set_config(ps);
    analyzer->execute(AC_SWAP);
}

static Pig* pigs = nullptr;
static unsigned max_pigs = 0;

//-------------------------------------------------------------------------
// main commands
//-------------------------------------------------------------------------

static void broadcast(AnalyzerCommand ac)
{
    // FIXIT-H X - Broadcast should either wait for all pigs to be attentive
    //              or queue commands for later processing.
    for (unsigned idx = 0; idx < max_pigs; ++idx)
        pigs[idx].execute(ac);
}

int main_dump_stats(lua_State*)
{
    DropStats();
    return 0;
}

int main_rotate_stats(lua_State*)
{
    request.respond("== rotating stats\n");
    broadcast(AC_ROTATE);
    return 0;
}

int main_reload_config(lua_State* L)
{
    if ( swapper )
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
    request.respond(".. swapping configuration\n");
    snort_conf = sc;
    proc_stats.conf_reloads++;

    swapper = new Swapper(old, sc);
    std::lock_guard<std::mutex> lock(Swapper::mutex);

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
        pigs[idx].swap(swapper);

    return 0;
}

int main_reload_hosts(lua_State* L)
{
    if ( swapper )
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
    swapper = new Swapper(old, tc);
    std::lock_guard<std::mutex> lock(Swapper::mutex);

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
        pigs[idx].swap(swapper);

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
    broadcast(AC_PAUSE);
    paused = true;
    return 0;
}

int main_resume(lua_State*)
{
    request.respond("== resuming\n");
    broadcast(AC_RESUME);
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
    exit_requested = 1;
    request.respond("== stopping\n");
    broadcast(AC_STOP);
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

// FIXIT-L return true if something was done to avoid sleeping
static bool house_keeping()
{
    signal_check();

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

static bool check_response()
{
    if ( !swapper )
        return false;

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
    {
        if ( pigs[idx].analyzer and pigs[idx].analyzer->swap_pending() )
            return false;
    }

    delete swapper;
    swapper = nullptr;

    LogMessage("== reload complete\n");
    return true;
}

static void service_check()
{
#ifdef SHELL
    if ( service_users() )
        return;
#endif

    if ( check_response() )
        return;

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

static void main_loop()
{
    unsigned idx = max_pigs, swine = 0, pending_privileges = 0;

    if (SnortConfig::change_privileges())
        pending_privileges = max_pigs;

    // Preemptively prep all pigs in live traffic mode
    if (!SnortConfig::read_mode())
    {
        for (swine = 0; swine < max_pigs; swine++)
            pigs[swine].prep(SFDAQ::get_input_spec(snort_conf, idx));
    }

    // Iterate over the drove, spawn them as allowed, and handle their deaths.
    // FIXIT-L X - If an exit has been requested, we might want to have some mechanism
    //              for forcing inconsiderate pigs to die in timely fashion.
    while (swine || (!exit_requested && (paused || Trough::has_next())))
    {
        if ( ++idx >= max_pigs )
            idx = 0;

        if (!paused)
        {
            Pig& pig = pigs[idx];

            if (pig.analyzer)
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
                            Snort::drop_privileges();
                        }
                        pig.execute(AC_START);
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
                            Snort::drop_privileges();
                        }
                        pig.execute(AC_RUN);
                        break;

                    case Analyzer::State::STOPPED:
                        pig.stop();
                        --swine;
                        break;

                    default:
                        break;
                }
            }
            else if (const char* src = Trough::get_next())
            {
                pig.prep(src);
                ++swine;
                continue;
            }
            else if (pending_privileges)
                pending_privileges--;
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

    for (unsigned idx = 0; idx < max_pigs; idx++)
    {
        Pig& pig = pigs[idx];
        if ( pig.analyzer )
            pig.stop();
    }
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

