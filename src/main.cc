//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifdef BUILD_SHELL
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <string>
#include <thread>
using namespace std;

#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_module.h"
#include "main/shell.h"
#include "main/analyzer.h"
#include "framework/module.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/inspector_manager.h"
#include "utils/util.h"
#include "parser/parser.h"
#include "packet_io/trough.h"
#include "packet_io/intf.h"
#include "packet_io/sfdaq.h"
#include "control/idle_processing.h"
#include "target_based/sftarget_reader.h"
#include "flow/flow_control.h"
#include "helpers/process.h"
#include "helpers/swapper.h"
#include "time/profiler.h"
#include "time/periodic.h"

#ifdef UNIT_TEST
#include "test/unit_test.h"
#endif

#ifdef PIGLET
#include "piglet/piglet.h"
#endif

//-------------------------------------------------------------------------

static Swapper* swapper = NULL;

static int exit_logged = 0;
static bool paused = false;
static bool unknown_source = false;

static bool pause_enabled = false;
#ifdef BUILD_SHELL
static bool shell_enabled = false;
#endif

const struct timespec main_sleep = { 0, 1000000 }; // 0.001 sec

static const char* prompt = "o\")~ ";

const char* get_prompt()
{ return prompt; }

static bool use_shell(SnortConfig* sc)
{
#ifdef BUILD_SHELL
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
    if ( old_conf )
        delete old_conf;

    if ( old_attribs )
        SFAT_Free(old_attribs);
}

void Swapper::apply()
{
    if ( new_conf )
    {
        snort_conf = new_conf;
        set_default_policy();
    }

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

    void read(int);
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
void Request::read(int f)
{
    fd = f;
    buf[0] = '\0';
    unsigned n = ::read(fd, buf, sizeof(buf)-1);

    do
        buf[n] = '\0';
    while ( n-- and isspace(buf[n]) );
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
    if ( write(fd, s, strlen(s)) )
        return;  // FIXIT-L count errors?
}

// FIXIT-L would like to flush prompt w/o \n
void Request::show_prompt() const
{
    string s = prompt;
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
    std::thread* athread;

    Pig() { analyzer = nullptr; }

    void start(unsigned, const char*, Swapper*);
    void stop(unsigned);

    void execute(AnalyzerCommand);
    void swap(Swapper*);
};

void Pig::start(unsigned idx, const char* source, Swapper* ps)
{
    LogMessage("++ [%u] %s\n", idx, source);
    analyzer = new Analyzer(source);
    athread = new std::thread(std::ref(*analyzer), idx, ps);
}

void Pig::stop(unsigned idx)
{
    if ( !analyzer->is_done() )
        analyzer->execute(AC_STOP);

    athread->join();
    delete athread;

    LogMessage("-- [%u] %s\n", idx, analyzer->get_source());

    delete analyzer;
    analyzer = nullptr;
}

void Pig::execute(AnalyzerCommand ac)
{
    if ( analyzer )
        analyzer->execute(ac);
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
    for ( unsigned idx = 0; idx < max_pigs; ++idx )
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

int main_reload_config(lua_State*)
{
    if ( swapper )
    {
        request.respond("== reload pending; retry\n");
        return 0;
    }
    request.respond(".. reloading configuration\n");
    SnortConfig* old = snort_conf;
    SnortConfig* sc = Snort::get_reload_config();

    if ( !sc )
    {
        request.respond("== reload failed\n");
        return 0;
    }
    request.respond(".. swapping configuration\n");
    snort_conf = sc;
    proc_stats.conf_reloads++;

    swapper = new Swapper(old, sc);

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
        pigs[idx].swap(swapper);

    return 0;
}

int main_reload_hosts(lua_State*)
{
    if ( swapper )
    {
        request.respond("== reload pending; retry\n");
        return 0;
    }
    request.respond(".. reloading hosts table\n");
    tTargetBasedConfig* old = SFAT_GetConfig();
    tTargetBasedConfig* tc = SFAT_Swap();

    if ( !tc )
    {
        request.respond("== reload failed\n");
        return 0;
    }
    swapper = new Swapper(old, tc);

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
    Trough_Multi(SOURCE_LIST, f);
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

#ifdef BUILD_SHELL
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
    exit_logged = 1;
    request.respond("== stopping\n");
    broadcast(AC_STOP);
    return 0;
}

int main_help(lua_State*)
{
    const Command* cmd = get_snort_module()->get_commands();

    while ( cmd->name )
    {
        string info = cmd->name;
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

    IdleProcessingExecute();

    periodic_check();

    InspectorManager::empty_trash();

    return false;
}

//-------------------------------------------------------------------------
// socket foo
//-------------------------------------------------------------------------

#ifdef BUILD_SHELL
// FIXIT-M make these non-blocking
// FIXIT-M allow at least 2 remote controls
// FIXIT-M bind to configured ip including INADDR_ANY
// (default is loopback if enabled)
static int listener = -1;
static int remote_control = -1;

static int socket_init()
{
    if ( !snort_conf->remote_control )
        return -1;

    listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0)
    {
        FatalError("socket failed: %s\n", strerror(errno));
        return -2;
    }

    // FIXIT-M want to disable time wait
    int on = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7F000001);
    addr.sin_port = htons(snort_conf->remote_control);

    if ( ::bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
    {
        FatalError("bind failed: %s\n", strerror(errno));
        return -3;
    }

    // FIXIT-M configure max conns
    if ( listen(listener, 5) < 0 )
    {
        FatalError("listen failed: %s\n", strerror(errno));
        return -4;
    }

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

static void shell(int fd)
{
    string rsp;
    request.read(fd);

    SnortConfig* sc = snort_conf;
    sc->policy_map->get_shell()->execute(request.get(), rsp);

    if ( rsp.size() )
        request.respond(rsp.c_str());

    request.show_prompt();
}

static bool service_users()
{
    fd_set inputs;
    FD_ZERO(&inputs);
    int max_fd = -1;

    if ( shell_enabled )
    {
        FD_SET(STDIN_FILENO, &inputs);
        max_fd = STDIN_FILENO;
    }

    if ( listener > max_fd )
    {
        FD_SET(listener, &inputs);
        max_fd = listener;
    }

    if ( remote_control > max_fd )
    {
        FD_SET(remote_control, &inputs);
        max_fd = remote_control;
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if ( select(max_fd+1, &inputs, NULL, NULL, &timeout) )
    {
        if ( FD_ISSET(STDIN_FILENO, &inputs) )
        {
            shell(STDIN_FILENO);
            proc_stats.local_commands++;
            return true;
        }
        else if ( remote_control > 0 and FD_ISSET(remote_control, &inputs) )
        {
            shell(remote_control);
            proc_stats.remote_commands++;
            return true;
        }
        else if ( listener > 0 and FD_ISSET(listener, &inputs) )
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
#ifdef BUILD_SHELL
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

    // pcap requires a source; as a convenience, if none given
    // just validate instead of erroring out
    if ( !Trough_GetQCount() and strcmp(DAQ_GetType(), "pcap") )
        unknown_source = true;

    if ( use_shell(snort_conf) )
        return false;

    if ( !Trough_GetQCount() and !strcmp(DAQ_GetType(), "pcap") )
        return true;

    return false;
}

static bool set_mode()
{
#ifdef PIGLET
    if ( Piglet::piglet_mode() )
        exit(Piglet::main());
#endif
#ifdef UNIT_TEST
    if ( catch_enabled() )
        exit(catch_test());
#endif

    if ( int k = get_parse_errors() )
    {
        FatalError("see prior %d errors\n", k);
        return false;
    }
    if ( SnortConfig::conf_error_out() )
    {
        if ( int k = get_parse_warnings() )
        {
            FatalError("see prior %d warnings\n", k);
            return false;
        }
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
        paused = pause_enabled = true;
    }
    else
        LogMessage("Commencing packet processing\n");

#ifdef BUILD_SHELL
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

static inline bool dont_stop()
{
    if ( paused or unknown_source or Trough_Next() )
        return true;

    if ( pause_enabled )
    {
        LogMessage("== pausing\n");
        pause_enabled = false;
        paused = true;
        return true;
    }
    return false;
}

static const char* get_source()
{
    if ( Trough_Next() )
        return Trough_First();

    if ( unknown_source )
    {
        unknown_source = false;
        return "";
    }
    return nullptr;
}

static void main_loop()
{
    unsigned idx = max_pigs, swine = 0;
    init_main_thread_sig();

    while ( !exit_logged and (swine or dont_stop()) )
    {
        if ( ++idx >= max_pigs )
            idx = 0;

        if ( !paused )
        {
            Pig& pig = pigs[idx];

            if ( pig.analyzer )
            {
                if ( pig.analyzer->is_done() )
                {
                    pig.stop(idx);
                    --swine;
                }
            }
            else if ( const char* src = get_source() )
            {
                Swapper* swapper = new Swapper(snort_conf, SFAT_GetConfig());
                pig.start(idx, src, swapper);
                ++swine;
                continue;
            }
        }
        service_check();
    }
}

static void snort_main()
{
#ifdef BUILD_SHELL
    socket_init();
#endif
    TimeStart();

    max_pigs = get_instance_max();
    assert(max_pigs > 0);

    pigs = new Pig[max_pigs];

    main_loop();

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
    {
        Pig& pig = pigs[idx];

        if ( pig.analyzer )
            pig.stop(idx);
    }
    delete[] pigs;
    pigs = nullptr;

    TimeStop();
#ifdef BUILD_SHELL
    socket_term();
#endif
}

int main(int argc, char* argv[])
{
    const char* s = getenv("SNORT_PROMPT");

    if ( s )
        prompt = s;

    Snort::setup(argc, argv);

    if ( set_mode() )
        snort_main();

    Snort::cleanup();

    return 0;
}

