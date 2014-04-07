/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
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
#include <sys/socket.h>
#include <netinet/in.h>

#include <string>
#include <thread>
using namespace std;

#include "snort.h"
#include "helpers/process.h"
#include "snort_config.h"
#include "framework/module.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/inspector_manager.h"
#include "managers/shell.h"
#include "util.h"
#include "profiler.h"
#include "packet_io/trough.h"
#include "packet_io/intf.h"
#include "control/idle_processing.h"
#include "target_based/sftarget_reader.h"
#include "flow/flow_control.h"
#include "analyzer.h"
#include "helpers/swapper.h"
#include "time/periodic.h"

#ifdef UNIT_TEST
#include "test/unit_test.h"
#endif

#ifdef SIDE_CHANNEL
#include "side_channel/sidechannel.h"
#endif

#include "framework/so_rule.h"

//-------------------------------------------------------------------------

static Swapper* swapper = NULL;

static int exit_logged = 0;
static bool paused = false;

const struct timespec main_sleep = { 0, 100000000 }; // 0.1 sec

#ifdef SIDE_CHANNEL
pthread_mutex_t snort_process_lock;
static bool snort_process_lock_held = false;
#endif

static const char* prompt = "o\")~ ";

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
        SnortConfFree(old_conf);

    if ( old_attribs )
        SFAT_Free(old_attribs);
}

void Swapper::apply()
{
    if ( new_conf )
        snort_conf = new_conf;
        set_default_policy();

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
    const char* get() const { return buf; };

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

// FIXIT ignoring partial reads for now
// using simple text for now so can use telnet as client
// but must parse commands out of stream (ending with \n)
void Request::read(int f)
{
    fd = f;
    buf[0] = '\0';
    unsigned n = ::read(fd, buf, sizeof(buf)-1);

    do buf[n] = '\0';
    while ( n-- && isspace(buf[n]) );
}

// FIXIT supporting only simple strings for now
// should support var args formats
void Request::respond(const char* s) const
{
    if ( fd < 1 )
    {
        LogMessage("%s", s);
        return;
    }
    write(fd, s, strlen(s));
}

void Request::show_prompt() const
{
    respond(prompt);
}

static Request request;

//-------------------------------------------------------------------------
// pig foo
//-------------------------------------------------------------------------

class Pig {
public:
    Analyzer* analyzer;
    std::thread* athread;

    Pig() { analyzer = nullptr; };

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

int main_dump_plugins(lua_State*)
{
    ModuleManager::dump_modules();
    PluginManager::dump_plugins();
    return 0;
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
    SnortConfig* sc = reload_config();

    if ( !sc )
    {
        request.respond("== reload failed\n");
        return 0;
    }
    request.respond(".. swapping configuration\n");
    swapper = new Swapper(old, sc);

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
        pigs[idx].swap(swapper);

    return 0;
}

int main_reload_attributes(lua_State*)
{
    if ( swapper )
    {
        request.respond("== reload pending; retry\n");
        return 0;
    }
    request.respond(".. reloading attribute table\n");
    tTargetBasedConfig* old = SFAT_GetConfig();
    tTargetBasedConfig* tc = SFAT_Reload();

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
    broadcast(AC_PAUSE);
    paused = true;
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

int main_quit(lua_State*)
{
    exit_logged = 1;
    request.respond("== stopping\n");
    broadcast(AC_STOP);
    return 0;
}

int main_help(lua_State*)
{
#if 0
    // FIXIT this should be generic for all modules
    RequestMap* map = cmd_set;

    while ( map->name )
    {
        string info = map->name;
        info += ": ";
        info += map->help;
        info += "\n";
        request.respond(info.c_str());
        ++map;
    }
    return 0;
#endif
    return 0;
}

//-------------------------------------------------------------------------
// housekeeping foo
//-------------------------------------------------------------------------

static int signal_check()
{
    PigSignal s = get_pending_signal();

    if ( s == PIG_SIG_NONE || s >= PIG_SIG_MAX )
        return 0;

    LogMessage("** caught %s signal\n", get_signal_name(s));

    switch ( s )
    {
    case PIG_SIG_QUIT:
    case PIG_SIG_TERM:
    case PIG_SIG_INT:
        main_quit();
        break;

    case PIG_SIG_RELOAD_CONFIG:
        main_reload_config();
        break;

    case PIG_SIG_RELOAD_ATTRIBUTES:
        main_reload_attributes();
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

// FIXIT return true if something was done to avoid sleeping
static bool house_keeping()
{
#ifdef SIDE_CHANNEL
    if (ScSideChannelEnabled() && !snort_process_lock_held)
    {
        pthread_mutex_lock(&snort_process_lock);
        snort_process_lock_held = true;
    }
#endif

    signal_check();

#ifdef SIDE_CHANNEL
    SideChannelDrainRX(0);
#endif
    IdleProcessingExecute();

    periodic_check();

    InspectorManager::empty_trash();

    return false;
}

//-------------------------------------------------------------------------
// socket foo
//-------------------------------------------------------------------------

// FIXIT make these non-blocking
// FIXIT allow at least 2 remote controls
static int listener = -1;
static int remote_control = -1;

static int socket_init()
{
    if ( !snort_conf->remote_control )
        return -1;

    listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0) 
        return -2;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(snort_conf->remote_control);

    if ( ::bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) 
        return -3;

    // FIXIT configure max conns
    if ( listen(listener, 5) < 0 )
        return -4;

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

    remote_control = accept(listener, (struct sockaddr *) &addr, &len);

    if ( remote_control < 0 ) 
        return -1;

    // FIXIT authenticate, use ssl ?
    return 0;
}

static bool service_users()
{
    fd_set inputs;
    FD_ZERO(&inputs);
    int max_fd = -1;

    if ( snort_conf->run_flags & RUN_FLAG__SHELL )
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
            request.read(STDIN_FILENO);
            Shell::execute(request.get());
            request.show_prompt();
            proc_stats.local_commands++;
            return true;
        }
        else if ( remote_control > 0 && FD_ISSET(remote_control, &inputs) )
        {
            request.read(remote_control);
            Shell::execute(request.get());
            request.show_prompt();
            proc_stats.remote_commands++;
            return true;
        }
        else if ( listener > 0 && FD_ISSET(listener, &inputs) )
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

static bool check_response()
{
    if ( !swapper )
        return false;

    for ( unsigned idx = 0; idx < max_pigs; ++idx )
    {
        if ( pigs[idx].analyzer &&
            pigs[idx].analyzer->swap_pending() )
            return false;
    }

    delete swapper;
    swapper = nullptr;

    LogMessage("== reload complete\n");
    return true;
}

static void service_check()
{
    if ( service_users() )
        return;

    if ( check_response() )
        return;

    if ( house_keeping() )
        return;

    nanosleep(&main_sleep, NULL);
}

//-------------------------------------------------------------------------
// main foo
//-------------------------------------------------------------------------

static bool set_mode()
{
#ifdef UNIT_TEST
    if ( unit_test_enabled() )
        exit(unit_test());
#endif

    if ( ScTestMode() ||
        (!Trough_GetQCount() && !(snort_conf->run_flags & RUN_FLAG__SHELL)) )
    {
        LogMessage("\nSnort successfully validated the configuration!\n");

        // force test mode to exit w/o stats
        snort_conf->run_flags |= RUN_FLAG__TEST;
        return false;
    }

    if ( snort_conf->run_flags & RUN_FLAG__SHELL )
    {
        LogMessage("Entering command shell\n");
        request.set(STDOUT_FILENO, "");
        request.show_prompt();
    }

    if ( snort_conf->run_flags & RUN_FLAG__PAUSE )
        paused = true;
    else
        LogMessage("Commencing packet processing\n");

    return true;
}

static inline bool dont_stop()
{
    return ( Trough_Next() || snort_conf->run_flags & RUN_FLAG__SHELL );
}

static void main_loop()
{
    unsigned idx = max_pigs, swine = 0;

    while ( !exit_logged && (dont_stop() || swine) )
    {
        if ( ++idx >= max_pigs )
            idx = 0;

        if ( !paused )
        {
            Pig& pig = pigs[idx];

            if ( pig.analyzer && pig.analyzer->is_done() )
            {
                pig.stop(idx);
                --swine;
            }
            if ( !pig.analyzer && Trough_Next() )
            {
                Swapper* swapper = new Swapper(snort_conf, SFAT_GetConfig());
                pig.start(idx, Trough_First(), swapper);
                ++swine;
                continue;
            }
        }
        service_check();
    }
}

static void snort_main()
{
    socket_init();
    TimeStart();

    max_pigs = snort_conf->max_threads;
    assert(max_pigs > 0);

    pigs = new Pig[max_pigs];

    main_loop();

    for ( unsigned idx = 0; pigs && idx < max_pigs; ++idx )
    {
        Pig& pig = pigs[idx];

        if ( pig.analyzer )
            pig.stop(idx);
    }
    delete[] pigs;
    pigs = nullptr;

    TimeStop();
    socket_term();
}

int main(int argc, char *argv[])
{
    const char* s = getenv("SNORT_PROMPT");

    if ( s )
        prompt = s;

    snort_setup(argc, argv);

    if ( set_mode() )
        snort_main();

    snort_cleanup();

    return 0;
}

