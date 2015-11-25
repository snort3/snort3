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

#include "process.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_MALLINFO
#include <malloc.h>
#endif

#ifdef HAVE_MALLOC_TRIM
#include <malloc.h>
#endif

#include <iostream>
using namespace std;

#include "main.h"
#include "main/analyzer.h"
#include "main/thread.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "utils/util.h"
#include "utils/stats.h"
#include "helpers/markup.h"
#include "helpers/ring.h"
#include "parser/parser.h"

#ifndef SIGNAL_SNORT_RELOAD
#define SIGNAL_SNORT_RELOAD        SIGHUP
#endif

#ifndef SIGNAL_SNORT_DUMP_STATS
#define SIGNAL_SNORT_DUMP_STATS    SIGUSR1
#endif

#ifndef SIGNAL_SNORT_ROTATE_STATS
#define SIGNAL_SNORT_ROTATE_STATS  SIGUSR2
#endif

// this one should not be changed by user
#define SIGNAL_SNORT_CHILD_READY   SIGCHLD

#ifndef SIGNAL_SNORT_READ_ATTR_TBL
#define SIGNAL_SNORT_READ_ATTR_TBL SIGURG
#endif

static const char* const pig_sig_names[PIG_SIG_MAX] =
{
    "none", "quit", "term", "int",
    "reload-config", "reload-attributes",
    "dump-stats", "rotate-stats"
};

static Ring<PigSignal> sig_ring(4);
static volatile sig_atomic_t child_ready_signal = 0;
static THREAD_LOCAL volatile bool is_main_thread = false;

typedef void (* sighandler_t)(int);
static int add_signal(int sig, sighandler_t, int check_needed);

static bool exit_pronto = true;

void set_quick_exit(bool b)
{ exit_pronto = b; }

void init_main_thread_sig()
{ is_main_thread = true; }

static void exit_log(const char* why)
{
    // printf() etc not allowed here
    char buf[256] = "\n\0";

    strncat(buf, get_prompt(), sizeof(buf)-strlen(buf)-1);
    strncat(buf, " caught ", sizeof(buf)-strlen(buf)-1);
    strncat(buf, why, sizeof(buf)-strlen(buf)-1);
    strncat(buf, " signal, exiting\n", sizeof(buf)-strlen(buf)-1);

    (void)write(STDOUT_FILENO, buf, strlen(buf));
}

static void exit_handler(int signal)
{
    PigSignal s;
    const char* t;

    switch ( signal )
    {
    case SIGTERM: s = PIG_SIG_TERM; t = "term"; break;
    case SIGQUIT: s = PIG_SIG_QUIT; t = "quit"; break;
    case SIGINT: s = PIG_SIG_INT;  t = "int";  break;
    default: return;
    }

    if ( exit_pronto )
    {
        exit_log(t);
        _exit(0);
    }

    sig_ring.put(s);
}

static void dirty_handler(int signal)
{
    snort_conf->dirty_pig = 1;
    exit_handler(signal);
}

static void dump_stats_handler(int /*signal*/)
{
    sig_ring.put(PIG_SIG_DUMP_STATS);
}

static void rotate_stats_handler(int /*signal*/)
{
    sig_ring.put(PIG_SIG_ROTATE_STATS);
}

static void reload_config_handler(int /*signal*/)
{
    sig_ring.put(PIG_SIG_RELOAD_CONFIG);
}

static void reload_attrib_handler(int /*signal*/)
{
    sig_ring.put(PIG_SIG_RELOAD_HOSTS);
}

static void ignore_handler(int /*signal*/)
{
}

static void child_ready_handler(int /*signal*/)
{
    child_ready_signal = 1;
}

static void oops_handler(int signal)
{
    // FIXIT-L what should we capture if this is the main thread?
    if ( !is_main_thread )
        Snort::capture_packet();

    add_signal(signal, SIG_DFL, 0);
    raise(signal);
}

//-------------------------------------------------------------------------
// access methods
//-------------------------------------------------------------------------

PigSignal get_pending_signal()
{
    return sig_ring.get(PIG_SIG_NONE);
}

const char* get_signal_name(PigSignal s)
{
    if ( s >= PIG_SIG_MAX )
        return "error";

    return pig_sig_names[s];
}

//-------------------------------------------------------------------------
// signal management
//-------------------------------------------------------------------------

// If check needed, also check whether previous signal_handler is neither
// SIG_IGN nor SIG_DFL

// FIXIT-L convert sigaction, etc. to c++11
static int add_signal(int sig, sighandler_t signal_handler, int check_needed)
{
#ifdef VALGRIND_TESTING
    if ( sig == SIGUSR2 )
        return 0;  // used by valgrind
#endif
    sighandler_t pre_handler;

#ifdef HAVE_SIGACTION
    struct sigaction action;
    struct sigaction old_action;
    sigfillset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    action.sa_handler = signal_handler;
    sigaction(sig, &action, &old_action);
    pre_handler = old_action.sa_handler;
#else
    pre_handler = signal(sig, signal_handler);
#endif
    if (SIG_ERR == pre_handler)
    {
        ErrorMessage("Could not add handler for signal %d \n", sig);
        return 0;
    }
    else if (check_needed && (SIG_IGN != pre_handler) && (SIG_DFL!= pre_handler))
    {
        ParseWarning(WARN_CONF, "handler is already installed for signal %d.\n", sig);
    }
    return 1;
}

void init_signals(void)
{
#if defined(LINUX) || defined(FREEBSD) || defined(OPENBSD) || \
    defined(SOLARIS) || defined(BSD) || defined(MACOS)
    sigset_t set;

    sigemptyset(&set);
    // FIXIT-L this is undefined for multithreaded apps
    sigprocmask(SIG_SETMASK, &set, NULL);
#else
    sigsetmask(0);
#endif

    /* Make this prog behave nicely when signals come along.
     * Windows doesn't like all of these signals, and will
     * set errno for some.  Ignore/reset this error so it
     * doesn't interfere with later checks of errno value.  */
    add_signal(SIGTERM, exit_handler, 1);
    add_signal(SIGINT, exit_handler, 1);
    add_signal(SIGQUIT, dirty_handler, 1);

    add_signal(SIGNAL_SNORT_DUMP_STATS, dump_stats_handler, 1);
    add_signal(SIGNAL_SNORT_ROTATE_STATS, rotate_stats_handler, 1);
    add_signal(SIGNAL_SNORT_RELOAD, reload_config_handler, 1);
    add_signal(SIGNAL_SNORT_READ_ATTR_TBL, reload_attrib_handler, 1);

    add_signal(SIGPIPE, ignore_handler, 1);
    add_signal(SIGABRT, oops_handler, 1);
    add_signal(SIGSEGV, oops_handler, 1);
    add_signal(SIGBUS, oops_handler, 1);

    errno = 0;
}

static void help_signal(unsigned n, const char* name, const char* h)
{
    cout << Markup::item();

    cout << Markup::emphasis_on();
    cout << name;
    cout << Markup::emphasis_off();

    cout << "(" << n << "): " << h << endl;
}

void help_signals()
{
    help_signal(SIGTERM, "term", "shutdown normally");
    help_signal(SIGINT,  "int", "shutdown normally");
    help_signal(SIGQUIT, "quit", "shutdown as if started with --dirty-pig");

    help_signal(SIGNAL_SNORT_DUMP_STATS,  "stats", "dump stats to stdout");
    help_signal(SIGNAL_SNORT_ROTATE_STATS,  "rotate", "rotate stats files");
    help_signal(SIGNAL_SNORT_RELOAD,  "reload", "reload config file");
    help_signal(SIGNAL_SNORT_READ_ATTR_TBL,  "hosts", "reload hosts file");
}

//-------------------------------------------------------------------------
// daemonize
//-------------------------------------------------------------------------

static void snuff_stdio()
{
    bool err = false;

    err = close(0) or err;
    err = close(1) or err;
    err = close(2) or err;

    /* redirect stdin/stdout/stderr to /dev/null */
    err = open("/dev/null", O_RDWR) or err;  /* stdin, fd 0 */

    err = dup(0) or err;  /* stdout, fd 0 => fd 1 */
    err = dup(0) or err;  /* stderr, fd 0 => fd 2 */

    if ( err )
        // message is hit or miss but we will exit with failure
        FatalError("daemonization errors - %s", strerror(errno));
}

// All threads need to be created after daemonizing.  If created in the
// parent thread, when it goes away, so will all of the threads.  The child
// does not "inherit" threads created in the parent.

// Similar to daemon(1, 0).  We also add a signal to confirm child was at
// least started ok.  Should daemon() become posix compliant, we can switch
// to that.  We can also consider updating to have the child execve().
// Note that there are system tools for daemonization these days.  See
// daemon(3) and search deprecated daemonomicon for more.
void daemonize()
{
    // don't daemonize more than once
    if ( getppid() == 1 )
        return;

    LogMessage("initializing daemon mode\n");

    // register signal handler so that parent can trap signal
    add_signal(SIGNAL_SNORT_CHILD_READY, child_ready_handler, 1);

    pid_t cpid = fork();

    if ( cpid < 0 )
        FatalError("fork failed - %s", strerror(errno));

    if ( cpid > 0 )
    {
        // parent
        int i = 0;

        while ( !child_ready_signal and i++ < 10 )
            sleep(1);

        if ( !child_ready_signal )
            FatalError("daemonization failed");
        else
            LogMessage("child process is %d\n", cpid);

        exit(0);
    }

    // child
    setsid();

    if ( SnortConfig::log_quiet() or SnortConfig::log_syslog() )
        snuff_stdio();

    pid_t ppid = getppid();

    if ( kill(ppid, SIGNAL_SNORT_CHILD_READY) )
        LogMessage("daemonization incomplete, failed to signal parent "
            "%d: %s\n", ppid, get_error(errno));
}

//-------------------------------------------------------------------------
// heap stats
//-------------------------------------------------------------------------

void trim_heap()
{
#ifdef HAVE_MALLOC_TRIM
    malloc_trim(0);
#endif
}

void log_malloc_info()
{
#ifdef HAVE_MALLINFO
    struct mallinfo mi = mallinfo();

    LogLabel("heap usage");
    LogCount("total non-mmapped bytes", mi.arena);
    LogCount("bytes in mapped regions", mi.hblkhd);
    LogCount("total allocated space", mi.uordblks);
    LogCount("total free space", mi.fordblks);
    LogCount("topmost releasable block", mi.keepcost);

#ifdef DEBUG
    LogCount("free chunks", mi.ordblks);
    LogCount("free fastbin blocks", mi.smblks);
    LogCount("mapped regions", mi.hblks);
    LogCount("max total alloc space", mi.usmblks);
    LogCount("free bytes in fastbins", mi.fsmblks);
#endif
#endif
}

