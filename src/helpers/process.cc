//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "process.h"

#include <fcntl.h>

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>
#endif

#ifdef HAVE_MALLOC_TRIM
#include <malloc.h>
#endif

#include <csignal>
#include <iostream>

#include "log/messages.h"
#include "main.h"
#include "main/oops_handler.h"
#include "main/snort_config.h"
#include "utils/cpp_macros.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "markup.h"
#include "ring.h"
#include "sigsafe.h"

using namespace snort;

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
static THREAD_LOCAL bool is_main_thread = false;

// Backup copies of the original fatal signal actions.  Kept here because they must
//  be trivially accessible to signal handlers.
#ifdef HAVE_SIGACTION
static struct
{
    int signal;
    struct sigaction original_sigaction;
}
original_sigactions[] =
{
    { SIGILL, { } },
    { SIGABRT, { } },
    { SIGBUS,  { } },
    { SIGFPE,  { } },
    { SIGSEGV, { } },
    { 0, { } },
};
#else
static struct
{
    int signal;
    sig_t original_sighandler;
}
original_sighandlers[] =
{
    { SIGILL,  SIG_DFL },
    { SIGABRT, SIG_DFL },
    { SIGBUS,  SIG_DFL },
    { SIGFPE,  SIG_DFL },
    { SIGSEGV, SIG_DFL },
    { 0, SIG_DFL },
};
#endif

static bool add_signal(int sig, sig_t);
static bool restore_signal(int sig, bool silent = false);

static bool exit_pronto = true;

void set_quick_exit(bool b)
{ exit_pronto = b; }

void set_main_thread()
{ is_main_thread = true; }

static void exit_handler(int signal)
{
    PigSignal s;
    const char* t;

    switch ( signal )
    {
        case SIGTERM: s = PIG_SIG_TERM; t = "term"; break;
        case SIGQUIT: s = PIG_SIG_QUIT; t = "quit"; break;
        case SIGINT:  s = PIG_SIG_INT;  t = "int";  break;
        default: return;
    }

    if ( exit_pronto )
    {
        SigSafePrinter(STDOUT_FILENO).printf("%s caught %s signal, exiting\n", get_prompt(), t);
        _exit(0);
    }

    sig_ring.put(s);
}

static void dirty_handler(int signal)
{
    SnortConfig::get_main_conf()->dirty_pig = true;
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

static void child_ready_handler(int /*signal*/)
{
    child_ready_signal = 1;
}

#ifdef HAVE_LIBUNWIND
static void print_backtrace(SigSafePrinter& ssp)
{
    int ret;

    // grab the machine context and initialize the cursor
    unw_context_t context;
    if ((ret = unw_getcontext(&context)) < 0)
    {
        ssp.printf("unw_getcontext failed: %s (%d)\n", unw_strerror(ret), ret);
        return;
    }

    unw_cursor_t cursor;
    if ((ret = unw_init_local(&cursor, &context)) < 0)
    {
        ssp.printf("unw_init_local failed: %s (%d)\n", unw_strerror(ret), ret);
        return;
    }

    ssp.printf("Backtrace:\n");

    // walk the stack frames
    unsigned frame_num = 0;
    while ((ret = unw_step(&cursor)) > 0)
    {
        // skip printing any frames until we've found the frame that received the signal
        if (frame_num == 0 && !unw_is_signal_frame(&cursor))
            continue;

        unw_word_t pc;
        if ((ret = unw_get_reg(&cursor, UNW_REG_IP, &pc)) < 0)
        {
            ssp.printf("unw_get_reg failed for instruction pointer: %s (%d)\n",
                    unw_strerror(ret), ret);
            return;
        }

        unw_proc_info_t pip;
        if ((ret = unw_get_proc_info(&cursor, &pip)) < 0)
        {
            ssp.printf("unw_get_proc_info failed: %s (%d)\n", unw_strerror(ret), ret);
            return;
        }

        ssp.printf("  #%u 0x%x", frame_num, pc);

        char sym[1024];
        unw_word_t offset;
        ret = unw_get_proc_name(&cursor, sym, sizeof(sym), &offset);
        switch (-ret)
        {
            case 0:
                // fallthrough
            case UNW_ENOMEM:
                ssp.printf(" in %s+0x%x", sym, offset);
                break;
            case UNW_ENOINFO:
                // fallthrough
            case UNW_EUNSPEC:
                // fallthrough
            default:
                ssp.printf(" unw_get_proc_name failed: %s (%d)", unw_strerror(ret), ret);
                break;
        }

        Dl_info dlinfo;
        if (dladdr((void *)(uintptr_t)(pip.start_ip + offset), &dlinfo)
            && dlinfo.dli_fname && *dlinfo.dli_fname)
        {
            ssp.printf(" (%s @0x%x)", dlinfo.dli_fname, dlinfo.dli_fbase);
        }

        ssp.printf("\n");

        frame_num++;
    }
    if (ret < 0)
        ssp.printf("unw_step failed: %s (%d)\n", unw_strerror(ret), ret);

    ssp.printf("\n");
}
#endif

static void oops_handler(int signal)
{
    // First things first, restore the original signal handler.
    restore_signal(signal, true);

    // Log the Snort version and signal caught.
    const char* sigstr = "???\n";
    switch (signal)
    {
        case SIGILL:
            sigstr = STRINGIFY(SIGILL) " (" STRINGIFY_MX(SIGILL) ")";
            break;
        case SIGABRT:
            sigstr = STRINGIFY(SIGABRT) " (" STRINGIFY_MX(SIGABRT) ")";
            break;
        case SIGBUS:
            sigstr = STRINGIFY(SIGBUS) " (" STRINGIFY_MX(SIGBUS) ")";
            break;
        case SIGFPE:
            sigstr = STRINGIFY(SIGFPE) " (" STRINGIFY_MX(SIGFPE) ")";
            break;
        case SIGSEGV:
            sigstr = STRINGIFY(SIGSEGV) " (" STRINGIFY_MX(SIGSEGV) ")";
            break;
    }
    SigSafePrinter ssp(STDERR_FILENO);
    ssp.printf("\nSnort (PID %u) caught fatal signal: %s\n", getpid(), sigstr);
#ifdef BUILD
    ssp.printf("Version: " VERSION " Build " BUILD "\n\n");
#else
    ssp.printf("Version: " VERSION "\n\n");
#endif

#ifdef HAVE_LIBUNWIND
    // Try to pretty-print a stack trace using libunwind to traverse the stack.
    print_backtrace(ssp);
#endif

    // FIXIT-L what should we capture if this is the main thread?
    if ( !is_main_thread )
        OopsHandler::handle_crash(STDERR_FILENO);

    // Finally, raise the signal so that the original handler can handle it.
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

static bool add_signal(int sig, sig_t signal_handler)
{
#ifdef HAVE_SIGACTION
    struct sigaction action;
    // Mask all other signals while in the signal handler
    sigfillset(&action.sa_mask);
    // Make compatible system calls restartable across signals
    action.sa_flags = SA_RESTART;
    action.sa_handler = signal_handler;

    struct sigaction* old_action = nullptr;
    for (unsigned i = 0; original_sigactions[i].signal; i++)
    {
        if (original_sigactions[i].signal == sig)
        {
            old_action = &original_sigactions[i].original_sigaction;
            break;
        }
    }

    if (sigaction(sig, &action, old_action) != 0)
    {
        ErrorMessage("Could not add handler for signal %d: %s (%d)\n", sig, get_error(errno), errno);
        return false;
    }
#else
    sig_t original_handler = signal(sig, signal_handler);
    if (original_handler == SIG_ERR)
    {
        ErrorMessage("Could not add handler for signal %d: %s (%d)\n", sig, get_error(errno), errno);
        return false;
    }

    for (unsigned i = 0; original_sighandlers[i].signal; i++)
    {
        if (original_sighandlers[i].signal == sig)
        {
            original_sighandlers[i].original_sighandler = original_handler;
            break;
        }
    }
#endif

    return true;
}

static bool restore_signal(int sig, bool silent)
{
#ifdef HAVE_SIGACTION
    struct sigaction* new_action = nullptr;
    struct sigaction action;

    for (unsigned i = 0; original_sigactions[i].signal; i++)
    {
        if (original_sigactions[i].signal == sig)
        {
            new_action = &original_sigactions[i].original_sigaction;
            break;
        }
    }

    if (!new_action)
    {
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        action.sa_handler = SIG_DFL;
        new_action = &action;
    }

    if (sigaction(sig, new_action, nullptr) != 0)
    {
        if (!silent)
            ErrorMessage("Could not restore handler for signal %d: %s (%d)\n", sig, get_error(errno), errno);
        return false;
    }
#else
    sig_t signal_handler = SIG_DFL;

    for (unsigned i = 0; original_sighandlers[i].signal; i++)
    {
        if (original_sighandlers[i].signal == sig)
        {
            signal_handler = original_sighandlers[i].original_sighandler;
            break;
        }
    }

    if (signal(sig, signal_handler) == SIG_ERR)
    {
        if (!silent)
            ErrorMessage("Could not restore handler for signal %d: %s (%d)\n", sig, get_error(errno), errno);
        return false;
    }
#endif

    return true;
}

void install_oops_handler()
{
    add_signal(SIGILL, oops_handler);
    add_signal(SIGABRT, oops_handler);
    add_signal(SIGBUS, oops_handler);
    add_signal(SIGFPE, oops_handler);
    add_signal(SIGSEGV, oops_handler);
}

void init_signals()
{
    sigset_t set;

    sigemptyset(&set);
    // FIXIT-L this is undefined for multithreaded apps
    sigprocmask(SIG_SETMASK, &set, nullptr);

    // First things first, install the crash handler
    install_oops_handler();

    // Ignore SIGPIPE for now (it's not particularly actionable in a multithreaded program)
    add_signal(SIGPIPE, SIG_IGN);

    // Set up a clean exit when expected shutdown signals come along
    add_signal(SIGTERM, exit_handler);
    add_signal(SIGINT, exit_handler);
    add_signal(SIGQUIT, dirty_handler);

    // Finally, set up signal handlers for custom Snort actions
    add_signal(SIGNAL_SNORT_DUMP_STATS, dump_stats_handler);
    add_signal(SIGNAL_SNORT_ROTATE_STATS, rotate_stats_handler);
    add_signal(SIGNAL_SNORT_RELOAD, reload_config_handler);
    add_signal(SIGNAL_SNORT_READ_ATTR_TBL, reload_attrib_handler);

    // Errno will have potentially been left set from a failed handler installation
    errno = 0;
}

void remove_oops_handler()
{
    restore_signal(SIGILL);
    restore_signal(SIGABRT);
    restore_signal(SIGBUS);
    restore_signal(SIGFPE);
    restore_signal(SIGSEGV);
}

void term_signals()
{
    restore_signal(SIGNAL_SNORT_DUMP_STATS);
    restore_signal(SIGNAL_SNORT_ROTATE_STATS);
    restore_signal(SIGNAL_SNORT_RELOAD);
    restore_signal(SIGNAL_SNORT_READ_ATTR_TBL);

    restore_signal(SIGTERM);
    restore_signal(SIGINT);
    restore_signal(SIGQUIT);

    restore_signal(SIGPIPE);

    remove_oops_handler();
}

static void help_signal(unsigned n, const char* name, const char* h)
{
    std::cout << Markup::item();

    std::cout << Markup::emphasis_on();
    std::cout << name;
    std::cout << Markup::emphasis_off();

    std::cout << "(" << n << "): " << h << std::endl;
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
    bool err = (close(STDIN_FILENO) != 0);
    err = err or (close(STDOUT_FILENO) != 0);
    err = err or (close(STDERR_FILENO) != 0);

    /* redirect stdin/stdout/stderr to /dev/null */
    err = err or (open("/dev/null", O_RDWR) != STDIN_FILENO);  // fd 0

    err = err or (dup(STDIN_FILENO) != STDOUT_FILENO);  // fd 0 => fd 1
    err = err or (dup(STDIN_FILENO) != STDERR_FILENO);  // fd 0 => fd 2

    if ( err )
        // message is hit or miss but we will exit with failure
        FatalError("failed to snuff stdio - %s", get_error(errno));
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
    add_signal(SIGNAL_SNORT_CHILD_READY, child_ready_handler);

    pid_t cpid = fork();

    if ( cpid < 0 )
        FatalError("fork failed - %s", get_error(errno));

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
    errno = 0;  // disregard any inherited issues

    setsid();

    if ( errno )
        FatalError("failed to setsid - %s", get_error(errno));

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
