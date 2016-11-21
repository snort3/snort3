//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// analyzer.cc author Russ Combs <rucombs@cisco.com>

#include "analyzer.h"

#include <chrono>
#include <thread>

#include "main.h"
#include "snort.h"
#include "snort_debug.h"
#include "thread.h"
#include "helpers/swapper.h"
#include "log/messages.h"
#include "memory/memory_cap.h"
#include "packet_io/sfdaq.h"

using namespace std;

typedef DAQ_Verdict
(* PacketCallback)(void*, const DAQ_PktHdr_t*, const uint8_t*);

// FIXIT-M add fail open capability
static THREAD_LOCAL PacketCallback main_func = Snort::packet_callback;

//-------------------------------------------------------------------------
// analyzer
//-------------------------------------------------------------------------

void Analyzer::set_state(State s)
{
    state = s;
    main_poke(id);
}

const char* Analyzer::get_state_string()
{
    State s = get_state();  // can't use atomic in switch with optimization

    switch ( s )
    {
    case State::NEW:         return "NEW";
    case State::INITIALIZED: return "INITIALIZED";
    case State::STARTED:     return "STARTED";
    case State::RUNNING:     return "RUNNING";
    case State::PAUSED:      return "PAUSED";
    case State::STOPPED:     return "STOPPED";
    }

    return "UNKNOWN";
}

const char* Analyzer::get_command_string(AnalyzerCommand ac)
{
    switch ( ac )
    {
    case AC_NONE:   return "NONE";
    case AC_START:  return "START";
    case AC_RUN:    return "RUN";
    case AC_STOP:   return "STOP";
    case AC_PAUSE:  return "PAUSE";
    case AC_RESUME: return "RESUME";
    case AC_ROTATE: return "ROTATE";
    case AC_SWAP:   return "SWAP";
    }

    return "UNRECOGNIZED";
}

Analyzer::Analyzer(unsigned i, const char* s)
{
    id = i;
    source = s;
    command = AC_NONE;
    swap = nullptr;
    daq_instance = nullptr;
    privileged_start = false;
    set_state(State::NEW);
}

void Analyzer::operator()(Swapper* ps)
{
    set_thread_type(STHREAD_TYPE_PACKET);
    set_instance_id(id);

    ps->apply();
    delete ps;

    if (Snort::thread_init_privileged(source))
    {
        daq_instance = SFDAQ::get_local_instance();
        privileged_start = daq_instance->can_start_unprivileged();
        set_state(State::INITIALIZED);

        analyze();

        Snort::thread_term();
    }

    set_state(State::STOPPED);
}

/* Note: This will be called from the main thread.  Everything it does must be
    thread-safe in relation to interactions with the analyzer thread. */
void Analyzer::execute(AnalyzerCommand ac)
{
    /* Nobody should be sending a command while we are still processing one. */
    assert(command == AC_NONE);

    command = ac;

    /* Break out of the DAQ acquire loop so that the command will be processed.
        This is explicitly safe to call from another thread. */
    if ( state == State::RUNNING and daq_instance )
        daq_instance->break_loop(0);
}

bool Analyzer::handle_command()
{
    AnalyzerCommand ac = command;  // can't use atomic in switch with optimization

    switch ( ac )
    {
    case AC_START:
        assert(state == State::INITIALIZED);

        if (!daq_instance->start())
        {
            ErrorMessage("Analyzer: Failed to start DAQ instance\n");
            return false;
        }
        command = AC_NONE;
        set_state(State::STARTED);
        DebugMessage(DEBUG_ANALYZER, "Handled START command\n");
        break;

    case AC_RUN:
        assert(state == State::STARTED);
        Snort::thread_init_unprivileged();
        command = AC_NONE;
        set_state(State::RUNNING);
        DebugMessage(DEBUG_ANALYZER, "Handled RUN command\n");
        break;

    case AC_STOP:
        command = AC_NONE;
        DebugMessage(DEBUG_ANALYZER, "Handled STOP command\n");
        return false;

    case AC_PAUSE:
        command = AC_NONE;
        if (state == State::RUNNING)
            set_state(State::PAUSED);
        else
            ErrorMessage("Analyzer: Received PAUSE command while in state %s\n",
                get_state_string());
        break;

    case AC_RESUME:
        command = AC_NONE;
        if (state == State::PAUSED)
            set_state(State::RUNNING);
        else
            ErrorMessage("Analyzer: Received RESUME command while in state %s\n",
                get_state_string());
        break;

    case AC_ROTATE:
        Snort::thread_rotate();
        command = AC_NONE;
        break;

    case AC_SWAP:
        if (swap)
            swap->apply();

        // clear cmd only; swap ptr cleared by main thread
        command = AC_NONE;
        break;

    case AC_NONE:
        break;
    }
    return true;
}

void Analyzer::analyze()
{
    // The main analyzer loop is terminated by a command returning false or an error during acquire
    while (true)
    {
        if (!handle_command())
            break;
        // If we're not in the running state (usually either pre-start or paused),
        // just keep stalling until something else comes up.
        if (state != State::RUNNING)
        {
            chrono::milliseconds ms(10);
            this_thread::sleep_for(ms);
            continue;
        }
        if (daq_instance->acquire(0, main_func))
            break;

        // FIXIT-L acquire(0) makes idle processing unlikely under high traffic
        // because it won't return until no packets, signal, etc.  that means
        // the idle processing may not be useful or that we need a hook to do
        // things periodically even when traffic is available
        Snort::thread_idle();
    }
}

