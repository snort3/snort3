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

#include "snort.h"
#include "snort_debug.h"
#include "thread.h"
#include "helpers/swapper.h"
#include "log/messages.h"
#include "memory/memory_cap.h"
#include "packet_io/sfdaq.h"
#include "tics/tics.h"

using namespace std;

typedef DAQ_Verdict
(* PacketCallback)(void*, const DAQ_PktHdr_t*, const uint8_t*);

// FIXIT-M add fail open capability
static THREAD_LOCAL PacketCallback main_func = Snort::packet_callback;

//-------------------------------------------------------------------------
// analyzer
//-------------------------------------------------------------------------

const char* Analyzer::get_state_string()
{
    switch (state)
    {
        case State::NEW:
            return "NEW";

        case State::INITIALIZED:
            return "INITIALIZED";

        case State::STARTED:
            return "STARTED";

        case State::RUNNING:
            return "RUNNING";

        case State::PAUSED:
            return "PAUSED";

        case State::STOPPED:
            return "STOPPED";
    }

    return "UNKNOWN";
}

const char* Analyzer::get_command_string(AnalyzerCommand ac)
{
    switch (ac)
    {
        case AC_NONE:
            return "NONE";

        case AC_START:
            return "START";

        case AC_RUN:
            return "RUN";

        case AC_STOP:
            return "STOP";

        case AC_PAUSE:
            return "PAUSE";

        case AC_RESUME:
            return "RESUME";

        case AC_ROTATE:
            return "ROTATE";

        case AC_SWAP:
            return "SWAP";
    }

    return "UNRECOGNIZED";
}

Analyzer::Analyzer(unsigned i, const char* s)
{
    state = State::NEW;
    count = 0;
    id = i;
    source = s;
    command = AC_NONE;
    swap = nullptr;
    daq_instance = nullptr;
    privileged_start = false;
}

void Analyzer::operator()(Swapper* ps)
{
    set_thread_type(STHREAD_TYPE_PACKET);

    set_instance_id(id);
    ps->apply();

    if (Snort::thread_init_privileged(source))
    {
        daq_instance = SFDAQ::get_local_instance();
        privileged_start = daq_instance->can_start_unprivileged();
        state = State::INITIALIZED;

        analyze();

        Snort::thread_term();
    }

    delete ps;
    state = State::STOPPED;
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
    if (daq_instance)
        daq_instance->break_loop(0);
}

bool Analyzer::handle_command()
{
    switch (command)
    {
        case AC_START:
            if (state != State::INITIALIZED)
            {
                if (state != State::STARTED)
                    ErrorMessage("Analyzer: Received START command while in state %s\n", get_state_string());
                command = AC_NONE;
                return false;
            }
            if (!daq_instance->start())
            {
                ErrorMessage("Analyzer: Failed to start DAQ instance\n");
                command = AC_NONE;
                return false;
            }
            state = State::STARTED;
            DebugMessage(DEBUG_ANALYZER, "Handled START command\n");
            command = AC_NONE;
            break;

        case AC_RUN:
            if (state != State::STARTED)
            {
                if (state != State::RUNNING)
                    ErrorMessage("Analyzer: Received RUN command while in state %s\n", get_state_string());
                command = AC_NONE;
                return false;
            }
            Snort::thread_init_unprivileged();
            state = State::RUNNING;
            DebugMessage(DEBUG_ANALYZER, "Handled RUN command\n");
            command = AC_NONE;
            break;

        case AC_STOP:
            DebugMessage(DEBUG_ANALYZER, "Handled STOP command\n");
            command = AC_NONE;
            return false;

        case AC_PAUSE:
            if (state == State::RUNNING)
                state = State::PAUSED;
            else
                ErrorMessage("Analyzer: Received PAUSE command while in state %s\n", get_state_string());
            command = AC_NONE;
            break;

        case AC_RESUME:
            if (state == State::PAUSED)
                state = State::RUNNING;
            else
                ErrorMessage("Analyzer: Received RESUME command while in state %s\n", get_state_string());
            command = AC_NONE;
            break;

        case AC_ROTATE:
            Snort::thread_rotate();
            command = AC_NONE;
            break;

        case AC_SWAP:
            if (swap)
            {
                swap->apply();
                swap = nullptr;
            }
            command = AC_NONE;
            break;

        default:
            command = AC_NONE;
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

