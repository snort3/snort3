//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
using namespace std;

#include "snort.h"
#include "thread.h"
#include "helpers/swapper.h"
#include "packet_io/sfdaq.h"

typedef DAQ_Verdict
(* PacketCallback)(void*, const DAQ_PktHdr_t*, const uint8_t*);

// FIXIT-M add fail open capability
static THREAD_LOCAL PacketCallback main_func = Snort::packet_callback;

//-------------------------------------------------------------------------
// analyzer
//-------------------------------------------------------------------------

Analyzer::Analyzer(const char* s)
{
    done = false;
    count = 0;
    source = s;
    command = AC_NONE;
    swap = nullptr;
    daqh = nullptr;
}

void Analyzer::operator()(unsigned id, Swapper* ps)
{
    set_instance_id(id);
    ps->apply();

    pin_thread_to_cpu(source);
    Snort::thread_init(source);
    daqh = DAQ_GetHandle();

    analyze();

    Snort::thread_term();

    delete ps;
    done = true;
}

bool Analyzer::execute(AnalyzerCommand ac)
{
    if ( command && command != AC_PAUSE )
        return false;

    if ( ac == AC_STOP )
        DAQ_BreakLoop(-1, daqh);

    // FIXIT-L executing a command while paused
    // will cause a resume
    command = ac;
    take_break();

    return true;
}

// clear pause in analyze() to avoid extra acquires
// (eg stop while paused)
// clear other commands here to avoid clearing an
// unexecuted command received while paused
bool Analyzer::handle(AnalyzerCommand ac)
{
    switch ( ac )
    {
    case AC_STOP:
        return false;

    case AC_PAUSE:
    {
        chrono::milliseconds ms(500);
        this_thread::sleep_for(ms);
    }
    break;

    case AC_RESUME:
        command = AC_NONE;
        break;

    case AC_ROTATE:
        Snort::thread_rotate();
        command = AC_NONE;
        break;

    case AC_SWAP:
        if ( swap )
        {
            swap->apply();
            swap = nullptr;
        }
        command = AC_NONE;
        break;

    default:
        break;
    }
    return true;
}

void Analyzer::analyze()
{
    while ( true )
    {
        if ( command )
        {
            if ( !handle(command) )
                break;

            if ( command == AC_PAUSE )
                continue;
        }
        if ( DAQ_Acquire(0, main_func, NULL) )
            break;

        // FIXIT-L acquire(0) won't return until no packets, signal, etc.
        // which makes this idle unlikely to execute under high traffic
        // conditions; that means the idle processing may not be useful
        // or that we need a hook to do things periodically even when
        // traffic is available
        Snort::thread_idle();
    }
}

