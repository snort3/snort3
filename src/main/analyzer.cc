/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Capyright (C) 2013-2013 Sourcefire, Inc.
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
// analyzer.cc author Russ Combs <rucombs@cisco.com>

#include "analyzer.h"

#include <chrono>
#include <thread>
using namespace std;

#include "snort.h"
#include "helpers/swapper.h"
#include "packet_io/sfdaq.h"

typedef DAQ_Verdict
    (*PacketCallback)(void*, const DAQ_PktHdr_t*, const uint8_t*);

static THREAD_LOCAL PacketCallback main_func = fail_open;

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
}

void Analyzer::operator()(unsigned id, Swapper* ps)
{
    set_instance_id(id);
    ps->apply();

    snort_thread_init(source);
    main_func = packet_callback;

    analyze();

    snort_thread_term();

    delete ps;
    done = true;
}

bool Analyzer::handle(AnalyzerCommand ac)
{
    switch ( ac )
    {
    case AC_STOP:
        return false;

    case AC_PAUSE:
        {
            chrono::seconds sec(1);
            this_thread::sleep_for(sec);
        }
        break;

    case AC_RESUME:
        break;

    case AC_ROTATE:
        snort_rotate();
        break;

    case AC_SWAP:
        if ( swap )
        {
            swap->apply();
            swap = nullptr;
        }
        break;

    default:
        break;
    }
    return true;
}

void Analyzer::analyze()
{
    uint64_t max = snort_conf->pkt_cnt;

    while ( true )
    {
        if ( command )
        {
            if ( !handle(command) )
                break;

            if ( command == AC_PAUSE )
                continue;

            command = AC_NONE;
        }
        if ( DAQ_Acquire(0, main_func, NULL) )
            break;

        ++count;

        if ( max && count >= max )
            break;
    }
}

