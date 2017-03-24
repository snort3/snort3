//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// perf_monitor.h author Carter Waxman <cwaxman@cisco.com>

#ifndef PERF_MONITOR_H
#define PERF_MONITOR_H

// These are the basic functions and structures that are needed to call
// performance functions.

#include "perf_module.h"

struct Packet;

extern PerfConfig* perfmon_config;  // FIXIT-M shouldn't be needed externally
extern THREAD_LOCAL bool perfmon_rotate_perf_file;

void perf_monitor_idle_process();

/* functions to set & get the RotatePerfFileFlag */
inline void SetRotatePerfFileFlag()
{
    perfmon_rotate_perf_file = true;
}

inline bool IsSetRotatePerfFileFlag()
{
    return perfmon_rotate_perf_file;
}

inline void ClearRotatePerfFileFlag()
{
    perfmon_rotate_perf_file = false;
}

#endif

