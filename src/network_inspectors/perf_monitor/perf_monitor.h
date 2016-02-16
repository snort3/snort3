//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
/*
**  DESCRIPTION
**    These are the basic functions and structures that are needed to call
**    performance functions.
**
** Carter Waxman <cwaxman@cisco.com>
*/

#ifndef PERF_MONITOR_H
#define PERF_MONITOR_H

#include "perf_flow.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "main/thread.h"

// Perf Flags
#define SFPERF_BASE             0x00000001
#define SFPERF_FLOW             0x00000002
#define SFPERF_EVENT            0x00000004
#define SFPERF_BASE_MAX         0x00000008
#define SFPERF_CONSOLE          0x00000010
#define SFPERF_PKTCNT           0x00000020
#define SFPERF_FLOWIP           0x00000040
#define SFPERF_TIME_COUNT       0x00000080
#define SFPERF_MAX_BASE_STATS   0x00000100

#define SFPERF_SUMMARY_BASE     0x00001000
#define SFPERF_SUMMARY_FLOW     0x00002000
#define SFPERF_SUMMARY_FLOWIP   0x00004000
#define SFPERF_SUMMARY_EVENT    0x00008000
#define SFPERF_SUMMARY \
    (SFPERF_SUMMARY_BASE|SFPERF_SUMMARY_FLOW|SFPERF_SUMMARY_FLOWIP|SFPERF_SUMMARY_EVENT)

/* The perfmonitor configuration */
typedef struct _SFPERF
{
    int perf_flags;
    uint32_t pkt_cnt;
    int sample_interval;
    bool file;
    int base_reset;
    int flow_max_port_to_track;
    bool flow_file;
    uint64_t max_file_size;
    bool flowip_file;
    uint32_t flowip_memcap;
} SFPERF;

//FIXIT-M: this shouldn't be needed outside of perfmon
extern SFPERF* perfmon_config;
extern THREAD_LOCAL bool perfmon_rotate_perf_file;

void perf_monitor_idle_process();

/* functions to set & get the RotatePerfFileFlag */
inline void SetRotatePerfFileFlag(void)
{
    perfmon_rotate_perf_file = true;
}

inline bool IsSetRotatePerfFileFlag(void)
{
    return perfmon_rotate_perf_file;
}

inline void ClearRotatePerfFileFlag(void)
{
    perfmon_rotate_perf_file = false;
}

#endif

