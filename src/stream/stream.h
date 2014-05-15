/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef STREAM_H
#define STREAM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <netinet/in.h>

#include "utils/bitop_funcs.h"
#include "sfip/ipv6_port.h"
#include "framework/inspector.h"

#include "mempool/mempool.h"
#include "snort_types.h"
#include "snort.h"
#include "detect.h"
#include "stream/stream_api.h"

#include "target_based/sftarget_hostentry.h"

//#define DEBUG_STREAM5 DEBUG

#define S5_DEFAULT_SSN_TIMEOUT  30        /* seconds to timeout a session */
#define S5_MAX_SSN_TIMEOUT      3600*24   /* max timeout (approx 1 day) */
#define S5_MIN_SSN_TIMEOUT      1         /* min timeout (1 second) */

#define S5_TRACK_YES            1
#define S5_TRACK_NO             0

// FIXIT move to proto specific where possible
#define STREAM5_CONFIG_STATEFUL_INSPECTION      0x00000001
#define STREAM5_CONFIG_LOG_STREAMS              0x00000004
#define STREAM5_CONFIG_REASS_CLIENT             0x00000008
#define STREAM5_CONFIG_REASS_SERVER             0x00000010
#define STREAM5_CONFIG_ASYNC                    0x00000020
#define STREAM5_CONFIG_SHOW_PACKETS             0x00000040
#define STREAM5_CONFIG_REQUIRE_3WHS             0x00000100
#define STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT   0x00000200
#define STREAM5_CONFIG_IGNORE_ANY               0x00000400
#define STREAM5_CONFIG_STATIC_FLUSHPOINTS       0x00001000
#define STREAM5_CONFIG_IPS                      0x00002000
#define STREAM5_CONFIG_NO_ASYNC_REASSEMBLY      0x00004000

/* traffic direction identification */
#define FROM_SERVER     0
#define FROM_RESPONDER  0
#define FROM_CLIENT     1
#define FROM_SENDER     1

class Memcap {
public:
    Memcap(unsigned u) { cap = u; use = 0; };

    void set_cap(unsigned c) { cap = c; };
    unsigned get_cap() { return cap; };
    bool at_max() { return use >= cap; };
    void alloc(unsigned sz) { use += sz; };
    void dealloc(unsigned sz) { if ( use >= sz) use -= sz; };
    unsigned used() { return use; };

private:
    unsigned cap;
    unsigned use;
};

/*  D A T A   S T R U C T U R E S  **********************************/
// FIXIT some of this stuff can be better encapsulated

struct Stream5GlobalConfig
{
    uint32_t prune_log_max;
    uint32_t flags;

    Stream5GlobalConfig();
};

struct Stream5Config
{
    class FlowControl* fc;
    class Stream* stream;

    struct Stream5GlobalConfig *global_config;
    uint8_t service_filter[MAX_PROTOCOL_ORDINAL];
};

typedef struct {
    PegCount  filtered;
    PegCount  inspected;
    PegCount  session_tracked;
} tPortFilterStats;

struct SessionStats
{
    PegCount sessions;
    PegCount prunes;
    PegCount timeouts;
    PegCount created;
    PegCount released;
    PegCount discards;
    PegCount events;
};

// shared stream state
extern THREAD_LOCAL Memcap* tcp_memcap;
extern THREAD_LOCAL class FlowControl* flow_con;

extern const char* session_pegs[];
extern const unsigned session_peg_count;

void Stream_SumNormalizationStats(void);
void Stream_PrintNormalizationStats(void);
void Stream_ResetNormalizationStats(void);

#endif

