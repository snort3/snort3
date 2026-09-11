//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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
// sfrf_test.cc author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"
#include "detection/rules.h"
#include "main/snort_config.h"
#include "parser/parse_ip.h"
#include "sfip/sf_ip.h"

#include "rate_filter.h"
#include "sfrf.h"

using namespace snort;

//---------------------------------------------------------------

#define IP_ANY   nullptr          // used to get "unset"

#define IP4_SRC  "1.2.3.4"
#define IP4_DST  "1.2.3.5"
#define IP4_EXT  "2.2.3.6"     // doesn't match either src|dst

#define IP4_NET  "1.2.0.0/16"
#define IP6_SRC  "1:2::8"
#define IP6_DST  "1:2::9"
#define IP6_NET  "1:2::/32"
#define IP6_EXT  "2:2::8"

#define IP4_SET1 "[1.2.3.4,1.2.3.5]"
#define IP4_SET2 "[1.2.0.0/16,![1.2.3.4,1.2.3.5]]"

#define RULE_ORIG  (-1)          // original action applies
#define RULE_NEW    0          // new_action when not orig

#define MEM_DEFAULT (16*1024*1024)  // default if not re"config"ed
#define MEM_MINIMUM 0          // forces use of minimum

typedef struct
{
    int gid;
    int sid;
    SFRF_TRACK track;
    int count;
    int seconds;
    int timeout;
    const char* ip;
    int expect;
    int create;
} RateData;

typedef struct
{
    unsigned int seq;
    unsigned int gid;
    unsigned int sid;
    const char* sip;
    const char* dip;
    float now;
    int expect;
} EventData;

static RateFilterConfig* rfc = nullptr;

//---------------------------------------------------------------

#define TRK_DST SFRF_TRACK_BY_DST
#define TRK_SRC SFRF_TRACK_BY_SRC
#define TRK_RUL SFRF_TRACK_BY_RULE

static RateData rfData[] =
{
    // illegal gid, sid checks
    { -1,   -1, TRK_DST,  1,  1,  0, IP_ANY, -1, 0 }
    ,{ 0,    0, TRK_DST,  1,  1,  0, IP_ANY, -1, 0 }
    ,{ 0, 2100, TRK_DST,  1,  1,  0, IP_ANY, -1, 0 }
    ,{ 100,    0, TRK_DST,  1,  1,  0, IP_ANY, -1, 0 }
    ,{ 100, 8129, TRK_DST,  1,  1,  0, IP_ANY,  0, 0 }
    ,{ 8129, 2100, TRK_DST,  1,  1,  0, IP_ANY, -1, 0 }

    // duplicate gid, sid checks
    ,{ 100, 1110, TRK_SRC,  1,  1,  0, IP_ANY,  0, 0 }
    ,{ 100, 2110, TRK_DST,  1,  1,  0, IP_ANY,  0, 0 }
    ,{ 100, 3110, TRK_RUL,  1,  1,  0, IP_ANY,  0, 0 }

    // count checks
    ,{ 100, 1000, TRK_SRC,  0,  0,  0, IP_ANY, -1, 0 }
    ,{ 100, 2000, TRK_DST,  0,  0,  0, IP_ANY, -1, 0 }
    ,{ 100, 3000, TRK_RUL,  0,  0,  0, IP_ANY, -1, 0 }

    // rate tests w/o apply ...
    ,{ 200, 1110, TRK_SRC,  1,  1,  0, IP_ANY,  0, 0 }
    ,{ 200, 1111, TRK_SRC,  1,  1,  1, IP_ANY,  0, 0 }
    ,{ 200, 1121, TRK_SRC,  1,  2,  1, IP_ANY,  0, 0 }
    ,{ 200, 1311, TRK_SRC,  3,  1,  1, IP_ANY,  0, 0 }
    ,{ 200, 1321, TRK_SRC,  3,  2,  1, IP_ANY,  0, 0 }
    ,{ 200, 1312, TRK_SRC,  3,  1,  2, IP_ANY,  0, 0 }
    ,{ 200, 2110, TRK_DST,  1,  1,  0, IP_ANY,  0, 0 }
    ,{ 200, 2111, TRK_DST,  1,  1,  1, IP_ANY,  0, 0 }
    ,{ 200, 3110, TRK_RUL,  1,  1,  0, IP_ANY,  0, 0 }
    ,{ 200, 3111, TRK_RUL,  1,  1,  1, IP_ANY,  0, 0 }

    ,{ 210, 3311, TRK_RUL,  3,  1,  1, IP_ANY,  0, 0 }
    ,{ 210, 3315, TRK_RUL,  3,  1,  5, IP_ANY,  0, 0 }
    ,{ 210, 3319, TRK_RUL,  3,  1,  9, IP_ANY,  0, 0 }
    ,{ 210, 3351, TRK_RUL,  3,  5,  1, IP_ANY,  0, 0 }
    ,{ 210, 3355, TRK_RUL,  3,  5,  5, IP_ANY,  0, 0 }
    ,{ 210, 3359, TRK_RUL,  3,  5,  9, IP_ANY,  0, 0 }
    ,{ 210, 3391, TRK_RUL,  3,  9,  1, IP_ANY,  0, 0 }
    ,{ 210, 3395, TRK_RUL,  3,  9,  5, IP_ANY,  0, 0 }
    ,{ 210, 3399, TRK_RUL,  3,  9,  9, IP_ANY,  0, 0 }

    // rate tests w/apply ...
    ,{ 300, 1110, TRK_SRC,  1,  1,  0, IP4_NET, 0, 0 }
    ,{ 300, 2110, TRK_DST,  1,  1,  0, IP4_NET, 0, 0 }
    ,{ 310, 1110, TRK_SRC,  1,  1,  0, "!" IP4_NET, 0, 0 }
    ,{ 310, 2110, TRK_DST,  1,  1,  0, "!" IP4_NET, 0, 0 }

    // ipv6 rate tests w/apply ...
    ,{ 400, 1110, TRK_SRC,  1,  1,  0, IP6_NET, 0, 0 }
    ,{ 400, 2110, TRK_DST,  1,  1,  0, IP6_NET, 0, 0 }
    ,{ 410, 1110, TRK_SRC,  1,  1,  0, "!" IP6_NET, 0, 0 }
    ,{ 410, 2110, TRK_DST,  1,  1,  0, "!" IP6_NET, 0, 0 }
};

#define NUM_NODES (sizeof(rfData)/sizeof(rfData[0]))

//---------------------------------------------------------------
// the seq field is only used to easily identify any failed tests

static EventData evData[] =
{
    { 0, 200, 1110, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1110, IP4_SRC, IP4_DST, 0.1, RULE_NEW }
    ,{ 2, 200, 1110, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 1110, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 4, 200, 1110, IP4_SRC, IP4_DST, 9.9, RULE_NEW }

    ,{ 0, 200, 1111, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1111, IP4_EXT, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 200, 1111, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 1111, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 4, 200, 1111, IP4_SRC, IP4_DST, 1.1, RULE_NEW }
    ,{ 5, 200, 1111, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 6, 200, 1111, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 7, 200, 1111, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }

    ,{ 0, 200, 1121, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1121, IP4_SRC, IP4_DST, 0.1, RULE_NEW }
    ,{ 2, 200, 1121, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 1121, IP4_SRC, IP4_DST, 0.3, RULE_NEW }
    ,{ 4, 200, 1121, IP4_SRC, IP4_DST, 0.4, RULE_NEW }
    ,{ 5, 200, 1121, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 6, 200, 1121, IP4_SRC, IP4_DST, 1.1, RULE_NEW }
    ,{ 7, 200, 1121, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 8, 200, 1121, IP4_SRC, IP4_DST, 1.3, RULE_NEW }
    ,{ 9, 200, 1121, IP4_SRC, IP4_DST, 1.4, RULE_NEW }
    ,{ 10, 200, 1121, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 11, 200, 1121, IP4_SRC, IP4_DST, 2.1, RULE_NEW }
    ,{ 12, 200, 1121, IP4_SRC, IP4_DST, 3.0, RULE_NEW }
    ,{ 13, 200, 1121, IP4_SRC, IP4_DST, 4.0, RULE_NEW }
    ,{ 14, 200, 1121, IP4_SRC, IP4_DST, 5.0, RULE_NEW }
    ,{ 15, 200, 1121, IP4_SRC, IP4_DST, 5.1, RULE_NEW }
    ,{ 16, 200, 1121, IP4_SRC, IP4_DST, 6.0, RULE_NEW }
    ,{ 17, 200, 1121, IP4_SRC, IP4_DST, 8.0, RULE_ORIG }
    ,{ 18, 200, 1121, IP4_SRC, IP4_DST,10.0, RULE_ORIG }

    ,{ 0, 200, 1311, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1311, IP4_SRC, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 200, 1311, IP4_SRC, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 200, 1311, IP4_SRC, IP4_DST, 0.3, RULE_NEW }
    ,{ 4, 200, 1311, IP4_SRC, IP4_DST, 0.4, RULE_NEW }
    ,{ 5, 200, 1311, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 6, 200, 1311, IP4_SRC, IP4_DST, 1.1, RULE_NEW }
    ,{ 7, 200, 1311, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 8, 200, 1311, IP4_SRC, IP4_DST, 1.3, RULE_NEW }
    ,{ 9, 200, 1311, IP4_SRC, IP4_DST, 1.4, RULE_NEW }
    ,{ 10, 200, 1311, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 11, 200, 1311, IP4_SRC, IP4_DST, 2.1, RULE_NEW }
    ,{ 12, 200, 1311, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }

    ,{ 0, 200, 1321, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1321, IP4_SRC, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 200, 1321, IP4_SRC, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 200, 1321, IP4_SRC, IP4_DST, 0.3, RULE_NEW }
    ,{ 4, 200, 1321, IP4_SRC, IP4_DST, 0.4, RULE_NEW }
    ,{ 5, 200, 1321, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 6, 200, 1321, IP4_SRC, IP4_DST, 1.1, RULE_NEW }
    ,{ 7, 200, 1321, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 8, 200, 1321, IP4_SRC, IP4_DST, 1.3, RULE_NEW }
    ,{ 9, 200, 1321, IP4_SRC, IP4_DST, 1.4, RULE_NEW }
    ,{ 10, 200, 1321, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 11, 200, 1321, IP4_SRC, IP4_DST, 2.1, RULE_NEW }
    ,{ 12, 200, 1321, IP4_SRC, IP4_DST, 3.0, RULE_NEW }
    ,{ 13, 200, 1321, IP4_SRC, IP4_DST, 4.0, RULE_ORIG }
    ,{ 14, 200, 1321, IP4_SRC, IP4_DST, 5.0, RULE_ORIG }

    ,{ 0, 200, 1312, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1312, IP4_SRC, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 200, 1312, IP4_SRC, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 200, 1312, IP4_SRC, IP4_DST, 0.3, RULE_NEW }
    ,{ 4, 200, 1312, IP4_SRC, IP4_DST, 0.4, RULE_NEW }
    ,{ 5, 200, 1312, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 6, 200, 1312, IP4_SRC, IP4_DST, 1.1, RULE_NEW }
    ,{ 7, 200, 1312, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 8, 200, 1312, IP4_SRC, IP4_DST, 1.3, RULE_NEW }
    ,{ 9, 200, 1312, IP4_SRC, IP4_DST, 1.4, RULE_NEW }
    ,{ 10, 200, 1312, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 11, 200, 1312, IP4_SRC, IP4_DST, 2.1, RULE_NEW }
    ,{ 12, 200, 1312, IP4_SRC, IP4_DST, 3.0, RULE_NEW }
    ,{ 13, 200, 1312, IP4_SRC, IP4_DST, 4.0, RULE_ORIG }
    ,{ 14, 200, 1312, IP4_SRC, IP4_DST, 5.0, RULE_ORIG }

    ,{ 0, 200, 2111, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 2111, IP4_SRC, IP4_EXT, 0.1, RULE_ORIG }
    ,{ 2, 200, 2111, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 2111, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 4, 200, 2111, IP4_SRC, IP4_EXT, 1.1, RULE_ORIG }
    ,{ 5, 200, 2111, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 6, 200, 2111, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 7, 200, 2111, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }

    ,{ 0, 200, 3111, IP4_EXT, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 3111, IP4_SRC, IP4_EXT, 0.1, RULE_NEW }
    ,{ 2, 200, 3111, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 3111, IP4_EXT, IP4_DST, 1.0, RULE_NEW }
    ,{ 4, 200, 3111, IP4_EXT, IP4_DST, 1.1, RULE_NEW }
    ,{ 5, 200, 3111, IP4_SRC, IP4_EXT, 1.2, RULE_NEW }
    ,{ 6, 200, 3111, IP4_SRC, IP4_EXT, 2.0, RULE_NEW }
    ,{ 7, 200, 3111, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }

    ,{ 0, 210, 3311, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3311, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3311, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3311, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3311, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3311, IP4_SRC, IP4_DST,  1.0, RULE_NEW }
    ,{ 6, 210, 3311, IP4_SRC, IP4_DST,  1.1, RULE_NEW }
    ,{ 7, 210, 3311, IP4_SRC, IP4_DST,  1.2, RULE_NEW }
    ,{ 8, 210, 3311, IP4_SRC, IP4_DST,  1.3, RULE_NEW }
    ,{ 9, 210, 3311, IP4_SRC, IP4_DST,  1.4, RULE_NEW }
    ,{ 10, 210, 3311, IP4_SRC, IP4_DST,  2.0, RULE_NEW }
    ,{ 11, 210, 3311, IP4_SRC, IP4_DST,  2.1, RULE_NEW }
    ,{ 12, 210, 3311, IP4_SRC, IP4_DST,  3.0, RULE_ORIG }
    ,{ 13, 210, 3311, IP4_SRC, IP4_DST,  5.0, RULE_ORIG }
    ,{ 14, 210, 3311, IP4_SRC, IP4_DST,  5.1, RULE_ORIG }
    ,{ 15, 210, 3311, IP4_SRC, IP4_DST,  5.2, RULE_ORIG }
    ,{ 16, 210, 3311, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 17, 210, 3311, IP4_SRC, IP4_DST,  9.8, RULE_ORIG }
    ,{ 18, 210, 3311, IP4_SRC, IP4_DST,  9.9, RULE_ORIG }
    ,{ 19, 210, 3311, IP4_SRC, IP4_DST, 10.0, RULE_ORIG }
    ,{ 20, 210, 3311, IP4_SRC, IP4_DST, 11.0, RULE_ORIG }

    ,{ 0, 210, 3315, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3315, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3315, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3315, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3315, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3315, IP4_SRC, IP4_DST,  1.0, RULE_NEW }
    ,{ 6, 210, 3315, IP4_SRC, IP4_DST,  1.1, RULE_NEW }
    ,{ 7, 210, 3315, IP4_SRC, IP4_DST,  1.2, RULE_NEW }
    ,{ 8, 210, 3315, IP4_SRC, IP4_DST,  1.3, RULE_NEW }
    ,{ 9, 210, 3315, IP4_SRC, IP4_DST,  1.4, RULE_NEW }
    ,{ 10, 210, 3315, IP4_SRC, IP4_DST,  2.0, RULE_NEW }
    ,{ 11, 210, 3315, IP4_SRC, IP4_DST,  2.1, RULE_NEW }
    ,{ 12, 210, 3315, IP4_SRC, IP4_DST,  3.0, RULE_NEW }
    ,{ 13, 210, 3315, IP4_SRC, IP4_DST,  5.0, RULE_ORIG }
    ,{ 14, 210, 3315, IP4_SRC, IP4_DST,  5.1, RULE_ORIG }
    ,{ 15, 210, 3315, IP4_SRC, IP4_DST,  5.2, RULE_ORIG }
    ,{ 16, 210, 3315, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 17, 210, 3315, IP4_SRC, IP4_DST,  9.8, RULE_NEW }
    ,{ 18, 210, 3315, IP4_SRC, IP4_DST,  9.9, RULE_NEW }
    ,{ 19, 210, 3315, IP4_SRC, IP4_DST, 10.0, RULE_ORIG }
    ,{ 20, 210, 3315, IP4_SRC, IP4_DST, 11.0, RULE_ORIG }

    ,{ 0, 210, 3319, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3319, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3319, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3319, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3319, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3319, IP4_SRC, IP4_DST,  1.0, RULE_NEW }
    ,{ 6, 210, 3319, IP4_SRC, IP4_DST,  1.1, RULE_NEW }
    ,{ 7, 210, 3319, IP4_SRC, IP4_DST,  1.2, RULE_NEW }
    ,{ 8, 210, 3319, IP4_SRC, IP4_DST,  1.3, RULE_NEW }
    ,{ 9, 210, 3319, IP4_SRC, IP4_DST,  1.4, RULE_NEW }
    ,{ 10, 210, 3319, IP4_SRC, IP4_DST,  2.0, RULE_NEW }
    ,{ 11, 210, 3319, IP4_SRC, IP4_DST,  2.1, RULE_NEW }
    ,{ 12, 210, 3319, IP4_SRC, IP4_DST,  3.0, RULE_NEW }
    ,{ 13, 210, 3319, IP4_SRC, IP4_DST,  5.0, RULE_NEW }
    ,{ 14, 210, 3319, IP4_SRC, IP4_DST,  5.1, RULE_NEW }
    ,{ 15, 210, 3319, IP4_SRC, IP4_DST,  5.2, RULE_NEW }
    ,{ 16, 210, 3319, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 17, 210, 3319, IP4_SRC, IP4_DST,  9.8, RULE_ORIG }
    ,{ 18, 210, 3319, IP4_SRC, IP4_DST,  9.9, RULE_ORIG }
    ,{ 19, 210, 3319, IP4_SRC, IP4_DST, 10.0, RULE_ORIG }
    ,{ 20, 210, 3319, IP4_SRC, IP4_DST, 11.0, RULE_ORIG }

    ,{ 0, 210, 3351, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3351, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3351, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3351, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3351, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3351, IP4_SRC, IP4_DST,  5.0, RULE_NEW }
    ,{ 6, 210, 3351, IP4_SRC, IP4_DST,  5.1, RULE_NEW }
    ,{ 7, 210, 3351, IP4_SRC, IP4_DST,  5.2, RULE_NEW }
    ,{ 8, 210, 3351, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 9, 210, 3351, IP4_SRC, IP4_DST,  5.4, RULE_NEW }
    ,{ 10, 210, 3351, IP4_SRC, IP4_DST, 10.0, RULE_NEW }
    ,{ 11, 210, 3351, IP4_SRC, IP4_DST, 10.1, RULE_NEW }
    ,{ 12, 210, 3351, IP4_SRC, IP4_DST, 15.0, RULE_ORIG }
    ,{ 13, 210, 3351, IP4_SRC, IP4_DST, 19.0, RULE_ORIG }
    ,{ 14, 210, 3351, IP4_SRC, IP4_DST, 25.0, RULE_ORIG }
    ,{ 15, 210, 3351, IP4_SRC, IP4_DST, 25.1, RULE_ORIG }
    ,{ 16, 210, 3351, IP4_SRC, IP4_DST, 25.2, RULE_ORIG }
    ,{ 17, 210, 3351, IP4_SRC, IP4_DST, 25.3, RULE_NEW }
    ,{ 18, 210, 3351, IP4_SRC, IP4_DST, 45.8, RULE_ORIG }
    ,{ 19, 210, 3351, IP4_SRC, IP4_DST, 45.9, RULE_ORIG }
    ,{ 20, 210, 3351, IP4_SRC, IP4_DST, 50.0, RULE_ORIG }
    ,{ 21, 210, 3351, IP4_SRC, IP4_DST, 55.0, RULE_ORIG }

    ,{ 0, 210, 3355, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3355, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3355, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3355, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3355, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3355, IP4_SRC, IP4_DST,  5.0, RULE_NEW }
    ,{ 6, 210, 3355, IP4_SRC, IP4_DST,  5.1, RULE_NEW }
    ,{ 7, 210, 3355, IP4_SRC, IP4_DST,  5.2, RULE_NEW }
    ,{ 8, 210, 3355, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 9, 210, 3355, IP4_SRC, IP4_DST,  5.4, RULE_NEW }
    ,{ 10, 210, 3355, IP4_SRC, IP4_DST, 10.0, RULE_NEW }
    ,{ 11, 210, 3355, IP4_SRC, IP4_DST, 10.1, RULE_NEW }
    ,{ 12, 210, 3355, IP4_SRC, IP4_DST, 15.0, RULE_ORIG }
    ,{ 13, 210, 3355, IP4_SRC, IP4_DST, 19.0, RULE_ORIG }
    ,{ 14, 210, 3355, IP4_SRC, IP4_DST, 25.0, RULE_ORIG }
    ,{ 15, 210, 3355, IP4_SRC, IP4_DST, 25.1, RULE_ORIG }
    ,{ 16, 210, 3355, IP4_SRC, IP4_DST, 25.2, RULE_ORIG }
    ,{ 17, 210, 3355, IP4_SRC, IP4_DST, 25.3, RULE_NEW }
    ,{ 18, 210, 3355, IP4_SRC, IP4_DST, 45.8, RULE_ORIG }
    ,{ 19, 210, 3355, IP4_SRC, IP4_DST, 45.9, RULE_ORIG }
    ,{ 20, 210, 3355, IP4_SRC, IP4_DST, 50.0, RULE_ORIG }
    ,{ 21, 210, 3355, IP4_SRC, IP4_DST, 55.0, RULE_ORIG }

    ,{ 0, 210, 3359, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3359, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3359, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3359, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3359, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3359, IP4_SRC, IP4_DST,  5.0, RULE_NEW }
    ,{ 6, 210, 3359, IP4_SRC, IP4_DST,  5.1, RULE_NEW }
    ,{ 7, 210, 3359, IP4_SRC, IP4_DST,  5.2, RULE_NEW }
    ,{ 8, 210, 3359, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 9, 210, 3359, IP4_SRC, IP4_DST,  5.4, RULE_NEW }
    ,{ 10, 210, 3359, IP4_SRC, IP4_DST, 10.0, RULE_NEW }
    ,{ 11, 210, 3359, IP4_SRC, IP4_DST, 10.1, RULE_NEW }
    ,{ 12, 210, 3359, IP4_SRC, IP4_DST, 15.0, RULE_NEW }
    ,{ 13, 210, 3359, IP4_SRC, IP4_DST, 19.0, RULE_ORIG }
    ,{ 14, 210, 3359, IP4_SRC, IP4_DST, 25.0, RULE_ORIG }
    ,{ 15, 210, 3359, IP4_SRC, IP4_DST, 25.1, RULE_ORIG }
    ,{ 16, 210, 3359, IP4_SRC, IP4_DST, 25.2, RULE_ORIG }
    ,{ 17, 210, 3359, IP4_SRC, IP4_DST, 25.3, RULE_NEW }
    ,{ 18, 210, 3359, IP4_SRC, IP4_DST, 45.8, RULE_ORIG }
    ,{ 19, 210, 3359, IP4_SRC, IP4_DST, 45.9, RULE_ORIG }
    ,{ 20, 210, 3359, IP4_SRC, IP4_DST, 50.0, RULE_ORIG }
    ,{ 21, 210, 3359, IP4_SRC, IP4_DST, 55.0, RULE_ORIG }

    ,{ 0, 210, 3391, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3391, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3391, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3391, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3391, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3391, IP4_SRC, IP4_DST,  9.0, RULE_NEW }
    ,{ 6, 210, 3391, IP4_SRC, IP4_DST,  9.1, RULE_NEW }
    ,{ 7, 210, 3391, IP4_SRC, IP4_DST,  9.2, RULE_NEW }
    ,{ 8, 210, 3391, IP4_SRC, IP4_DST,  9.3, RULE_NEW }
    ,{ 9, 210, 3391, IP4_SRC, IP4_DST,  9.4, RULE_NEW }
    ,{ 10, 210, 3391, IP4_SRC, IP4_DST, 18.0, RULE_NEW }
    ,{ 11, 210, 3391, IP4_SRC, IP4_DST, 18.1, RULE_NEW }
    ,{ 12, 210, 3391, IP4_SRC, IP4_DST, 27.0, RULE_ORIG }
    ,{ 13, 210, 3391, IP4_SRC, IP4_DST, 35.0, RULE_ORIG }
    ,{ 14, 210, 3391, IP4_SRC, IP4_DST, 45.0, RULE_ORIG }
    ,{ 15, 210, 3391, IP4_SRC, IP4_DST, 45.1, RULE_ORIG }
    ,{ 16, 210, 3391, IP4_SRC, IP4_DST, 45.2, RULE_ORIG }
    ,{ 17, 210, 3391, IP4_SRC, IP4_DST, 45.3, RULE_NEW }
    ,{ 18, 210, 3391, IP4_SRC, IP4_DST, 81.8, RULE_ORIG }
    ,{ 19, 210, 3391, IP4_SRC, IP4_DST, 81.9, RULE_ORIG }
    ,{ 20, 210, 3391, IP4_SRC, IP4_DST, 90.0, RULE_ORIG }
    ,{ 21, 210, 3391, IP4_SRC, IP4_DST, 99.0, RULE_ORIG }

    ,{ 0, 210, 3395, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3395, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3395, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3395, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3395, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3395, IP4_SRC, IP4_DST,  9.0, RULE_NEW }
    ,{ 6, 210, 3395, IP4_SRC, IP4_DST,  9.1, RULE_NEW }
    ,{ 7, 210, 3395, IP4_SRC, IP4_DST,  9.2, RULE_NEW }
    ,{ 8, 210, 3395, IP4_SRC, IP4_DST,  9.3, RULE_NEW }
    ,{ 9, 210, 3395, IP4_SRC, IP4_DST,  9.4, RULE_NEW }
    ,{ 10, 210, 3395, IP4_SRC, IP4_DST, 18.0, RULE_NEW }
    ,{ 11, 210, 3395, IP4_SRC, IP4_DST, 18.1, RULE_NEW }
    ,{ 12, 210, 3395, IP4_SRC, IP4_DST, 27.0, RULE_ORIG }
    ,{ 13, 210, 3395, IP4_SRC, IP4_DST, 35.0, RULE_ORIG }
    ,{ 14, 210, 3395, IP4_SRC, IP4_DST, 45.0, RULE_ORIG }
    ,{ 15, 210, 3395, IP4_SRC, IP4_DST, 45.1, RULE_ORIG }
    ,{ 16, 210, 3395, IP4_SRC, IP4_DST, 45.2, RULE_ORIG }
    ,{ 17, 210, 3395, IP4_SRC, IP4_DST, 45.3, RULE_NEW }
    ,{ 18, 210, 3395, IP4_SRC, IP4_DST, 81.8, RULE_ORIG }
    ,{ 19, 210, 3395, IP4_SRC, IP4_DST, 81.9, RULE_ORIG }
    ,{ 20, 210, 3395, IP4_SRC, IP4_DST, 90.0, RULE_ORIG }
    ,{ 21, 210, 3395, IP4_SRC, IP4_DST, 99.0, RULE_ORIG }

    ,{ 0, 210, 3399, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3399, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3399, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3399, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3399, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3399, IP4_SRC, IP4_DST,  9.0, RULE_NEW }
    ,{ 6, 210, 3399, IP4_SRC, IP4_DST,  9.1, RULE_NEW }
    ,{ 7, 210, 3399, IP4_SRC, IP4_DST,  9.2, RULE_NEW }
    ,{ 8, 210, 3399, IP4_SRC, IP4_DST,  9.3, RULE_NEW }
    ,{ 9, 210, 3399, IP4_SRC, IP4_DST,  9.4, RULE_NEW }
    ,{ 10, 210, 3399, IP4_SRC, IP4_DST, 18.0, RULE_NEW }
    ,{ 11, 210, 3399, IP4_SRC, IP4_DST, 18.1, RULE_NEW }
    ,{ 12, 210, 3399, IP4_SRC, IP4_DST, 27.0, RULE_ORIG }
    ,{ 13, 210, 3399, IP4_SRC, IP4_DST, 35.0, RULE_ORIG }
    ,{ 14, 210, 3399, IP4_SRC, IP4_DST, 45.0, RULE_ORIG }
    ,{ 15, 210, 3399, IP4_SRC, IP4_DST, 45.1, RULE_ORIG }
    ,{ 16, 210, 3399, IP4_SRC, IP4_DST, 45.2, RULE_ORIG }
    ,{ 17, 210, 3399, IP4_SRC, IP4_DST, 45.3, RULE_NEW }
    ,{ 18, 210, 3399, IP4_SRC, IP4_DST, 81.8, RULE_ORIG }
    ,{ 19, 210, 3399, IP4_SRC, IP4_DST, 81.9, RULE_ORIG }
    ,{ 20, 210, 3399, IP4_SRC, IP4_DST, 90.0, RULE_ORIG }
    ,{ 21, 210, 3399, IP4_SRC, IP4_DST, 99.0, RULE_ORIG }

    ,{ 0, 300, 1110, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 300, 1110, IP4_EXT, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 300, 1110, IP4_EXT, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 300, 1110, IP4_SRC, IP4_DST, 1.0, RULE_ORIG }
    ,{ 4, 300, 1110, IP4_SRC, IP4_DST, 1.9, RULE_NEW }
    ,{ 5, 300, 1110, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 6, 300, 1110, IP4_SRC, IP4_DST, 9.9, RULE_NEW }

    ,{ 0, 300, 2110, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 300, 2110, IP4_SRC, IP4_EXT, 0.1, RULE_ORIG }
    ,{ 2, 300, 2110, IP4_SRC, IP4_EXT, 0.2, RULE_ORIG }
    ,{ 3, 300, 2110, IP4_SRC, IP4_DST, 1.0, RULE_ORIG }
    ,{ 4, 300, 2110, IP4_SRC, IP4_DST, 1.9, RULE_NEW }
    ,{ 5, 300, 2110, IP4_SRC, IP4_DST, 2.0, RULE_NEW }
    ,{ 6, 300, 2110, IP4_SRC, IP4_DST, 9.9, RULE_NEW }

    ,{ 0, 310, 1110, IP4_EXT, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 310, 1110, IP4_SRC, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 310, 1110, IP4_SRC, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 310, 1110, IP4_EXT, IP4_DST, 1.0, RULE_ORIG }
    ,{ 4, 310, 1110, IP4_EXT, IP4_DST, 1.9, RULE_NEW }
    ,{ 5, 310, 1110, IP4_EXT, IP4_DST, 2.0, RULE_NEW }
    ,{ 6, 310, 1110, IP4_EXT, IP4_DST, 9.9, RULE_NEW }

    ,{ 0, 310, 2110, IP4_SRC, IP4_EXT, 0.0, RULE_ORIG }
    ,{ 1, 310, 2110, IP4_SRC, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 310, 2110, IP4_SRC, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 310, 2110, IP4_SRC, IP4_EXT, 1.0, RULE_ORIG }
    ,{ 4, 310, 2110, IP4_SRC, IP4_EXT, 1.9, RULE_NEW }
    ,{ 5, 310, 2110, IP4_SRC, IP4_EXT, 2.0, RULE_NEW }
    ,{ 6, 310, 2110, IP4_SRC, IP4_EXT, 9.9, RULE_NEW }

    ,{ 0, 410, 1110, IP6_EXT, IP6_DST, 0.0, RULE_ORIG }
    ,{ 1, 410, 1110, IP6_SRC, IP6_DST, 0.1, RULE_ORIG }
    ,{ 2, 410, 1110, IP6_SRC, IP6_DST, 0.2, RULE_ORIG }
    ,{ 3, 410, 1110, IP6_EXT, IP6_DST, 1.0, RULE_ORIG }
    ,{ 4, 410, 1110, IP6_EXT, IP6_DST, 1.9, RULE_NEW }
    ,{ 5, 410, 1110, IP6_EXT, IP6_DST, 2.0, RULE_NEW }
    ,{ 6, 410, 1110, IP6_EXT, IP6_DST, 9.9, RULE_NEW }

    ,{ 0, 410, 2110, IP6_SRC, IP6_EXT, 0.0, RULE_ORIG }
    ,{ 1, 410, 2110, IP6_SRC, IP6_DST, 0.1, RULE_ORIG }
    ,{ 2, 410, 2110, IP6_SRC, IP6_DST, 0.2, RULE_ORIG }
    ,{ 3, 410, 2110, IP6_SRC, IP6_EXT, 1.0, RULE_ORIG }
    ,{ 4, 410, 2110, IP6_SRC, IP6_EXT, 1.9, RULE_NEW }
    ,{ 5, 410, 2110, IP6_SRC, IP6_EXT, 2.0, RULE_NEW }
    ,{ 6, 410, 2110, IP6_SRC, IP6_EXT, 9.9, RULE_NEW }
};

#define NUM_EVENTS (sizeof(evData)/sizeof(evData[0]))

//---------------------------------------------------------------

#if 0
static void PrintTests()
{
    unsigned i;
    EventData* prev = nullptr;

    for ( i = 0; i < NUM_EVENTS; i++ )
    {
        EventData* e = evData + i;

        const char* act = (e->expect == RULE_ORIG) ? "-" : "+";
        const char* net = "";

        if ( !prev || prev->gid != e->gid || prev->sid != e->sid )
        {
            printf("\n%d,%d:", e->gid, e->sid);
        }
        if ( strcmp(e->sip, IP4_SRC) )
            net = "s";
        else if ( strcmp(e->dip, IP4_DST) )
            net = "d";

        printf(" %s%.1f%s", act, e->now, net);
        prev = e;
    }
    exit(0);
}
#endif

//---------------------------------------------------------------

static void Init(const SnortConfig* sc, unsigned cap)
{
    // FIXIT-L must set policies because they may have been invalidated
    // by prior tests with transient SnortConfigs.  better to fix sfrf
    // to use a SnortConfig parameter or make this a make check test
    // with a separate executable.
    set_default_policy(sc);
    rfc = RateFilter_ConfigNew();
    rfc->memcap = cap;

    SFRF_Alloc(rfc->memcap);

    for ( unsigned i = 0; i < NUM_NODES; i++ )
    {
        RateData* p = rfData + i;
        tSFRFConfigNode cfg;

        cfg.gid = p->gid;
        cfg.sid = p->sid;
        cfg.tracking = p->track;
        cfg.count = p->count;
        cfg.seconds = p->seconds;
        cfg.newAction = (IpsAction::Type)RULE_NEW;
        cfg.timeout = p->timeout;
        cfg.applyTo = p->ip ? sfip_var_from_string(p->ip, "sfrf_test") : nullptr;

        p->create = SFRF_ConfigAdd(nullptr, rfc, &cfg);
    }
}

static void Term()
{
    SFRF_Delete();
    RateFilter_ConfigFree(rfc);
    rfc = nullptr;
}

static int SetupCheck(int i)
{
    const RateData* p = rfData + i;
    if ( p->expect == p->create )
        return 1;
    printf("setup %d: exp %d, got %d\n", i, p->expect, p->create);
    return 0;
}

static int EventTest(const EventData* p)
{
    // now is a float to clarify the impact of
    // just using truncated seconds on thresholds
    long curtime = (long)p->now;
    int status;

    // this is the only acceptable public value for op
    SFRF_COUNT_OPERATION op = SFRF_COUNT_INCREMENT;

    SfIp sip, dip;
    sip.set(p->sip);
    dip.set(p->dip);

    status = SFRF_TestThreshold(rfc, p->gid, p->sid, get_network_policy()->policy_id,
        &sip, &dip, curtime, op);

    if ( status >= IpsAction::get_max_types() )
        status -= IpsAction::get_max_types();

    return status;
}

static int EventCheck(int i)
{
    const EventData* p = evData + i;
    int status = EventTest(p);

    if ( p->expect == status )
        return 1;

    printf("event[%u](%u,%u): exp %d, got %d\n",
        p->seq, p->gid, p->sid, p->expect, status);
    return 0;
}

static int CapCheck(int i)
{
    const EventData* p = evData + i;
    int status = EventTest(p);

    if ( RULE_ORIG == status )
        return 1;

    printf("cap[%u](%u,%u): exp %d, got %d\n",
        p->seq, p->gid, p->sid, RULE_ORIG, status);
    return 0;
}

//---------------------------------------------------------------

TEST_CASE("sfrf default memcap", "[sfrf]")
{
    SnortConfig sc;
    Init(&sc, MEM_DEFAULT);

    SECTION("setup")
    {
        for ( unsigned i = 0; i < NUM_NODES; ++i )
            CHECK(SetupCheck(i) == 1);
    }
    SECTION("event")
    {
        for ( unsigned i = 0; i < NUM_NODES; ++i )
            CHECK(EventCheck(i) == 1);
    }
    Term();
}

TEST_CASE("sfrf minimum memcap", "[sfrf]")
{
    SnortConfig sc;
    Init(&sc, MEM_MINIMUM);

    SECTION("setup")
    {
        for ( unsigned i = 0; i < NUM_NODES; ++i )
            CHECK(SetupCheck(i) == 1);
    }
    SECTION("cap")
    {
        for ( unsigned i = 0; i < NUM_NODES; ++i )
            CHECK(CapCheck(i) == 1);
    }
    Term();
}

//---------------------------------------------------------------
// a rate_filter with seconds = 0 on session setup is not a rate but a gauge: it counts the
// connections that are currently up.  that only stays bounded because the flow that took a
// count gives it back when it goes away, so the pairing is the property worth testing.

#define GAUGE_COUNT   2
#define GAUGE_TIMEOUT 5

static int GaugeUp(RateFilterConfig* cf, time_t now, SFRFGaugeKeys& gauges)
{
    SfIp sip, dip;
    sip.set(IP4_SRC);
    dip.set(IP4_DST);

    int status = SFRF_TestThreshold(cf, GID_SESSION, SESSION_EVENT_SETUP,
        get_network_policy()->policy_id, &sip, &dip, now, SFRF_COUNT_INCREMENT, &gauges);

    // the first trip is returned offset, to say "log this one too"
    if ( status >= IpsAction::get_max_types() )
        status -= IpsAction::get_max_types();

    return status;
}

TEST_CASE("sfrf connect gauge pairs", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    rfc = RateFilter_ConfigNew();
    rfc->memcap = MEM_DEFAULT;
    SFRF_Alloc(rfc->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = GAUGE_COUNT;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;

    // a zero timeout never rereads the count once the filter is on, which would hide
    // whether the decrements landed at all
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, rfc, &cfg) == 0);

    SFRFGaugeKeys held[GAUGE_COUNT + 1];

    // connections up to the limit are at it, not over it
    for ( int i = 0; i < GAUGE_COUNT; ++i )
        CHECK(GaugeUp(rfc, 0, held[i]) == RULE_ORIG);

    // one more is over it
    CHECK(GaugeUp(rfc, 0, held[GAUGE_COUNT]) == RULE_NEW);

    // now every one of those connections ends, each giving back what it took
    for ( int i = 0; i <= GAUGE_COUNT; ++i )
        SFRF_ReleaseGauges(held[i]);

    // past the revert timeout the gauge is read again, so this is the whole point: with the
    // counts given back this connection is the first one and passes.  had they not been,
    // the gauge would still read three and every later connection would be filtered forever
    SFRFGaugeKeys next;
    CHECK(GaugeUp(rfc, GAUGE_TIMEOUT * 2, next) == RULE_ORIG);

    Term();
}

TEST_CASE("sfrf setup rate is not a connect gauge", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    rfc = RateFilter_ConfigNew();
    rfc->memcap = MEM_DEFAULT;
    SFRF_Alloc(rfc->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = 1;
    cfg.seconds = 60;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, rfc, &cfg) == 0);

    SfIp sip, dip;
    sip.set(IP4_SRC);
    dip.set(IP4_DST);

    SFRFGaugeKeys gauges;
    int status = SFRF_TestThreshold(rfc, GID_SESSION, SESSION_EVENT_SETUP,
        get_network_policy()->policy_id, &sip, &dip, 0, SFRF_COUNT_INCREMENT, &gauges);

    CHECK(gauges.empty());
    CHECK(status == RULE_ORIG);

    status = SFRF_TestThreshold(rfc, GID_SESSION, SESSION_EVENT_SETUP,
        get_network_policy()->policy_id, &sip, &dip, 0, SFRF_COUNT_INCREMENT, &gauges);
    CHECK(gauges.empty());
    CHECK(status >= 0);

    // a session that took nothing gives nothing back, so a rate cannot be un-tripped by
    // the sessions that raised it ending
    SFRF_ReleaseGauges(gauges);

    status = SFRF_TestThreshold(rfc, GID_SESSION, SESSION_EVENT_SETUP,
        get_network_policy()->policy_id, &sip, &dip, 1, SFRF_COUNT_INCREMENT, &gauges);
    CHECK(status >= 0);

    Term();
}

TEST_CASE("sfrf reports connect gauge ownership", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    rfc = RateFilter_ConfigNew();
    rfc->memcap = MEM_DEFAULT;
    SFRF_Alloc(rfc->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = GAUGE_COUNT;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, rfc, &cfg) == 0);

    SfIp sip, dip;
    sip.set(IP4_SRC);
    dip.set(IP4_DST);

    SFRFGaugeKeys gauges;
    SFRF_TestThreshold(rfc, GID_SESSION, SESSION_EVENT_SETUP,
        get_network_policy()->policy_id, &sip, &dip, 0, SFRF_COUNT_INCREMENT, &gauges);
    CHECK(gauges.size() == 1);
    CHECK(gauges[0].policyId == get_network_policy()->policy_id);

    Term();
}

TEST_CASE("sfrf connect gauge counts outlive the config that took them", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    RateFilterConfig* first = RateFilter_ConfigNew();
    first->memcap = MEM_DEFAULT;
    SFRF_Alloc(first->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = GAUGE_COUNT;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, first, &cfg) == 0);

    SFRFGaugeKeys held[GAUGE_COUNT];

    for ( int i = 0; i < GAUGE_COUNT; ++i )
        CHECK(GaugeUp(first, 0, held[i]) == RULE_ORIG);

    RateFilterConfig* second = RateFilter_ConfigNew();
    second->memcap = MEM_DEFAULT;
    CHECK(SFRF_ConfigAdd(nullptr, second, &cfg) == 0);

    SFRFGaugeKeys next;
    CHECK(GaugeUp(second, 0, next) == RULE_NEW);

    SFRF_Delete();
    RateFilter_ConfigFree(first);
    RateFilter_ConfigFree(second);
}

TEST_CASE("sfrf connect gauge counts are stranded when a reload reorders the filters",
    "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = GAUGE_COUNT;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    tSFRFConfigNode other = cfg;
    other.sid = SESSION_EVENT_CLEAR;

    RateFilterConfig* first = RateFilter_ConfigNew();
    first->memcap = MEM_DEFAULT;
    SFRF_Alloc(first->memcap);

    CHECK(SFRF_ConfigAdd(nullptr, first, &other) == 0);
    CHECK(SFRF_ConfigAdd(nullptr, first, &cfg) == 0);

    SFRFGaugeKeys held[GAUGE_COUNT];

    for ( int i = 0; i < GAUGE_COUNT; ++i )
        CHECK(GaugeUp(first, 0, held[i]) == RULE_ORIG);

    RateFilterConfig* second = RateFilter_ConfigNew();
    second->memcap = MEM_DEFAULT;

    CHECK(SFRF_ConfigAdd(nullptr, second, &cfg) == 0);
    CHECK(SFRF_ConfigAdd(nullptr, second, &other) == 0);

    SFRFGaugeKeys taken[GAUGE_COUNT];

    for ( int i = 0; i < GAUGE_COUNT; ++i )
        CHECK(GaugeUp(second, 0, taken[i]) == RULE_ORIG);

    // the connections counted under the old order end.  each gives its count back to the
    // node that took it, so the gauge the new order is using is left where it was; taking
    // the keys from the current configuration instead would credit it with counts it never
    // gave out and let it over shoot the limit
    for ( int i = 0; i < GAUGE_COUNT; ++i )
        SFRF_ReleaseGauges(held[i]);

    SFRFGaugeKeys next;
    CHECK(GaugeUp(second, 0, next) == RULE_NEW);

    SFRF_Delete();
    RateFilter_ConfigFree(first);
    RateFilter_ConfigFree(second);
}

TEST_CASE("sfrf connect gauge counts are given back after the gauge is removed", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = GAUGE_COUNT;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    tSFRFConfigNode other = cfg;
    other.sid = SESSION_EVENT_CLEAR;

    RateFilterConfig* first = RateFilter_ConfigNew();
    first->memcap = MEM_DEFAULT;
    SFRF_Alloc(first->memcap);

    CHECK(SFRF_ConfigAdd(nullptr, first, &other) == 0);
    CHECK(SFRF_ConfigAdd(nullptr, first, &cfg) == 0);

    SFRFGaugeKeys held[GAUGE_COUNT];

    for ( int i = 0; i < GAUGE_COUNT; ++i )
        CHECK(GaugeUp(first, 0, held[i]) == RULE_ORIG);

    // a reload drops the gauge, and the connections that took counts under it end with no
    // gauge configured at all.  the counts still go back, so a later configuration that is
    // given the same identity starts from zero rather than inheriting them
    for ( int i = 0; i < GAUGE_COUNT; ++i )
        SFRF_ReleaseGauges(held[i]);

    RateFilterConfig* third = RateFilter_ConfigNew();
    third->memcap = MEM_DEFAULT;

    CHECK(SFRF_ConfigAdd(nullptr, third, &other) == 0);
    CHECK(SFRF_ConfigAdd(nullptr, third, &cfg) == 0);

    SFRFGaugeKeys taken[GAUGE_COUNT];

    for ( int i = 0; i < GAUGE_COUNT; ++i )
        CHECK(GaugeUp(third, 0, taken[i]) == RULE_ORIG);

    SFRF_Delete();
    RateFilter_ConfigFree(first);
    RateFilter_ConfigFree(third);
}

#define MANY_GAUGES 5

TEST_CASE("sfrf every overlapping connect gauge is enforced", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    RateFilterConfig* cf = RateFilter_ConfigNew();
    cf->memcap = MEM_DEFAULT;
    SFRF_Alloc(cf->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    // the last one configured is the one with something to say, so it is only heard if every
    // gauge the session matches is counted, however many of them there are
    for ( int i = 0; i < MANY_GAUGES; ++i )
    {
        cfg.count = ( i == MANY_GAUGES - 1 ) ? 1 : MANY_GAUGES * 2;
        CHECK(SFRF_ConfigAdd(nullptr, cf, &cfg) == 0);
    }

    SFRFGaugeKeys first, second;

    CHECK(GaugeUp(cf, 0, first) == RULE_ORIG);
    CHECK(first.size() == MANY_GAUGES);

    CHECK(GaugeUp(cf, 0, second) == RULE_NEW);
    CHECK(second.size() == MANY_GAUGES);

    SFRF_ReleaseGauges(first);
    SFRF_ReleaseGauges(second);

    SFRFGaugeKeys next;
    CHECK(GaugeUp(cf, GAUGE_TIMEOUT * 2, next) == RULE_ORIG);

    SFRF_Delete();
    RateFilter_ConfigFree(cf);
}

static int GaugeUpAt(RateFilterConfig* cf, time_t now, SFRFGaugeKeys& gauges,
    const char* src, const char* dst)
{
    SfIp sip, dip;
    sip.set(src);
    dip.set(dst);

    int status = SFRF_TestThreshold(cf, GID_SESSION, SESSION_EVENT_SETUP,
        get_network_policy()->policy_id, &sip, &dip, now, SFRF_COUNT_INCREMENT, &gauges);

    if ( status >= IpsAction::get_max_types() )
        status -= IpsAction::get_max_types();

    return status;
}

// enough addresses to fill a table this small many times over
#define GAUGE_SPRAY 200

TEST_CASE("sfrf restarts a connect gauge when its node is recovered", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    RateFilterConfig* cf = RateFilter_ConfigNew();

    // room for a handful of nodes, so the spray below has to recover the node holding the
    // gauge below it
    cf->memcap = 2048;
    SFRF_Alloc(cf->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = 1;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, cf, &cfg) == 0);

    SFRFGaugeKeys held;
    CHECK(GaugeUpAt(cf, 0, held, IP4_SRC, IP4_DST) == RULE_ORIG);
    CHECK(held.size() == 1);

    const PegCount nomem = rate_filter_stats.xhash_nomem_peg;
    const PegCount recoveries = rate_filter_stats.recoveries;

    // one node per address, none of them given back, oldest first
    for ( unsigned i = 0; i < GAUGE_SPRAY; ++i )
    {
        char dst[24];
        snprintf(dst, sizeof(dst), "10.0.%u.%u", i / 256, i % 256);

        SFRFGaugeKeys spray;
        GaugeUpAt(cf, 0, spray, IP4_SRC, dst);
    }

    // every node can be recovered, so the spray never runs the table out
    CHECK(rate_filter_stats.xhash_nomem_peg == nomem);

    // a table too small for what is being tracked is visible as a peg rather than only as
    // gauges that read low
    CHECK(rate_filter_stats.recoveries > recoveries);

    // the held address no longer has a node, so its count starts over and the next
    // connection reads as the first
    SFRFGaugeKeys second;
    CHECK(GaugeUpAt(cf, 0, second, IP4_SRC, IP4_DST) == RULE_ORIG);

    // the count owed on the recovered node went with it, so giving it back must not come off
    // the node that took its place and must not wrap the count of the session that is up
    SFRF_ReleaseGauges(held);
    SFRF_ReleaseGauges(held);

    SFRFGaugeKeys third;
    CHECK(GaugeUpAt(cf, 0, third, IP4_SRC, IP4_DST) == RULE_NEW);

    // the keys taken against the node that is there now still give their counts back, so the
    // gauge reverts once the revert timeout is up
    SFRF_ReleaseGauges(second);
    SFRF_ReleaseGauges(third);

    SFRFGaugeKeys fourth;
    CHECK(GaugeUpAt(cf, GAUGE_TIMEOUT + 1, fourth, IP4_SRC, IP4_DST) == RULE_ORIG);
    SFRF_ReleaseGauges(fourth);

    SFRF_Delete();
    RateFilter_ConfigFree(cf);
}

TEST_CASE("sfrf does not pass a recycled node's filter state to another address", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    RateFilterConfig* cf = RateFilter_ConfigNew();
    cf->memcap = 2048;
    SFRF_Alloc(cf->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_DST;
    cfg.count = 1;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, cf, &cfg) == 0);

    // every address trips its gauge and then gives the counts back, so the table fills with
    // nodes that are on but owe nothing, and those are what a later address recycles
    bool clean = true;

    for ( unsigned i = 0; i < GAUGE_SPRAY; ++i )
    {
        char dst[24];
        snprintf(dst, sizeof(dst), "10.1.%u.%u", i / 256, i % 256);

        SFRFGaugeKeys up, over;

        // the first connection to an address never seen before is under the gauge, whatever
        // the node it was given was last used for
        if ( GaugeUpAt(cf, 1, up, IP4_SRC, dst) != RULE_ORIG )
            clean = false;

        GaugeUpAt(cf, 1, over, IP4_SRC, dst);

        SFRF_ReleaseGauges(up);
        SFRF_ReleaseGauges(over);
    }

    CHECK(clean);

    SFRF_Delete();
    RateFilter_ConfigFree(cf);
}

TEST_CASE("sfrf a by_rule connect gauge is shared and given back", "[sfrf]")
{
    SnortConfig sc;
    set_default_policy(&sc);

    RateFilterConfig* cf = RateFilter_ConfigNew();
    cf->memcap = MEM_DEFAULT;
    SFRF_Alloc(cf->memcap);

    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = TRK_RUL;
    cfg.count = 1;
    cfg.seconds = 0;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(SFRF_ConfigAdd(nullptr, cf, &cfg) == 0);

    // by_rule counts against no address at all, so sessions between unrelated hosts share
    // the one count and the second of them is over the gauge
    SFRFGaugeKeys first, second;

    CHECK(GaugeUpAt(cf, 0, first, IP4_SRC, IP4_DST) == RULE_ORIG);
    CHECK(first.size() == 1);

    CHECK(GaugeUpAt(cf, 0, second, IP6_SRC, IP6_DST) == RULE_NEW);
    CHECK(second.size() == 1);

    // each session kept the cleared key it was counted under rather than its own addresses,
    // so both releases land on the shared node
    SFRF_ReleaseGauges(first);
    SFRF_ReleaseGauges(second);

    SFRFGaugeKeys next;
    CHECK(GaugeUpAt(cf, GAUGE_TIMEOUT * 2, next, IP6_SRC, IP4_DST) == RULE_ORIG);

    SFRF_Delete();
    RateFilter_ConfigFree(cf);
}
