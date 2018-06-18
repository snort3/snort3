//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "parser/parse_ip.h"
#include "sfip/sf_ip.h"

#include "rate_filter.h"
#include "sfrf.h"

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

#define MEM_DEFAULT (1024*1024)  // default if not re"config"ed
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
#ifndef SFRF_OVER_RATE
    { 0, 200, 1110, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1110, IP4_SRC, IP4_DST, 0.1, RULE_NEW }
    ,{ 2, 200, 1110, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 1110, IP4_SRC, IP4_DST, 1.0, RULE_NEW }
    ,{ 4, 200, 1110, IP4_SRC, IP4_DST, 9.9, RULE_NEW }

    ,{ 0, 200, 1111, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1111, IP4_EXT, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 200, 1111, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 1111, IP4_SRC, IP4_DST, 1.0, RULE_ORIG }
    ,{ 4, 200, 1111, IP4_SRC, IP4_DST, 1.1, RULE_NEW }
    ,{ 5, 200, 1111, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 6, 200, 1111, IP4_SRC, IP4_DST, 2.0, RULE_ORIG }
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
    ,{ 10, 200, 1121, IP4_SRC, IP4_DST, 2.0, RULE_ORIG }
    ,{ 11, 200, 1121, IP4_SRC, IP4_DST, 2.1, RULE_NEW }
    ,{ 12, 200, 1121, IP4_SRC, IP4_DST, 3.0, RULE_NEW }
    ,{ 13, 200, 1121, IP4_SRC, IP4_DST, 4.0, RULE_ORIG }
    ,{ 14, 200, 1121, IP4_SRC, IP4_DST, 5.0, RULE_NEW }
    ,{ 15, 200, 1121, IP4_SRC, IP4_DST, 5.1, RULE_NEW }
    ,{ 16, 200, 1121, IP4_SRC, IP4_DST, 6.0, RULE_ORIG }
    ,{ 17, 200, 1121, IP4_SRC, IP4_DST, 8.0, RULE_ORIG }
    ,{ 18, 200, 1121, IP4_SRC, IP4_DST,10.0, RULE_ORIG }

    ,{ 0, 200, 1311, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 1311, IP4_SRC, IP4_DST, 0.1, RULE_ORIG }
    ,{ 2, 200, 1311, IP4_SRC, IP4_DST, 0.2, RULE_ORIG }
    ,{ 3, 200, 1311, IP4_SRC, IP4_DST, 0.3, RULE_NEW }
    ,{ 4, 200, 1311, IP4_SRC, IP4_DST, 0.4, RULE_NEW }
    ,{ 5, 200, 1311, IP4_SRC, IP4_DST, 1.0, RULE_ORIG }
    ,{ 6, 200, 1311, IP4_SRC, IP4_DST, 1.1, RULE_ORIG }
    ,{ 7, 200, 1311, IP4_SRC, IP4_DST, 1.2, RULE_ORIG }
    ,{ 8, 200, 1311, IP4_SRC, IP4_DST, 1.3, RULE_NEW }
    ,{ 9, 200, 1311, IP4_SRC, IP4_DST, 1.4, RULE_NEW }
    ,{ 10, 200, 1311, IP4_SRC, IP4_DST, 2.0, RULE_ORIG }
    ,{ 11, 200, 1311, IP4_SRC, IP4_DST, 2.1, RULE_ORIG }
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
    ,{ 10, 200, 1321, IP4_SRC, IP4_DST, 2.0, RULE_ORIG }
    ,{ 11, 200, 1321, IP4_SRC, IP4_DST, 2.1, RULE_ORIG }
    ,{ 12, 200, 1321, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }
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
    ,{ 10, 200, 1312, IP4_SRC, IP4_DST, 2.0, RULE_ORIG }
    ,{ 11, 200, 1312, IP4_SRC, IP4_DST, 2.1, RULE_ORIG }
    ,{ 12, 200, 1312, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }
    ,{ 13, 200, 1312, IP4_SRC, IP4_DST, 4.0, RULE_ORIG }
    ,{ 14, 200, 1312, IP4_SRC, IP4_DST, 5.0, RULE_ORIG }

    ,{ 0, 200, 2111, IP4_SRC, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 2111, IP4_SRC, IP4_EXT, 0.1, RULE_ORIG }
    ,{ 2, 200, 2111, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 2111, IP4_SRC, IP4_DST, 1.0, RULE_ORIG }
    ,{ 4, 200, 2111, IP4_SRC, IP4_EXT, 1.1, RULE_ORIG }
    ,{ 5, 200, 2111, IP4_SRC, IP4_DST, 1.2, RULE_NEW }
    ,{ 6, 200, 2111, IP4_SRC, IP4_DST, 2.0, RULE_ORIG }
    ,{ 7, 200, 2111, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }

    ,{ 0, 200, 3111, IP4_EXT, IP4_DST, 0.0, RULE_ORIG }
    ,{ 1, 200, 3111, IP4_SRC, IP4_EXT, 0.1, RULE_NEW }
    ,{ 2, 200, 3111, IP4_SRC, IP4_DST, 0.2, RULE_NEW }
    ,{ 3, 200, 3111, IP4_EXT, IP4_DST, 1.0, RULE_ORIG }
    ,{ 4, 200, 3111, IP4_EXT, IP4_DST, 1.1, RULE_NEW }
    ,{ 5, 200, 3111, IP4_SRC, IP4_EXT, 1.2, RULE_NEW }
    ,{ 6, 200, 3111, IP4_SRC, IP4_EXT, 2.0, RULE_ORIG }
    ,{ 7, 200, 3111, IP4_SRC, IP4_DST, 3.0, RULE_ORIG }

    ,{ 0, 210, 3311, IP4_SRC, IP4_DST,  0.0, RULE_ORIG }
    ,{ 1, 210, 3311, IP4_SRC, IP4_DST,  0.1, RULE_ORIG }
    ,{ 2, 210, 3311, IP4_SRC, IP4_DST,  0.2, RULE_ORIG }
    ,{ 3, 210, 3311, IP4_SRC, IP4_DST,  0.3, RULE_NEW }
    ,{ 4, 210, 3311, IP4_SRC, IP4_DST,  0.4, RULE_NEW }
    ,{ 5, 210, 3311, IP4_SRC, IP4_DST,  1.0, RULE_ORIG }
    ,{ 6, 210, 3311, IP4_SRC, IP4_DST,  1.1, RULE_ORIG }
    ,{ 7, 210, 3311, IP4_SRC, IP4_DST,  1.2, RULE_ORIG }
    ,{ 8, 210, 3311, IP4_SRC, IP4_DST,  1.3, RULE_NEW }
    ,{ 9, 210, 3311, IP4_SRC, IP4_DST,  1.4, RULE_NEW }
    ,{ 10, 210, 3311, IP4_SRC, IP4_DST,  2.0, RULE_ORIG }
    ,{ 11, 210, 3311, IP4_SRC, IP4_DST,  2.1, RULE_ORIG }
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
    ,{ 5, 210, 3351, IP4_SRC, IP4_DST,  5.0, RULE_ORIG }
    ,{ 6, 210, 3351, IP4_SRC, IP4_DST,  5.1, RULE_ORIG }
    ,{ 7, 210, 3351, IP4_SRC, IP4_DST,  5.2, RULE_ORIG }
    ,{ 8, 210, 3351, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 9, 210, 3351, IP4_SRC, IP4_DST,  5.4, RULE_NEW }
    ,{ 10, 210, 3351, IP4_SRC, IP4_DST, 10.0, RULE_ORIG }
    ,{ 11, 210, 3351, IP4_SRC, IP4_DST, 10.1, RULE_ORIG }
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
    ,{ 5, 210, 3355, IP4_SRC, IP4_DST,  5.0, RULE_ORIG }
    ,{ 6, 210, 3355, IP4_SRC, IP4_DST,  5.1, RULE_ORIG }
    ,{ 7, 210, 3355, IP4_SRC, IP4_DST,  5.2, RULE_ORIG }
    ,{ 8, 210, 3355, IP4_SRC, IP4_DST,  5.3, RULE_NEW }
    ,{ 9, 210, 3355, IP4_SRC, IP4_DST,  5.4, RULE_NEW }
    ,{ 10, 210, 3355, IP4_SRC, IP4_DST, 10.0, RULE_ORIG }
    ,{ 11, 210, 3355, IP4_SRC, IP4_DST, 10.1, RULE_ORIG }
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
    ,{ 10, 210, 3359, IP4_SRC, IP4_DST, 10.0, RULE_ORIG }
    ,{ 11, 210, 3359, IP4_SRC, IP4_DST, 10.1, RULE_ORIG }
    ,{ 12, 210, 3359, IP4_SRC, IP4_DST, 15.0, RULE_ORIG }
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
    ,{ 5, 210, 3391, IP4_SRC, IP4_DST,  9.0, RULE_ORIG }
    ,{ 6, 210, 3391, IP4_SRC, IP4_DST,  9.1, RULE_ORIG }
    ,{ 7, 210, 3391, IP4_SRC, IP4_DST,  9.2, RULE_ORIG }
    ,{ 8, 210, 3391, IP4_SRC, IP4_DST,  9.3, RULE_NEW }
    ,{ 9, 210, 3391, IP4_SRC, IP4_DST,  9.4, RULE_NEW }
    ,{ 10, 210, 3391, IP4_SRC, IP4_DST, 18.0, RULE_ORIG }
    ,{ 11, 210, 3391, IP4_SRC, IP4_DST, 18.1, RULE_ORIG }
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
    ,{ 5, 210, 3395, IP4_SRC, IP4_DST,  9.0, RULE_ORIG }
    ,{ 6, 210, 3395, IP4_SRC, IP4_DST,  9.1, RULE_ORIG }
    ,{ 7, 210, 3395, IP4_SRC, IP4_DST,  9.2, RULE_ORIG }
    ,{ 8, 210, 3395, IP4_SRC, IP4_DST,  9.3, RULE_NEW }
    ,{ 9, 210, 3395, IP4_SRC, IP4_DST,  9.4, RULE_NEW }
    ,{ 10, 210, 3395, IP4_SRC, IP4_DST, 18.0, RULE_ORIG }
    ,{ 11, 210, 3395, IP4_SRC, IP4_DST, 18.1, RULE_ORIG }
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
    ,{ 5, 210, 3399, IP4_SRC, IP4_DST,  9.0, RULE_ORIG }
    ,{ 6, 210, 3399, IP4_SRC, IP4_DST,  9.1, RULE_ORIG }
    ,{ 7, 210, 3399, IP4_SRC, IP4_DST,  9.2, RULE_ORIG }
    ,{ 8, 210, 3399, IP4_SRC, IP4_DST,  9.3, RULE_NEW }
    ,{ 9, 210, 3399, IP4_SRC, IP4_DST,  9.4, RULE_NEW }
    ,{ 10, 210, 3399, IP4_SRC, IP4_DST, 18.0, RULE_ORIG }
    ,{ 11, 210, 3399, IP4_SRC, IP4_DST, 18.1, RULE_ORIG }
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
#else
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
#endif
};

#define NUM_EVENTS (sizeof(evData)/sizeof(evData[0]))

//---------------------------------------------------------------

#if 0
static void PrintTests()
{
    unsigned i;
    EventData* prev = NULL;

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

static void Init(unsigned cap)
{
    // FIXIT-L must set policies because they may have been invalidated
    // by prior tests with transient SnortConfigs.  better to fix sfrf
    // to use a SnortConfig parameter or make this a make check test
    // with a separate executable.
    set_default_policy();
    rfc = RateFilter_ConfigNew();
    rfc->memcap = cap;

    for ( unsigned i = 0; i < NUM_NODES; i++ )
    {
        RateData* p = rfData + i;
        tSFRFConfigNode cfg;

        cfg.gid = p->gid;
        cfg.sid = p->sid;
        cfg.tracking = p->track;
        cfg.count = p->count;
        cfg.seconds = p->seconds;
        cfg.newAction = (snort::Actions::Type)RULE_NEW;
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
    RateData* p = rfData + i;
    if ( p->expect == p->create )
        return 1;
    printf("setup %d: exp %d, got %d\n", i, p->expect, p->create);
    return 0;
}

static int EventTest(EventData* p)
{
    // now is a float to clarify the impact of
    // just using truncated seconds on thresholds
    long curtime = (long)p->now;
    int status;

    // this is the only acceptable public value for op
    SFRF_COUNT_OPERATION op = SFRF_COUNT_INCREMENT;

    snort::SfIp sip, dip;
    sip.set(p->sip);
    dip.set(p->dip);

    status = SFRF_TestThreshold(
        rfc, p->gid, p->sid, &sip, &dip, curtime, op);

    if ( status >= snort::Actions::MAX )
        status -= snort::Actions::MAX;

    return status;
}

static int EventCheck(int i)
{
    EventData* p = evData + i;
    int status = EventTest(p);

    if ( p->expect == status )
        return 1;

    printf("event[%u](%u,%u): exp %d, got %d\n",
        p->seq, p->gid, p->sid, p->expect, status);
    return 0;
}

static int CapCheck(int i)
{
    EventData* p = evData + i;
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
    Init(MEM_DEFAULT);

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
    Init(MEM_MINIMUM);

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

