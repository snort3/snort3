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
// sfthd_test.cc author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"
#include "hash/xhash.h"
#include "parser/parse_ip.h"
#include "sfip/sf_ip.h"

#include "sfthd.h"

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
#define IP6_NONE "::"

#define IP4_SET1 "[1.2.3.4,1.2.3.5]"
#define IP4_SET2 "[1.2.0.0/16,![1.2.3.4,1.2.3.5]]"

#define LOG_OK  0              // event is loggable
#define LOG_NO  1              // event was filtered
#define LOG_SU (-1)              // event was suppressed

#define MEM_DEFAULT (1024*1024)  // default if not re"config"ed
#define MEM_MINIMUM 0          // forces use of minimum

// priority should not be exposed as implemented ...
// you can only have one non-suppress thd and it is forced to a lower priority
// than suppress. although you can have multiple suppress thds, they are all
// forced to maximum priority so in the end priority is only used internally
// to order the list of thds per gid,sid and the order will always be:
// 1st suppress, 2nd suppress, ..., last suppress, non-suppress (if present).
#define PRIORITY 0

typedef struct
{
    unsigned int gid;
    unsigned int sid;
    int tracking;  // THD_TRK_ SRC | DST
    int type;      // THD_TYPE_ LIMIT | THRESHOLD | BOTH | SUPPRESS
    int count;
    int seconds;
    const char* ip;
    int expect;
    int create;
    THD_NODE* rule;
} ThreshData;

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

static THD_STRUCT* pThd = nullptr;
static ThresholdObjects* pThdObjs = nullptr;
static XHash* dThd = nullptr;

//---------------------------------------------------------------

static ThreshData thData[] =
{
    // gid, sid checks
    { 0,   1, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, -1, 0, nullptr }
    ,{ 1,   0, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 1,   0, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0, nullptr }
    ,{ 2,   0, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 8129,   1, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, -1, 0, nullptr }
    ,{ 1,   1, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 1,   1, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0, nullptr }

    // tracking checks
    ,{ 100, 100, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100, 100, THD_TRK_SRC, THD_TYPE_LIMIT,       1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0,
       nullptr }
    ,{ 100, 101, THD_TRK_SRC, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100, 101, THD_TRK_DST, THD_TYPE_LIMIT,       1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0,
       nullptr }

    // type checks (dup gid,sid allowed with suppress)
    ,{ 100, 110, THD_TRK_SRC, THD_TYPE_THRESHOLD,   1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100, 110, THD_TRK_SRC, THD_TYPE_THRESHOLD,   1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0,
       nullptr }
    ,{ 100, 120, THD_TRK_SRC, THD_TYPE_BOTH,        1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100, 120, THD_TRK_SRC, THD_TYPE_BOTH,        1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0,
       nullptr }
    ,{ 100, 130, THD_TRK_SRC, THD_TYPE_SUPPRESS,    1,  1, IP4_SRC, 0, 0, nullptr }
    ,{ 100, 130, THD_TRK_SRC, THD_TYPE_SUPPRESS,    1,  1, IP4_SRC, 0, 0, nullptr }
    ,{ 100, 140, THD_TRK_SRC, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100, 140, THD_TRK_SRC, THD_TYPE_LIMIT,       1,  1, IP_ANY, THD_TOO_MANY_THDOBJ, 0,
       nullptr }
    ,{ 100, 110, THD_TRK_SRC, THD_TYPE_SUPPRESS,    1,  1, IP4_SRC, 0, 0, nullptr }
    ,{ 100, 120, THD_TRK_SRC, THD_TYPE_SUPPRESS,    1,  1, IP4_SRC, 0, 0, nullptr }
    ,{ 100, 130, THD_TRK_SRC, THD_TYPE_SUPPRESS,    1,  1, IP4_SRC, 0, 0, nullptr }
    ,{ 100, 140, THD_TRK_SRC, THD_TYPE_SUPPRESS,    1,  1, IP4_SRC, 0, 0, nullptr }

    // count/seconds / ip checks
    // count/seconds = 0 means fire after 1st event
    ,{ 120, 100, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_DST, 0, 0, nullptr }
    ,{ 120, 101, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  1, IP4_DST, 0, 0, nullptr }
    ,{ 120, 102, THD_TRK_DST, THD_TYPE_SUPPRESS,    1,  0, IP4_DST, 0, 0, nullptr }
    // count/seconds < 0 means fire every time
    ,{ 120, 110, THD_TRK_SRC, THD_TYPE_SUPPRESS,   -1, -1, IP4_SRC, 0, 0, nullptr }
    // code assumes a valid SfIp* so can't test this
    //,{ 120, 120, THD_TRK_SRC, THD_TYPE_SUPPRESS, 0, 0, "", 0, 0, nullptr }
    ,{ 120, 130, THD_TRK_SRC, THD_TYPE_LIMIT,      -1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 120, 131, THD_TRK_SRC, THD_TYPE_THRESHOLD,  -1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 120, 132, THD_TRK_SRC, THD_TYPE_BOTH,       -1,  1, IP_ANY, 0, 0, nullptr }

    // local thresholds ...
    // limit tests ...
    ,{ 200, 200, THD_TRK_SRC, THD_TYPE_LIMIT,       0, 60, IP_ANY, 0, 0, nullptr }
    ,{ 200, 201, THD_TRK_SRC, THD_TYPE_LIMIT,       1, 60, IP_ANY, 0, 0, nullptr }
    ,{ 200, 202, THD_TRK_SRC, THD_TYPE_LIMIT,       1, 60, IP_ANY, 0, 0, nullptr }
    ,{ 200, 203, THD_TRK_SRC, THD_TYPE_LIMIT,       1, 60, IP_ANY, 0, 0, nullptr }
    ,{ 200, 204, THD_TRK_SRC, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 200, 205, THD_TRK_SRC, THD_TYPE_LIMIT,       3,  1, IP_ANY, 0, 0, nullptr }
    ,{ 200, 206, THD_TRK_SRC, THD_TYPE_LIMIT,       0,  0, IP_ANY, 0, 0, nullptr }

    // threshold tests ...
    ,{ 300, 300, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2, 10, IP_ANY, 0, 0, nullptr }
    ,{ 300, 301, THD_TRK_SRC, THD_TYPE_THRESHOLD,   1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 300, 302, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2,  2, IP_ANY, 0, 0, nullptr }
    ,{ 300, 303, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2,  1, IP_ANY, 0, 0, nullptr }
    ,{ 300, 304, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2, 10, IP_ANY, 0, 0, nullptr }
    ,{ 300, 305, THD_TRK_SRC, THD_TYPE_THRESHOLD,   3, 10, IP_ANY, 0, 0, nullptr }
    ,{ 300, 306, THD_TRK_SRC, THD_TYPE_THRESHOLD,   5,  2, IP_ANY, 0, 0, nullptr }

    // both tests ...
    ,{ 400, 400, THD_TRK_SRC, THD_TYPE_BOTH,        2, 10, IP_ANY, 0, 0, nullptr }

    // ip4 suppress tests ...
    ,{ 500, 500, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_DST, 0, 0, nullptr }
    ,{ 500, 501, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP4_NET, 0, 0, nullptr }
    ,{ 500, 502, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, "!" IP4_NET, 0, 0, nullptr }
    ,{ 500, 503, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP_ANY, 0, 0, nullptr }

    // ip6 suppress tests ...
    ,{ 500, 510, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP6_DST, 0, 0, nullptr }
    ,{ 500, 511, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP6_NET, 0, 0, nullptr }
    ,{ 500, 512, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, "!" IP6_NET, 0, 0, nullptr }
    ,{ 500, 513, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP6_NONE, 0, 0, nullptr }

    // ip4 list suppress tests (list only tested with ip6) ...
    ,{ 500, 520, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP4_SET1, 0, 0, nullptr }
    ,{ 500, 521, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_SET1, 0, 0, nullptr }
    ,{ 500, 530, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP4_SET2, 0, 0, nullptr }
    ,{ 500, 531, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_SET2, 0, 0, nullptr }

    // global thresholds ...
    // limit tests ...
    ,{ 600,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       0, 60, IP_ANY, 0, 0, nullptr }
    ,{ 601,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       1, 60, IP_ANY, 0, 0, nullptr }
    ,{ 602,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       1, 60, IP_ANY, 0, 0, nullptr }
    ,{ 603,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       1, 60, IP_ANY, 0, 0, nullptr }
    ,{ 604,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 605,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       3,  1, IP_ANY, 0, 0, nullptr }
    ,{ 606,   0, THD_TRK_SRC, THD_TYPE_LIMIT,       0,  0, IP_ANY, 0, 0, nullptr }

    // threshold tests ...
    ,{ 700,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2, 10, IP_ANY, 0, 0, nullptr }
    ,{ 701,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 702,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2,  2, IP_ANY, 0, 0, nullptr }
    ,{ 703,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2,  1, IP_ANY, 0, 0, nullptr }
    ,{ 704,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   2, 10, IP_ANY, 0, 0, nullptr }
    ,{ 705,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   3, 10, IP_ANY, 0, 0, nullptr }
    ,{ 706,   0, THD_TRK_SRC, THD_TYPE_THRESHOLD,   5,  2, IP_ANY, 0, 0, nullptr }

    // both tests ...
    ,{ 800,   0, THD_TRK_SRC, THD_TYPE_BOTH,        2, 10, IP_ANY, 0, 0, nullptr }

    // ip4 suppress tests ...
    ,{ 900,   0, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_DST, 0, 0, nullptr }
    ,{ 901,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP4_NET, 0, 0, nullptr }
    ,{ 902,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, "!" IP4_NET, 0, 0, nullptr }
    ,{ 903,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP_ANY, 0, 0, nullptr }

    // ip6 suppress tests ...
    ,{ 910,   0, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP6_DST, 0, 0, nullptr }
    ,{ 911,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP6_NET, 0, 0, nullptr }
    ,{ 912,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, "!" IP6_NET, 0, 0, nullptr }
    ,{ 913,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP6_NONE, 0, 0, nullptr }

    // ip4 list suppress tests (list only tested with ip6) ...
    ,{ 920,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP4_SET1, 0, 0, nullptr }
    ,{ 921,   0, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_SET1, 0, 0, nullptr }
    ,{ 930,   0, THD_TRK_SRC, THD_TYPE_SUPPRESS,    0,  0, IP4_SET2, 0, 0, nullptr }
    ,{ 931,   0, THD_TRK_DST, THD_TYPE_SUPPRESS,    0,  0, IP4_SET2, 0, 0, nullptr }
};

#define NUM_THDS (sizeof(thData)/sizeof(thData[0]))

//---------------------------------------------------------------
// the seq field is only used to easily identify any failed tests

static EventData evData[] =
{
    // log all w/o thresholds
    { 0, THD_MAX_GENID, 200, IP4_SRC, IP4_DST, 0, LOG_OK }
    ,{ 1, 200, 199, IP4_SRC, IP4_DST,   0, LOG_OK }

    // these have count or seconds = 0
    ,{ 0, 120, 100, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 120, 100, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 2, 120, 100, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 3, 120, 101, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 4, 120, 101, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 5, 120, 101, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 6, 120, 102, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 7, 120, 102, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 8, 120, 102, IP4_SRC, IP4_DST,   0, LOG_SU }

    // loggable when count < 0
    ,{ 0, 120, 130, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 120, 131, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 2, 120, 132, IP4_SRC, IP4_DST,   0, LOG_OK }

    // LOCAL THRESHOLD TESTS
    // don't log when count is zero
    ,{ 0, 200, 200, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 200, 200, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 2, 200, 200, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 3, 200, 200, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 4, 200, 200, IP4_SRC, IP4_DST,  60, LOG_NO }
    ,{ 5, 200, 200, IP4_SRC, IP4_DST,  60, LOG_NO }
    ,{ 6, 200, 200, IP4_SRC, IP4_DST,  61, LOG_NO }
    ,{ 7, 200, 200, IP4_SRC, IP4_DST,  61, LOG_NO }

    // log the 1st event each 60 secs
    ,{ 0, 200, 201, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 200, 201, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 2, 200, 201, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 3, 200, 201, IP4_SRC, IP4_DST,  60, LOG_OK }
    ,{ 4, 200, 201, IP4_EXT, IP4_DST,  60, LOG_OK }
    ,{ 5, 200, 201, IP4_SRC, IP4_DST,  61, LOG_NO }

    // log the 1st event each 60 secs
    ,{ 0, 200, 202, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 200, 202, IP4_SRC, IP4_DST,  60, LOG_OK }
    ,{ 2, 200, 202, IP4_SRC, IP4_DST, 120, LOG_OK }
    ,{ 3, 200, 202, IP4_SRC, IP4_DST, 180, LOG_OK }
    ,{ 4, 200, 202, IP4_SRC, IP4_DST, 240, LOG_OK }
    ,{ 5, 200, 202, IP4_SRC, IP4_DST, 300, LOG_OK }
    ,{ 6, 200, 202, IP4_SRC, IP4_DST, 360, LOG_OK }
    ,{ 7, 200, 202, IP4_SRC, IP4_DST, 420, LOG_OK }

    // log the 1st event each 60 secs
    ,{ 0, 200, 203, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 200, 203, IP4_SRC, IP4_DST,  61, LOG_OK }
    ,{ 2, 200, 203, IP4_SRC, IP4_DST, 122, LOG_OK }
    ,{ 3, 200, 203, IP4_SRC, IP4_DST, 183, LOG_OK }
    ,{ 4, 200, 203, IP4_SRC, IP4_DST, 244, LOG_OK }
    ,{ 5, 200, 203, IP4_SRC, IP4_DST, 305, LOG_OK }
    ,{ 6, 200, 203, IP4_SRC, IP4_DST, 366, LOG_OK }

    // log the 1st event each 1 secs
    ,{ 0, 200, 204, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 200, 204, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 2, 200, 204, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 200, 204, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 4, 200, 204, IP4_SRC, IP4_DST,   4, LOG_OK }

    // log the 1st 3 events each 1 secs
    ,{ 0, 200, 205, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 1, 200, 205, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 2, 200, 205, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 200, 205, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 4, 200, 205, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 5, 200, 205, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 6, 200, 205, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 7, 200, 205, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 8, 200, 205, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 9, 200, 205, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 10, 200, 205, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 11, 200, 205, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 12, 200, 205, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 13, 200, 205, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 14, 200, 205, IP4_SRC, IP4_DST,   5, LOG_NO }

    // log the 1st 0 events each 0 secs (equivalent to suppress)
    ,{ 0, 200, 206, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 1, 200, 206, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 2, 200, 206, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 3, 200, 206, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 4, 200, 206, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 5, 200, 206, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 6, 200, 206, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 7, 200, 206, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 8, 200, 206, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 9, 200, 206, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 10, 200, 206, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 11, 200, 206, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 12, 200, 206, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 13, 200, 206, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 14, 200, 206, IP4_SRC, IP4_DST,   5, LOG_NO }

    // log every 2nd event each 10 secs
    ,{ 0, 300, 300, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 300, 300, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 2, 300, 300, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 3, 300, 300, IP4_SRC, IP4_DST,  15, LOG_NO }
    ,{ 4, 300, 300, IP4_SRC, IP4_DST,  16, LOG_OK }
    ,{ 5, 300, 300, IP4_SRC, IP4_DST,  25, LOG_NO }
    ,{ 6, 300, 300, IP4_SRC, IP4_DST,  30, LOG_NO }
    ,{ 7, 300, 300, IP4_SRC, IP4_DST,  36, LOG_OK }

    // log every event each second
    ,{ 0, 300, 301, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 300, 301, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 2, 300, 301, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 300, 301, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 4, 300, 301, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 5, 300, 301, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 6, 300, 301, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 7, 300, 301, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 8, 300, 301, IP4_SRC, IP4_DST,   5, LOG_OK }

    // log every 2nd event each 2 secs
    ,{ 0, 300, 302, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 300, 302, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 2, 300, 302, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 3, 300, 302, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 4, 300, 302, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 5, 300, 302, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 6, 300, 302, IP4_SRC, IP4_DST,   6, LOG_NO }

    // log every 2nd event each 1 secs
    ,{ 0, 300, 303, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 300, 303, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 2, 300, 303, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 3, 300, 303, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 4, 300, 303, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 5, 300, 303, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 6, 300, 303, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 7, 300, 303, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 8, 300, 303, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 9, 300, 303, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 10, 300, 303, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 11, 300, 303, IP4_SRC, IP4_DST,   5, LOG_OK }

    // log every 2nd event each 10 secs
    ,{ 0, 300, 304, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 300, 304, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 2, 300, 304, IP4_SRC, IP4_DST,  20, LOG_NO }
    ,{ 3, 300, 304, IP4_SRC, IP4_DST,  30, LOG_NO }
    ,{ 4, 300, 304, IP4_SRC, IP4_DST,  40, LOG_NO }

    // log every 3rd event each 10 secs
    ,{ 0, 300, 305, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 300, 305, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 2, 300, 305, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 300, 305, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 4, 300, 305, IP4_SRC, IP4_DST,  11, LOG_NO }
    ,{ 5, 300, 305, IP4_SRC, IP4_DST,  12, LOG_NO }
    ,{ 6, 300, 305, IP4_SRC, IP4_DST,  20, LOG_NO }
    ,{ 7, 300, 305, IP4_SRC, IP4_DST,  21, LOG_OK }
    ,{ 8, 300, 305, IP4_SRC, IP4_DST,  23, LOG_NO }
    ,{ 9, 300, 305, IP4_SRC, IP4_DST,  25, LOG_NO }
    ,{ 10, 300, 305, IP4_SRC, IP4_DST,  27, LOG_OK }

    // log every 5th event each 2 secs
    ,{ 0, 300, 306, IP4_SRC, IP4_DST, 0.1, LOG_NO }
    ,{ 1, 300, 306, IP4_SRC, IP4_DST, 0.5, LOG_NO }
    ,{ 2, 300, 306, IP4_SRC, IP4_DST, 0.9, LOG_NO }
    ,{ 3, 300, 306, IP4_SRC, IP4_DST, 1.3, LOG_NO }
    ,{ 4, 300, 306, IP4_SRC, IP4_DST, 1.7, LOG_OK }
    ,{ 5, 300, 306, IP4_SRC, IP4_DST, 2.1, LOG_NO }
    ,{ 6, 300, 306, IP4_SRC, IP4_DST, 2.5, LOG_NO }
    ,{ 7, 300, 306, IP4_SRC, IP4_DST, 2.9, LOG_NO }
    ,{ 8, 300, 306, IP4_SRC, IP4_DST, 3.3, LOG_NO }
    ,{ 9, 300, 306, IP4_SRC, IP4_DST, 4.0, LOG_NO }
    ,{ 10, 300, 306, IP4_SRC, IP4_DST, 4.1, LOG_NO }
    ,{ 11, 300, 306, IP4_SRC, IP4_DST, 4.5, LOG_NO }
    ,{ 12, 300, 306, IP4_SRC, IP4_DST, 4.9, LOG_OK }
    ,{ 13, 300, 306, IP4_SRC, IP4_DST, 5.3, LOG_NO }
    ,{ 14, 300, 306, IP4_SRC, IP4_DST, 5.5, LOG_NO }
    ,{ 15, 300, 306, IP4_SRC, IP4_DST, 6.1, LOG_NO }

    // log once after 2 events in 10 secs
    ,{ 0, 400, 400, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 400, 400, IP4_SRC, IP4_DST,   9, LOG_OK }
    ,{ 2, 400, 400, IP4_SRC, IP4_DST,   9, LOG_NO }
    ,{ 3, 400, 400, IP4_SRC, IP4_DST,   9, LOG_NO }
    ,{ 4, 400, 400, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 5, 400, 400, IP4_SRC, IP4_DST,  10, LOG_OK }
    ,{ 6, 400, 400, IP4_SRC, IP4_DST,  11, LOG_NO }
    ,{ 7, 400, 400, IP4_SRC, IP4_DST,  11, LOG_NO }
    ,{ 8, 400, 400, IP4_SRC, IP4_DST,  20, LOG_NO }
    ,{ 9, 400, 400, IP4_SRC, IP4_DST,  20, LOG_OK }
    ,{ 10, 400, 400, IP4_SRC, IP4_DST,  21, LOG_NO }
    ,{ 11, 400, 400, IP4_SRC, IP4_DST,  21, LOG_NO }
    ,{ 12, 400, 400, IP4_SRC, IP4_DST,  22, LOG_NO }
    ,{ 13, 400, 400, IP4_SRC, IP4_DST,  22, LOG_NO }

    // ip4 suppression tests
    ,{ 0, 500, 500, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 500, 500, IP4_SRC, IP4_EXT,   0, LOG_OK }
    ,{ 0, 500, 501, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 500, 501, IP4_DST, IP4_SRC,   0, LOG_SU }
    ,{ 2, 500, 501, IP4_EXT, IP4_SRC,   0, LOG_OK }
    ,{ 0, 500, 502, IP4_DST, IP4_SRC,   0, LOG_OK }
    ,{ 1, 500, 502, IP4_EXT, IP4_SRC,   0, LOG_SU }
    ,{ 0, 500, 503, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 500, 503, IP6_SRC, IP6_DST,   0, LOG_SU }

    // ip6 suppression tests
    ,{ 0, 500, 510, IP6_SRC, IP6_DST,   0, LOG_SU }
    ,{ 1, 500, 510, IP6_SRC, IP6_EXT,   0, LOG_OK }
    ,{ 0, 500, 511, IP6_SRC, IP6_DST,   0, LOG_SU }
    ,{ 1, 500, 511, IP6_DST, IP6_SRC,   0, LOG_SU }
    ,{ 2, 500, 511, IP6_EXT, IP6_SRC,   0, LOG_OK }
    ,{ 0, 500, 512, IP6_DST, IP6_SRC,   0, LOG_OK }
    ,{ 1, 500, 512, IP6_EXT, IP6_SRC,   0, LOG_SU }
    ,{ 0, 500, 513, IP6_SRC, IP6_DST,   0, LOG_SU }
    ,{ 1, 500, 513, IP4_SRC, IP4_DST,   0, LOG_SU }

    // ip4 list suppress tests (list only tested with ip6) ...
    ,{ 0, 500, 520, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 500, 520, IP4_EXT, IP4_DST,   0, LOG_OK }
    ,{ 0, 500, 521, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 500, 521, IP4_SRC, IP4_EXT,   0, LOG_OK }
    ,{ 0, 500, 530, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 500, 530, IP4_EXT, IP4_DST,   0, LOG_OK }
    ,{ 0, 500, 531, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 500, 531, IP4_SRC, IP4_EXT,   0, LOG_OK }

    // GLOBAL THRESHOLD TESTS
    // global tests are the same as local but exercise
    // different code
    // don't log when count is zero
    ,{ 0, 600,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 600,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 2, 600,   0, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 3, 600,   0, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 4, 600,   0, IP4_SRC, IP4_DST,  60, LOG_NO }
    ,{ 5, 600,   0, IP4_SRC, IP4_DST,  60, LOG_NO }
    ,{ 6, 600,   0, IP4_SRC, IP4_DST,  61, LOG_NO }
    ,{ 7, 600,   0, IP4_SRC, IP4_DST,  61, LOG_NO }

    // log the 1st event each 60 secs
    ,{ 0, 601,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 601,   0, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 2, 601,   0, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 3, 601,   0, IP4_SRC, IP4_DST,  60, LOG_OK }
    ,{ 4, 601,   0, IP4_EXT, IP4_DST,  60, LOG_OK }
    ,{ 5, 601,   0, IP4_SRC, IP4_DST,  61, LOG_NO }

    // log the 1st event each 60 secs
    ,{ 0, 602,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 602,   0, IP4_SRC, IP4_DST,  60, LOG_OK }
    ,{ 2, 602,   0, IP4_SRC, IP4_DST, 120, LOG_OK }
    ,{ 3, 602,   0, IP4_SRC, IP4_DST, 180, LOG_OK }
    ,{ 4, 602,   0, IP4_SRC, IP4_DST, 240, LOG_OK }
    ,{ 5, 602,   0, IP4_SRC, IP4_DST, 300, LOG_OK }
    ,{ 6, 602,   0, IP4_SRC, IP4_DST, 360, LOG_OK }
    ,{ 7, 602,   0, IP4_SRC, IP4_DST, 420, LOG_OK }

    // log the 1st event each 60 secs
    ,{ 0, 603,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 603,   0, IP4_SRC, IP4_DST,  61, LOG_OK }
    ,{ 2, 603,   0, IP4_SRC, IP4_DST, 122, LOG_OK }
    ,{ 3, 603,   0, IP4_SRC, IP4_DST, 183, LOG_OK }
    ,{ 4, 603,   0, IP4_SRC, IP4_DST, 244, LOG_OK }
    ,{ 5, 603,   0, IP4_SRC, IP4_DST, 305, LOG_OK }
    ,{ 6, 603,   0, IP4_SRC, IP4_DST, 366, LOG_OK }

    // log the 1st event each 1 secs
    ,{ 0, 604,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 604,   0, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 2, 604,   0, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 604,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 4, 604,   0, IP4_SRC, IP4_DST,   4, LOG_OK }

    // log the 1st 3 events each 1 secs
    ,{ 0, 605,   0, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 1, 605,   0, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 2, 605,   0, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 605,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 4, 605,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 5, 605,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 6, 605,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 7, 605,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 8, 605,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 9, 605,   0, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 10, 605,   0, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 11, 605,   0, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 12, 605,   0, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 13, 605,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 14, 605,   0, IP4_SRC, IP4_DST,   5, LOG_NO }

    // log the 1st 0 events each 0 secs (equivalent to suppress)
    ,{ 0, 606,   0, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 1, 606,   0, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 2, 606,   0, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 3, 606,   0, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 4, 606,   0, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 5, 606,   0, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 6, 606,   0, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 7, 606,   0, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 8, 606,   0, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 9, 606,   0, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 10, 606,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 11, 606,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 12, 606,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 13, 606,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 14, 606,   0, IP4_SRC, IP4_DST,   5, LOG_NO }

    // log every 2nd event each 10 secs
    ,{ 0, 700,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 700,   0, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 2, 700,   0, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 3, 700,   0, IP4_SRC, IP4_DST,  15, LOG_NO }
    ,{ 4, 700,   0, IP4_SRC, IP4_DST,  16, LOG_OK }
    ,{ 5, 700,   0, IP4_SRC, IP4_DST,  25, LOG_NO }
    ,{ 6, 700,   0, IP4_SRC, IP4_DST,  30, LOG_NO }
    ,{ 7, 700,   0, IP4_SRC, IP4_DST,  36, LOG_OK }

    // log every event each second
    ,{ 0, 701,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 701,   0, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 2, 701,   0, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 701,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 4, 701,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 5, 701,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 6, 701,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 7, 701,   0, IP4_SRC, IP4_DST,   5, LOG_OK }
    ,{ 8, 701,   0, IP4_SRC, IP4_DST,   5, LOG_OK }

    // log every 2nd event each 2 secs
    ,{ 0, 702,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 702,   0, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 2, 702,   0, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 3, 702,   0, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 4, 702,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 5, 702,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 6, 702,   0, IP4_SRC, IP4_DST,   6, LOG_NO }

    // log every 2nd event each 1 secs
    ,{ 0, 703,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 703,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 2, 703,   0, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 3, 703,   0, IP4_SRC, IP4_DST,   1, LOG_OK }
    ,{ 4, 703,   0, IP4_SRC, IP4_DST,   2, LOG_NO }
    ,{ 5, 703,   0, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 6, 703,   0, IP4_SRC, IP4_DST,   3, LOG_NO }
    ,{ 7, 703,   0, IP4_SRC, IP4_DST,   3, LOG_OK }
    ,{ 8, 703,   0, IP4_SRC, IP4_DST,   4, LOG_NO }
    ,{ 9, 703,   0, IP4_SRC, IP4_DST,   4, LOG_OK }
    ,{ 10, 703,   0, IP4_SRC, IP4_DST,   5, LOG_NO }
    ,{ 11, 703,   0, IP4_SRC, IP4_DST,   5, LOG_OK }

    // log every 2nd event each 10 secs
    ,{ 0, 704,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 704,   0, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 2, 704,   0, IP4_SRC, IP4_DST,  20, LOG_NO }
    ,{ 3, 704,   0, IP4_SRC, IP4_DST,  30, LOG_NO }
    ,{ 4, 704,   0, IP4_SRC, IP4_DST,  40, LOG_NO }

    // log every 3rd event each 10 secs
    ,{ 0, 705,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 705,   0, IP4_SRC, IP4_DST,   1, LOG_NO }
    ,{ 2, 705,   0, IP4_SRC, IP4_DST,   2, LOG_OK }
    ,{ 3, 705,   0, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 4, 705,   0, IP4_SRC, IP4_DST,  11, LOG_NO }
    ,{ 5, 705,   0, IP4_SRC, IP4_DST,  12, LOG_NO }
    ,{ 6, 705,   0, IP4_SRC, IP4_DST,  20, LOG_NO }
    ,{ 7, 705,   0, IP4_SRC, IP4_DST,  21, LOG_OK }
    ,{ 8, 705,   0, IP4_SRC, IP4_DST,  23, LOG_NO }
    ,{ 9, 705,   0, IP4_SRC, IP4_DST,  25, LOG_NO }
    ,{ 10, 705,   0, IP4_SRC, IP4_DST,  27, LOG_OK }

    // log every 5th event each 2 secs
    ,{ 0, 706,   0, IP4_SRC, IP4_DST, 0.1, LOG_NO }
    ,{ 1, 706,   0, IP4_SRC, IP4_DST, 0.5, LOG_NO }
    ,{ 2, 706,   0, IP4_SRC, IP4_DST, 0.9, LOG_NO }
    ,{ 3, 706,   0, IP4_SRC, IP4_DST, 1.3, LOG_NO }
    ,{ 4, 706,   0, IP4_SRC, IP4_DST, 1.7, LOG_OK }
    ,{ 5, 706,   0, IP4_SRC, IP4_DST, 2.1, LOG_NO }
    ,{ 6, 706,   0, IP4_SRC, IP4_DST, 2.5, LOG_NO }
    ,{ 7, 706,   0, IP4_SRC, IP4_DST, 2.9, LOG_NO }
    ,{ 8, 706,   0, IP4_SRC, IP4_DST, 3.3, LOG_NO }
    ,{ 9, 706,   0, IP4_SRC, IP4_DST, 4.0, LOG_NO }
    ,{ 10, 706,   0, IP4_SRC, IP4_DST, 4.1, LOG_NO }
    ,{ 11, 706,   0, IP4_SRC, IP4_DST, 4.5, LOG_NO }
    ,{ 12, 706,   0, IP4_SRC, IP4_DST, 4.9, LOG_OK }
    ,{ 13, 706,   0, IP4_SRC, IP4_DST, 5.3, LOG_NO }
    ,{ 14, 706,   0, IP4_SRC, IP4_DST, 5.5, LOG_NO }
    ,{ 15, 706,   0, IP4_SRC, IP4_DST, 6.1, LOG_NO }

    // log once after 2 events in 10 secs
    ,{ 0, 800,   0, IP4_SRC, IP4_DST,   0, LOG_NO }
    ,{ 1, 800,   0, IP4_SRC, IP4_DST,   9, LOG_OK }
    ,{ 2, 800,   0, IP4_SRC, IP4_DST,   9, LOG_NO }
    ,{ 3, 800,   0, IP4_SRC, IP4_DST,   9, LOG_NO }
    ,{ 4, 800,   0, IP4_SRC, IP4_DST,  10, LOG_NO }
    ,{ 5, 800,   0, IP4_SRC, IP4_DST,  10, LOG_OK }
    ,{ 6, 800,   0, IP4_SRC, IP4_DST,  11, LOG_NO }
    ,{ 7, 800,   0, IP4_SRC, IP4_DST,  11, LOG_NO }
    ,{ 8, 800,   0, IP4_SRC, IP4_DST,  20, LOG_NO }
    ,{ 9, 800,   0, IP4_SRC, IP4_DST,  20, LOG_OK }
    ,{ 10, 800,   0, IP4_SRC, IP4_DST,  21, LOG_NO }
    ,{ 11, 800,   0, IP4_SRC, IP4_DST,  21, LOG_NO }
    ,{ 12, 800,   0, IP4_SRC, IP4_DST,  22, LOG_NO }
    ,{ 13, 800,   0, IP4_SRC, IP4_DST,  22, LOG_NO }

    // ip4 suppression tests
    ,{ 0, 900,   0, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 900,   0, IP4_SRC, IP4_EXT,   0, LOG_OK }
    ,{ 2, 901,   0, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 3, 901,   0, IP4_DST, IP4_SRC,   0, LOG_SU }
    ,{ 4, 901,   0, IP4_EXT, IP4_SRC,   0, LOG_OK }
    ,{ 5, 902,   0, IP4_DST, IP4_SRC,   0, LOG_OK }
    ,{ 6, 902,   0, IP4_EXT, IP4_SRC,   0, LOG_SU }
    ,{ 7, 903,   0, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 8, 903,   0, IP6_SRC, IP6_DST,   0, LOG_SU }

    // ip6 suppression tests
    ,{ 0, 910,   0, IP6_SRC, IP6_DST,   0, LOG_SU }
    ,{ 1, 910,   0, IP6_SRC, IP6_EXT,   0, LOG_OK }
    ,{ 0, 911,   0, IP6_SRC, IP6_DST,   0, LOG_SU }
    ,{ 1, 911,   0, IP6_DST, IP6_SRC,   0, LOG_SU }
    ,{ 2, 911,   0, IP6_EXT, IP6_SRC,   0, LOG_OK }
    ,{ 0, 912,   0, IP6_DST, IP6_SRC,   0, LOG_OK }
    ,{ 1, 912,   0, IP6_EXT, IP6_SRC,   0, LOG_SU }
    ,{ 0, 913,   0, IP6_SRC, IP6_DST,   0, LOG_SU }
    ,{ 1, 913,   0, IP4_SRC, IP4_DST,   0, LOG_SU }

    // ip4 list suppress tests (list only tested with ip6) ...
    ,{ 0, 920,   0, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 920,   0, IP4_EXT, IP4_DST,   0, LOG_OK }
    ,{ 0, 921,   0, IP4_SRC, IP4_DST,   0, LOG_SU }
    ,{ 1, 921,   0, IP4_SRC, IP4_EXT,   0, LOG_OK }
    ,{ 0, 930,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 930,   0, IP4_EXT, IP4_DST,   0, LOG_OK }
    ,{ 0, 931,   0, IP4_SRC, IP4_DST,   0, LOG_OK }
    ,{ 1, 931,   0, IP4_SRC, IP4_EXT,   0, LOG_OK }
};

#define NUM_EVTS (sizeof(evData)/sizeof(evData[0]))

//---------------------------------------------------------------

static ThreshData ruleData[] =
{
    { 100,   0, THD_TRK_SRC, THD_TYPE_DETECT, 1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100,   1, THD_TRK_DST, THD_TYPE_DETECT, 1,  1, IP_ANY, 0, 0, nullptr }
    ,{ 100,   2, THD_TRK_SRC, THD_TYPE_DETECT, 1,  1, IP6_NONE, 0, 0, nullptr }
    ,{ 100,   3, THD_TRK_DST, THD_TYPE_DETECT, 1,  1, IP6_NONE, 0, 0, nullptr }
};

#define NUM_RULS (sizeof(ruleData)/sizeof(ruleData[0]))

static EventData pktData[] =
{
    // track by_src
    { 0, 0, 0, IP4_SRC, IP4_DST, 0.0, LOG_NO }
    ,{ 1, 0, 0, IP4_SRC, IP4_DST, 1.0, LOG_NO }
    ,{ 2, 0, 0, IP4_SRC, IP4_DST, 2.0, LOG_NO }
    ,{ 3, 0, 0, IP4_SRC, IP4_EXT, 2.1, LOG_OK }
    ,{ 4, 0, 0, IP4_SRC, IP4_DST, 2.1, LOG_OK }
    ,{ 5, 0, 0, IP4_SRC, IP4_EXT, 2.9, LOG_OK }
    ,{ 6, 0, 0, IP4_SRC, IP4_DST, 3.0, LOG_OK }
    ,{ 7, 0, 0, IP4_SRC, IP4_DST, 4.0, LOG_NO }
    ,{ 8, 0, 0, IP4_EXT, IP4_DST, 4.1, LOG_NO }
    ,{ 9, 0, 0, IP4_SRC, IP4_DST, 5.0, LOG_NO }
    // track by_dst
    ,{ 0, 0, 1, IP4_SRC, IP4_DST, 0.0, LOG_NO }
    ,{ 1, 0, 1, IP4_SRC, IP4_DST, 1.0, LOG_NO }
    ,{ 2, 0, 1, IP4_SRC, IP4_DST, 2.0, LOG_NO }
    ,{ 3, 0, 1, IP4_EXT, IP4_DST, 2.1, LOG_OK }
    ,{ 4, 0, 1, IP4_SRC, IP4_DST, 2.1, LOG_OK }
    ,{ 5, 0, 1, IP4_EXT, IP4_DST, 2.9, LOG_OK }
    ,{ 6, 0, 1, IP4_SRC, IP4_DST, 3.0, LOG_OK }
    ,{ 7, 0, 1, IP4_SRC, IP4_DST, 4.0, LOG_NO }
    ,{ 8, 0, 1, IP4_SRC, IP4_EXT, 4.1, LOG_NO }
    ,{ 9, 0, 1, IP4_SRC, IP4_DST, 5.0, LOG_NO }
    // track by_src
    ,{ 0, 0, 2, IP6_SRC, IP6_DST, 0.0, LOG_NO }
    ,{ 1, 0, 2, IP6_SRC, IP6_DST, 1.0, LOG_NO }
    ,{ 2, 0, 2, IP6_SRC, IP6_DST, 2.0, LOG_NO }
    ,{ 3, 0, 2, IP6_SRC, IP6_EXT, 2.1, LOG_OK }
    ,{ 4, 0, 2, IP6_SRC, IP6_DST, 2.1, LOG_OK }
    ,{ 5, 0, 2, IP6_SRC, IP6_EXT, 2.9, LOG_OK }
    ,{ 6, 0, 2, IP6_SRC, IP6_DST, 3.0, LOG_OK }
    ,{ 7, 0, 2, IP6_SRC, IP6_DST, 4.0, LOG_NO }
    ,{ 8, 0, 2, IP6_EXT, IP6_DST, 4.1, LOG_NO }
    ,{ 9, 0, 2, IP6_SRC, IP6_DST, 5.0, LOG_NO }
    // track by_dst
    ,{ 0, 0, 3, IP6_SRC, IP6_DST, 0.0, LOG_NO }
    ,{ 1, 0, 3, IP6_SRC, IP6_DST, 1.0, LOG_NO }
    ,{ 2, 0, 3, IP6_SRC, IP6_DST, 2.0, LOG_NO }
    ,{ 3, 0, 3, IP6_EXT, IP6_DST, 2.1, LOG_OK }
    ,{ 4, 0, 3, IP6_SRC, IP6_DST, 2.1, LOG_OK }
    ,{ 5, 0, 3, IP6_EXT, IP6_DST, 2.9, LOG_OK }
    ,{ 6, 0, 3, IP6_SRC, IP6_DST, 3.0, LOG_OK }
    ,{ 7, 0, 3, IP6_SRC, IP6_DST, 4.0, LOG_NO }
    ,{ 8, 0, 3, IP6_SRC, IP6_EXT, 4.1, LOG_NO }
    ,{ 9, 0, 3, IP6_SRC, IP6_DST, 5.0, LOG_NO }
};

#define NUM_PKTS (sizeof(pktData)/sizeof(pktData[0]))

//---------------------------------------------------------------

static void Init(ThreshData* base, int max)
{
    // FIXIT-L must set policies because they may have been invalidated
    // by prior tests with transient SnortConfigs.  better to fix sfthd
    // to use a SnortConfig parameter or make this a make check test
    // with a separate executable.
    set_default_policy();

    int i;
    int id = 0;

    for ( i = 0; i < max; i++ )
    {
        ThreshData* p = base + i;

        if ( p->type != THD_TYPE_DETECT )
        {
            sfip_var_t* set = p->ip ? sfip_var_from_string(p->ip, "sfthd_test") : nullptr;

            p->create = sfthd_create_threshold(nullptr,
                pThdObjs, p->gid, p->sid, p->tracking, p->type, PRIORITY,
                p->count, p->seconds, set);

            continue;
        }
        p->rule = sfthd_create_rule_threshold(
            ++id, p->tracking, p->type, p->count, p->seconds);

        p->create = (p->rule) ? 0 : -1;
    }
}

static void InitDefault()
{
    pThdObjs = sfthd_objs_new();
    pThd = sfthd_new(MEM_DEFAULT, MEM_DEFAULT);
    Init(thData, NUM_THDS);
}

static void InitMincap()
{
    pThdObjs = sfthd_objs_new();
    pThd = sfthd_new(MEM_MINIMUM, MEM_MINIMUM+1);
    Init(thData, NUM_THDS);
}

static void InitDetect()
{
    dThd = sfthd_local_new(MEM_DEFAULT);
    Init(ruleData, NUM_RULS);
}

static void Term()
{
    sfthd_objs_free(pThdObjs);
    pThdObjs = nullptr;
    sfthd_free(pThd);
    pThd = nullptr;

    for ( unsigned i = 0; i < NUM_RULS; i++ )
    {
        ThreshData* p = ruleData + i;

        if ( p->rule )
        {
            sfthd_node_free(p->rule);
            p->rule = nullptr;
        }
    }
    xhash_delete(dThd);
}

static int SetupCheck(int i)
{
    ThreshData* p = thData + i;
    if ( p->expect == p->create )
        return 1;
    printf("setup %d: exp %d, got %d\n", i, p->expect, p->create);
    return 0;
}

static int RuleCheck(int i)
{
    ThreshData* p = ruleData + i;
    if ( p->expect == p->create )
        return 1;
    printf("rule %d: exp %d, got %d\n", i, p->expect, p->create);
    return 0;
}

static int EventTest(EventData* p, THD_NODE* rule)
{
    // now is a float to clarify the impact of
    // just using truncated seconds on thresholds
    long curtime = (long)p->now;
    int status;

    snort::SfIp sip, dip;
    sip.set(p->sip);
    dip.set(p->dip);

    if ( rule )
    {
        status = sfthd_test_rule(dThd, rule, &sip, &dip, curtime);
    }
    else
    {
        status = sfthd_test_threshold(
            pThdObjs, pThd, p->gid, p->sid, &sip, &dip, curtime);
    }

    return status;
}

static int EventCheck(int i)
{
    EventData* p = evData + i;
    int status = EventTest(p, nullptr);

    if ( p->expect == status )
        return 1;

    printf("event[%u](%u,%u): exp %d, got %d\n",
        p->seq, p->gid, p->sid, p->expect, status);
    return 0;
}

static int IsSuppress(unsigned gid, unsigned sid)
{
    ThreshData* p = thData + NUM_THDS;

    while ( --p >= thData )
    {
        if ( gid == p->gid && sid == p->sid )
            return p->type == THD_TYPE_SUPPRESS;
    }
    return 0;
}

static int CapCheck(int i)
{
    EventData* p = evData + i;
    int status = EventTest(p, nullptr);

    // suppression not affected by ip nodes limit
    int expect = IsSuppress(p->gid, p->sid) ? p->expect : LOG_OK;

    if ( expect == status )
        return 1;

    printf("cap[%u](%u,%u): exp %d, got %d\n",
        p->seq, p->gid, p->sid, expect, status);

    return 0;
}

static int PacketCheck(int i)
{
    EventData* p = pktData + i;
    int status = EventTest(p, ruleData[p->sid].rule);

    if ( p->expect == status )
        return 1;

    printf("packet[%u](%u,%u): exp %d, got %d\n",
        p->seq, p->gid, p->sid, p->expect, status);

    return 0;
}

//---------------------------------------------------------------

TEST_CASE("sfthd normal", "[sfthd]")
{
    InitDefault();

    SECTION("setup")
    {
        for ( unsigned i = 0; i < NUM_THDS; ++i )
            CHECK(SetupCheck(i) == 1);
    }
    SECTION("event")
    {
        for ( unsigned i = 0; i < NUM_EVTS; ++i )
            CHECK(EventCheck(i) == 1);
    }
    Term();
}

TEST_CASE("sfthd mincap", "[sfthd]")
{
    InitMincap();

    SECTION("setup")
    {
        for ( unsigned i = 0; i < NUM_THDS; ++i )
            CHECK(SetupCheck(i) == 1);
    }
    SECTION("cap")
    {
        for ( unsigned i = 0; i < NUM_EVTS; ++i )
            CHECK(CapCheck(i) == 1);
    }
    Term();
}

TEST_CASE("sfthd detect", "[sfthd]")
{
    InitDetect();

    SECTION("rules")
    {
        for ( unsigned i = 0; i < NUM_RULS; ++i )
            CHECK(RuleCheck(i) == 1);
    }
    SECTION("packets")
    {
        for ( unsigned i = 0; i < NUM_PKTS; ++i )
            CHECK(PacketCheck(i) == 1);
    }
    Term();
}

