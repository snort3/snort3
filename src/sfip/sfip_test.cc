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
// sf_ip_test.cc author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "catch/snort_catch.h"

#include "sf_cidr.h"

using namespace snort;

//---------------------------------------------------------------

static int s_debug = 0;

static const char* const codes[] =
{
    "success",
    "failure",
    "lesser",
    "greater",
    "equal",
    "arg_err",
    "cidr_err",
    "inet_parse_err",
    "invalid_mask",
    "alloc_err",
    "contains",
    "not_contains",
    "duplicate",
    "lookup_failure",
    "unmatched_bracket",
    "not_any",
    "conflict"
};

struct FuncTest
{
    const char* func;
    const char* arg1;
    const char* arg2;
    int expected;
};

//---------------------------------------------------------------
// __STRDUMP_DISABLE__

static FuncTest ftests[] =
{
    { "sfip_pton", "192.168.0.1", "192.168.0.1", SFIP_SUCCESS },
    { "sfip_pton", "255.255.255.255/21", "255.255.248.0", SFIP_SUCCESS },
    { "sfip_pton", "1.1.255.255      255.255.248.0", "1.1.248.0", SFIP_SUCCESS },
    { "sfip_pton", " 2001:0db8:0000:0000:0000:0000:1428:57ab   ",
      "2001:0db8:0000:0000:0000:0000:1428:57ab", SFIP_SUCCESS },
    { "sfip_pton", "ffff:ffff::1",
      "ffff:ffff:0000:0000:0000:0000:0000:0001", SFIP_SUCCESS },
    { "sfip_pton", "fFfF::FfFf:FFFF/127",
      "ffff:0000:0000:0000:0000:0000:ffff:fffe", SFIP_SUCCESS },
    { "sfip_pton", "ffff::ffff:1/8",
      "ff00:0000:0000:0000:0000:0000:0000:0000", SFIP_SUCCESS },
    { "sfip_pton", "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::",
      "6543:2100:0000:0000:0000:0000:0000:0000", SFIP_SUCCESS },
    { "sfip_pton", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
      "ffee:ddcc:0000:0000:0000:0000:0000:0000", SFIP_SUCCESS },
    { "sfip_pton", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100",
      "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4:255.0.0.0", "1.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4/255.0.0.0", "1.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4 : 255.0.0.0", "1.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4 / 255.0.0.0", "1.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4  :255.0.0.0", "1.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4/  255.0.0.0", "1.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4/16", "1.2.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4/ 16", "1.2.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4 / 16", "1.2.0.0", SFIP_SUCCESS },
    { "sfip_pton", " 1.2.3.4 / 16 ", "1.2.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4/0", "0.0.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1.2.3.4/16", "1.2.0.0", SFIP_SUCCESS },
    { "sfip_pton", "1234::1.2.3.4",
      "1234:0000:0000:0000:0000:0000:0102:0304", SFIP_SUCCESS },
    { "sfip_pton", "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210",
      "fedc:ba98:7654:3210:fedc:ba98:7654:3210", SFIP_SUCCESS },
    { "sfip_pton", "1080:0:0:0:8:800:200C:4171",
      "1080:0000:0000:0000:0008:0800:200c:4171", SFIP_SUCCESS },
    { "sfip_pton", "3ffe:2a00:100:7031::1",
      "3ffe:2a00:0100:7031:0000:0000:0000:0001", SFIP_SUCCESS },
    { "sfip_pton", "1080::8:800:200C:417A",
      "1080:0000:0000:0000:0008:0800:200c:417a", SFIP_SUCCESS },
    { "sfip_pton", "::192.9.5.5",
      "0000:0000:0000:0000:0000:0000:c009:0505", SFIP_SUCCESS },
    { "sfip_pton", "::FFFF:129.144.52.38",
      "0000:0000:0000:0000:0000:ffff:8190:3426", SFIP_SUCCESS },

    { "sfip_pton", "2010:836B:4179::836B:4179",
      "2010:836b:4179:0000:0000:0000:836b:4179", SFIP_SUCCESS },
    { "sfip_pton", "::",
      "0000:0000:0000:0000:0000:0000:0000:0000", SFIP_SUCCESS },

    { "sfip_is_set", "8::", nullptr, SFIP_SUCCESS },
    { "sfip_is_set", "::1", nullptr, SFIP_SUCCESS },
    { "sfip_is_set", "::", nullptr, SFIP_FAILURE },

    { "sfip_is_loopback", "127.0.0.0", nullptr, SFIP_SUCCESS },
    { "sfip_is_loopback", "127.255.255.255", nullptr, SFIP_SUCCESS },
    { "sfip_is_loopback", "128.0.0.0", nullptr, SFIP_FAILURE },
    { "sfip_is_loopback", "::1", nullptr, SFIP_SUCCESS },
    { "sfip_is_loopback", "::2", nullptr, SFIP_FAILURE },
    { "sfip_is_loopback", "::7f00:0/104", nullptr, SFIP_SUCCESS },
    { "sfip_is_loopback", "::ffff:127.0.0.0/104", nullptr, SFIP_SUCCESS },
    { "sfip_is_loopback", "::127.0.0.0", nullptr, SFIP_SUCCESS },
    { "sfip_is_loopback", "::128.0.0.1", nullptr, SFIP_FAILURE },
    { "sfip_is_loopback", "::ffff:0.0.0.1", nullptr, SFIP_FAILURE },

    { "sfip_ismapped", "::ffff:c000:280", nullptr, SFIP_SUCCESS },
    { "sfip_ismapped", "8::ffff:c000:280", nullptr, SFIP_FAILURE },
    { "sfip_ismapped", "::fffe:c000:280", nullptr, SFIP_FAILURE },

    // v6<->v6 Comparisons
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:1:3:4:5:6:7:8", SFIP_GREATER },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:2:4:4:5:6:7:8", SFIP_LESSER },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:5:7:8", SFIP_GREATER },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:8:8", SFIP_LESSER },

    { "sfip_compare", "1.2.3.4", "1.2.3.4", SFIP_EQUAL },
    { "sfip_compare", "255.255.255.255", "192.168.0.1", SFIP_GREATER },
    { "sfip_compare", "192.168.0.1", "255.255.255.255/21", SFIP_LESSER },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "sfip_compare", "ffff:ffff::1",
      "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::", SFIP_GREATER },
    { "sfip_compare", "1.2.3.4", "0.0.0.0", SFIP_EQUAL },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "::", SFIP_EQUAL },
    { "sfip_compare", "10.10.1.0/16", "10.10.24.14/24", SFIP_LESSER },
    { "sfip_compare", "10.10.1.0/24", "10.10.1.0/16", SFIP_GREATER },
    { "sfip_compare", "10.10.1.0/16", "10.10.2.1/8", SFIP_GREATER },
    { "sfip_compare", "10.10.1.8/32", "10.10.1.8", SFIP_EQUAL },

    { "sfip_compare_unset", "1.2.3.4", "1.2.3.4", SFIP_EQUAL },
    { "sfip_compare_unset", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "sfip_compare_unset", "1.2.3.4", "0.0.0.0", SFIP_FAILURE },

    { "sfip_compare_unset", "1:2:3:4:5:6:7:8", "::", SFIP_FAILURE },

    { "sfip_fast_eq4", "1.2.3.4", "1.2.3.4", SFIP_SUCCESS },
    { "sfip_fast_eq4", "1.2.3.4", "1.2.3.5", SFIP_FAILURE },
    { "sfip_fast_eq4", "1.2.3.5", "1.2.3.4", SFIP_FAILURE },

    { "sfip_fast_lt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_FAILURE },
    { "sfip_fast_lt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", SFIP_SUCCESS },
    { "sfip_fast_lt6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", SFIP_FAILURE },

    { "sfip_fast_gt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_FAILURE },
    { "sfip_fast_gt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", SFIP_FAILURE },
    { "sfip_fast_gt6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", SFIP_SUCCESS },

    { "sfip_fast_eq6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_SUCCESS },
    { "sfip_fast_eq6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", SFIP_FAILURE },
    { "sfip_fast_eq6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", SFIP_FAILURE },

    { "sfip_fast_cont4", "255.255.255.255", "192.168.0.1", SFIP_FAILURE },
    { "sfip_fast_cont4", "192.168.0.1", "255.255.255.255/21", SFIP_FAILURE },
    { "sfip_fast_cont4", "255.255.255.255/21", "255.255.255.255", SFIP_SUCCESS },
    { "sfip_fast_cont4", "255.255.255.255", "255.255.255.255/21", SFIP_FAILURE },

    { "sfip_contains", "255.255.255.255", "192.168.0.1", SFIP_NOT_CONTAINS },
    { "sfip_contains", "192.168.0.1", "255.255.255.255/21", SFIP_NOT_CONTAINS },
    { "sfip_contains", "255.255.255.255/21", "255.255.255.255", SFIP_CONTAINS },
    { "sfip_contains", "255.255.255.255", "255.255.255.255/21", SFIP_NOT_CONTAINS },
    { "sfip_contains", "10.10.1.0/16", "10.10.24.14/24", SFIP_CONTAINS },
    { "sfip_contains", "10.10.1.0/16", "10.10.1.0/24", SFIP_CONTAINS },
    { "sfip_contains", "10.10.1.0/16", "10.10.2.1/8", SFIP_NOT_CONTAINS },
    { "sfip_contains", "10.10.1.8/32", "10.10.1.8", SFIP_CONTAINS },

    { "sfip_fast_cont6", "ffff:ffff::1", "ffff::ffff:1/8", SFIP_FAILURE },
    { "sfip_fast_cont6", "ffff::ffff:1/8", "ffff:ffff::1", SFIP_SUCCESS },
    { "sfip_fast_cont6", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
      "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", SFIP_SUCCESS },
    { "sfip_fast_cont6", "1001:db8:85a3::/28", "1001:db0::", SFIP_SUCCESS },
    { "sfip_fast_cont6", "1001:db8:85a3::/29", "1001:db0::", SFIP_FAILURE },

    { "sfip_contains", "ffff:ffff::1", "ffff::ffff:1/8", SFIP_NOT_CONTAINS },
    { "sfip_contains", "ffff::ffff:1/8", "ffff:ffff::1", SFIP_CONTAINS },
    { "sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
      "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", SFIP_CONTAINS },
    { "sfip_contains", "1001:db8:85a3::/28", "1001:db0::", SFIP_CONTAINS },
    { "sfip_contains", "1001:db8:85a3::/29", "1001:db0::", SFIP_NOT_CONTAINS },

    { "sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101",
      "ffee:ddcc:bbaa:9988:7766:5544:3322:1102", SFIP_NOT_CONTAINS },
    { "sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101/96",
      "ffee:ddcc:bbaa:9988:7766:5544:3322:1102", SFIP_CONTAINS },
    { "sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101/97",
      "ffee:ddcc:bbaa:9988:7766:5544:3322:1102", SFIP_CONTAINS },
    { "sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1101/97",
      "ffee:ddcc:bbaa:9988:7766:5544:b322:1102", SFIP_NOT_CONTAINS },

    { "sfip_contains", "255.255.255.255",
      "2001:0db8:0000:0000:0000:0000:1428:57ab", SFIP_NOT_CONTAINS },

    { "sfip_obfuscate", "::",
      "0000:0000:0000:0000:0000:0000:0000:0000", SFIP_EQUAL },
    { "sfip_obfuscate", "::/64",
      "0000:0000:0000:0000:0004:0003:0002:0001", SFIP_EQUAL },
    { "sfip_obfuscate", "f0:e0:d0:c0::8/64",
      "00f0:00e0:00d0:00c0:0004:0003:0002:0001", SFIP_EQUAL },
    { "sfip_obfuscate", "9.8.7.6", "9.8.7.6", SFIP_EQUAL },
    { "sfip_obfuscate", "0.0.0.8/16", "0.0.2.1", SFIP_EQUAL },
    { "sfip_obfuscate", "192.168.0.0/16", "192.168.2.1", SFIP_EQUAL }
};

#define NUM_TESTS (sizeof(ftests)/sizeof(ftests[0]))

// __STRDUMP_ENABLE__
//---------------------------------------------------------------

static int RunFunc(const char* func, const char* arg1, const char* arg2)
{
    SfCidr cidr1, cidr2;
    const SfIp* ip1, * ip2;
    int result = SFIP_FAILURE;

    cidr1.clear();
    if (arg1)
        cidr1.set(arg1);
    ip1 = cidr1.get_addr();

    cidr2.clear();
    if (arg2)
        cidr2.set(arg2);
    ip2 = cidr2.get_addr();

    if ( !strcmp(func, "sfip_pton") )
    {
        char buf[INET6_ADDRSTRLEN];

        sfip_ntop(ip1, buf, sizeof(buf));
        if (arg2)
            result = strcmp(buf, arg2) ? SFIP_FAILURE : SFIP_SUCCESS;
    }
    else if ( !strcmp(func, "sfip_contains") )
    {
        result = cidr1.contains(ip2);
    }
    else if ( !strcmp(func, "sfip_is_set") )
    {
        result = !ip1->is_set();
    }
    else if ( !strcmp(func, "sfip_is_loopback") )
    {
        result = !ip1->is_loopback();
    }
    else if ( !strcmp(func, "sfip_ismapped") )
    {
        result = !ip1->is_mapped();
    }
    else if ( !strcmp(func, "sfip_compare") )
    {
        result = ip1->compare(*ip2);
    }
    else if ( !strcmp(func, "sfip_compare_unset") )
    {
        result = ip1->compare(*ip2, false);
    }
    else if ( !strcmp(func, "sfip_fast_eq4") )
    {
        result = !ip1->fast_eq4(*ip2);
    }
    else if ( !strcmp(func, "sfip_fast_lt6") )
    {
        result = !ip1->fast_lt6(*ip2);
    }
    else if ( !strcmp(func, "sfip_fast_gt6") )
    {
        result = !ip1->fast_gt6(*ip2);
    }
    else if ( !strcmp(func, "sfip_fast_eq6") )
    {
        result = !ip1->fast_eq6(*ip2);
    }
    else if ( !strcmp(func, "sfip_fast_cont4") )
    {
        result = !cidr1.fast_cont4(*ip2);
    }
    else if ( !strcmp(func, "sfip_fast_cont6") )
    {
        result = !cidr1.fast_cont6(*ip2);
    }
    else if ( !strcmp(func, "sfip_obfuscate") )
    {
        SfIp ip;
        if ( ip1->get_family() == AF_INET )
            ip.set("4.3.2.1");
        else
            ip.set("8:7:6:5:4:3:2:1");
        ip.obfuscate(&cidr1);
        result = ip.compare(*ip2);
    }

    return result;
}

//---------------------------------------------------------------

static int FuncCheck(int i)
{
    FuncTest* f = ftests + i;
    int result;

    const char* status = "Passed";
    const char* code;

    result = RunFunc(f->func, f->arg1, f->arg2);

    code = (0 <= result && (size_t)result < sizeof(codes)/sizeof(code[0])) ?
        codes[result] : "uh oh";

    if ( result != f->expected )
    {
        status = "Failed";
    }
    if ( result != f->expected || s_debug )
    {
        if ( f->arg2 )
            printf("[%d] %s: %s(%s, %s) = %s\n",
                i, status, f->func, f->arg1, f->arg2, code);
        else
            printf("[%d] %s: %s(%s) = %s\n",
                i, status, f->func, f->arg1, code);
    }
    return result == f->expected;
}

static int SetCheck(int i)
{
    FuncTest* f = ftests + i;
    SfIpRet status;
    SfIp ip1, ip2;

    ip1.set(f->arg1);
    status = ip2.set(ip1.get_ptr(), ip1.get_family());

    return (status == SFIP_SUCCESS) && !memcmp(&ip1, &ip2, sizeof(ip1));
}

static int CopyCheck(int i)
{
    FuncTest* f = ftests + i;
    SfIp ip1, ip2;

    ip1.set(f->arg1);
    ip2.set(ip1);

    return !memcmp(&ip1, &ip2, sizeof(ip1));
}

//---------------------------------------------------------------

TEST_CASE("sfip exec", "[sfip]")
{
    for ( unsigned i = 0; i < NUM_TESTS; ++i )
        CHECK(FuncCheck(i) == 1);
}

TEST_CASE("sfip set", "[sfip]")
{
    for ( unsigned i = 0; i < NUM_TESTS; ++i )
        CHECK(SetCheck(i) == 1);
}

TEST_CASE("sfip copy", "[sfip]")
{
    for ( unsigned i = 0; i < NUM_TESTS; ++i )
        CHECK(CopyCheck(i) == 1);
}
