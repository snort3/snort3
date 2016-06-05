//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "catch/catch.hpp"

#include "main/snort_types.h"
#include "sf_ip.h"

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

static FuncTest ftests[] =
{
    { "sfip_pton", "192.168.0.1", "192.168.0.1", SFIP_SUCCESS },
    { "sfip_pton", "255.255.255.255/21", "255.255.248.0", SFIP_SUCCESS },
    { "sfip_pton", "1.1.255.255      255.255.248.0", "1.1.248.0", SFIP_SUCCESS },
    { "sfip_pton", " 2001:0db8:0000:0000:0000:0000:1428:57ab   ",
      "2001:db8::1428:57ab", SFIP_SUCCESS },
    { "sfip_pton", "ffff:ffff::1",
      "ffff:ffff::1", SFIP_SUCCESS },
    { "sfip_pton", "fFfF::FfFf:FFFF/127",
      "ffff::ffff:fffe", SFIP_SUCCESS },
    { "sfip_pton", "ffff::ffff:1/8",
      "ff00::", SFIP_SUCCESS },
    { "sfip_pton", "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::",
      "6543:2100::", SFIP_SUCCESS },
    { "sfip_pton", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
      "ffee:ddcc::", SFIP_SUCCESS },
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
    { "sfip_pton", "1234::1.2.3.4",
      "1234::102:304", SFIP_SUCCESS },
    { "sfip_pton", "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210",
      "fedc:ba98:7654:3210:fedc:ba98:7654:3210", SFIP_SUCCESS },
    { "sfip_pton", "1080:0:0:0:8:800:200C:4171",
      "1080::8:800:200c:4171", SFIP_SUCCESS },
    { "sfip_pton", "3ffe:2a00:100:7031::1",
      "3ffe:2a00:100:7031::1", SFIP_SUCCESS },
    { "sfip_pton", "1080::8:800:200C:417A",
      "1080::8:800:200c:417a", SFIP_SUCCESS },
    { "sfip_pton", "::192.9.5.5",
      "::192.9.5.5", SFIP_SUCCESS },
    { "sfip_pton", "::FFFF:129.144.52.38",
      "::ffff:129.144.52.38", SFIP_SUCCESS },
    { "sfip_pton", "2010:836B:4179::836B:4179",
      "2010:836b:4179::836b:4179", SFIP_SUCCESS },
    { "sfip_pton", "::", "::", SFIP_SUCCESS },

    // atoi(arg2) gives expected hash length
    // ip format ensures alloc tests don't fail
    { "sfip_size", "::", "20.0.0.0", SFIP_SUCCESS },
    { "sfip_size", "1.2.3.4", "8.0.0.0", SFIP_SUCCESS },

    { "sfip_is_set", "8::", NULL, SFIP_SUCCESS },
    { "sfip_is_set", "::1", NULL, SFIP_SUCCESS },
    { "sfip_is_set", "::", NULL, SFIP_FAILURE },

    { "sfip_is_loopback", "127.0.0.0", NULL, SFIP_SUCCESS },
    { "sfip_is_loopback", "127.255.255.255", NULL, SFIP_SUCCESS },
    { "sfip_is_loopback", "128.0.0.0", NULL, SFIP_FAILURE },
    { "sfip_is_loopback", "::1", NULL, SFIP_SUCCESS },
    { "sfip_is_loopback", "::2", NULL, SFIP_FAILURE },
    { "sfip_is_loopback", "::7f00:0/104", NULL, SFIP_SUCCESS },
    { "sfip_is_loopback", "::ffff:127.0.0.0/104", NULL, SFIP_SUCCESS },
    { "sfip_is_loopback", "::127.0.0.0", NULL, SFIP_SUCCESS },
    { "sfip_is_loopback", "::128.0.0.1", NULL, SFIP_FAILURE },
    { "sfip_is_loopback", "::ffff:0.0.0.1", NULL, SFIP_FAILURE },

    { "sfip_ismapped", "::ffff:c000:280", NULL, SFIP_SUCCESS },
    { "sfip_ismapped", "8::ffff:c000:280", NULL, SFIP_FAILURE },
    { "sfip_ismapped", "::fffe:c000:280", NULL, SFIP_FAILURE },

    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:1:3:4:5:6:7:8", SFIP_GREATER },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:4:4:5:6:7:8", SFIP_LESSER },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:3:4:5:5:7:8", SFIP_GREATER },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:8:8", SFIP_LESSER },

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

    { "sfip_fast_lt4", "1.2.3.4", "1.2.3.4", SFIP_FAILURE },
    { "sfip_fast_lt4", "1.2.3.4", "1.2.3.5", SFIP_SUCCESS },
    { "sfip_fast_lt4", "1.2.3.5", "1.2.3.4", SFIP_FAILURE },

    { "sfip_fast_gt4", "1.2.3.4", "1.2.3.4", SFIP_FAILURE },
    { "sfip_fast_gt4", "1.2.3.4", "1.2.3.5", SFIP_FAILURE },
    { "sfip_fast_gt4", "1.2.3.5", "1.2.3.4", SFIP_SUCCESS },

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

    { "sfip_contains", "255.255.255.255",
      "2001:0db8:0000:0000:0000:0000:1428:57ab", SFIP_ARG_ERR },

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

//---------------------------------------------------------------

static int RunFunc(const char* func, const char* arg1, const char* arg2)
{
    sfip_t ip1, ip2;
    sfip_clear(ip1);
    sfip_clear(ip2);
    int result = SFIP_FAILURE;

    if ( arg1 )
        sfip_pton(arg1, &ip1);
    if ( arg2 )
        sfip_pton(arg2, &ip2);

    if ( !strcmp(func, "sfip_pton") )
    {
        char buf1[INET6_ADDRSTRLEN];
        char buf2[INET6_ADDRSTRLEN];

        sfip_ntop(&ip1, buf1, sizeof(buf1));
        sfip_ntop(&ip2, buf2, sizeof(buf2));

        result = strcmp(buf1, buf2) ? SFIP_FAILURE : SFIP_SUCCESS;
    }
    else if ( !strcmp(func, "sfip_size") and arg2 )
    {
        result = sfip_size(&ip1);
        result = (result == atoi(arg2)) ? SFIP_SUCCESS : SFIP_FAILURE;
    }
    else if ( !strcmp(func, "sfip_contains") )
    {
        result = sfip_contains(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_is_set") )
    {
        result = !sfip_is_set(&ip1);
    }
    else if ( !strcmp(func, "sfip_is_loopback") )
    {
        result = !sfip_is_loopback(&ip1);
    }
    else if ( !strcmp(func, "sfip_ismapped") )
    {
        result = !sfip_ismapped(&ip1);
    }
    else if ( !strcmp(func, "_ip6_cmp") )
    {
        result = _ip6_cmp(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_compare") )
    {
        result = sfip_compare(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_compare_unset") )
    {
        result = sfip_compare_unset(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_lt4") )
    {
        result = !sfip_fast_lt4(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_gt4") )
    {
        result = !sfip_fast_gt4(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_eq4") )
    {
        result = !sfip_fast_eq4(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_lt6") )
    {
        result = !sfip_fast_lt6(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_gt6") )
    {
        result = !sfip_fast_gt6(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_eq6") )
    {
        result = !sfip_fast_eq6(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_cont4") )
    {
        result = !sfip_fast_cont4(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_fast_cont6") )
    {
        result = !sfip_fast_cont6(&ip1, &ip2);
    }
    else if ( !strcmp(func, "sfip_obfuscate") )
    {
        sfip_t ip;
        if ( ip1.family == AF_INET )
        {
            sfip_pton("4.3.2.1", &ip);
        }
        else
        {
            sfip_pton("8:7:6:5:4:3:2:1", &ip);
        }
        sfip_obfuscate(&ip1, &ip);
        result = sfip_compare(&ip, &ip2);
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

static int AllocCheck(int i)
{
    FuncTest* f = ftests + i;
    SFIP_RET status;
    sfip_t* pip1, * pip2;

    pip1 = sfip_alloc(f->arg1, &status);
    if ( !pip1 || status != SFIP_SUCCESS )
        return 0;

    if ( f->arg2 )
    {
        pip2 = sfip_alloc(f->arg2, &status);
    }
    else
    {
        unsigned int i = 0xffffffff;
        pip2 = sfip_alloc_raw(&i, AF_INET, &status);
    }
    if ( !pip2 || status != SFIP_SUCCESS )
        return 0;

    sfip_free(pip1);
    sfip_free(pip2);

    return 1;
}

static int RawCheck(int i)
{
    SFIP_RET status;
    uint8_t addr[16];
    const char* s, * exp;
    size_t j;
    sfip_t* pip;

    for ( j = 0; j < sizeof(addr); j++ )
        // avoid leading zero confusion
        addr[j] = j | (j % 2 ? 0x00 : 0x80);

    if ( i )
    {
        pip = sfip_alloc_raw(addr, AF_INET6, &status);
        exp = "8001:8203:8405:8607:8809:8a0b:8c0d:8e0f";
    }
    else
    {
        pip = sfip_alloc_raw(addr, AF_INET, &status);
        exp = "128.1.130.3";
    }
    if ( status != SFIP_SUCCESS )
        return 0;

    s = sfip_to_str(pip);
    sfip_free(pip);

    return !strcasecmp(s, exp);
}

static int SetCheck(int i)
{
    FuncTest* f = ftests + i;
    SFIP_RET status;
    sfip_t ip1, ip2;

    sfip_pton(f->arg1, &ip1);
    status = sfip_set_raw(&ip2, ip1.ip8, ip1.family);
    sfip_set_bits(&ip2, sfip_bits(&ip1));

    return (status == SFIP_SUCCESS) && !memcmp(&ip1, &ip2, sizeof(ip1));
}

static int CopyCheck(int i)
{
    FuncTest* f = ftests + i;
    SFIP_RET status;
    sfip_t ip1, ip2;

    sfip_pton(f->arg1, &ip1);
    status = sfip_set_ip(&ip2, &ip1);

    return (status == SFIP_SUCCESS) && !memcmp(&ip1, &ip2, sizeof(ip1));
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

TEST_CASE("sfip alloc", "[sfip]")
{
    for ( unsigned i = 0; i < NUM_TESTS; ++i )
        CHECK(AllocCheck(i) == 1);
}

TEST_CASE("sfip raw", "[sfip]")
{
    for ( unsigned i = 0; i < 2; ++i )
        CHECK(RawCheck(i) == 1);
}

