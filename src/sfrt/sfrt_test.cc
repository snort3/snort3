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
// sfrt_test.cc author Hui Cao <hcao@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"
#include "sfip/sf_cidr.h"
#include "utils/util.h"

#include "sfrt.h"

using namespace snort;

#define NUM_IPS 32
#define NUM_DATA 4

typedef struct
{
    const char* ip_str;
    int value;
} IP_entry;

static IP_entry ip_lists[] =
{
    { "192.168.0.1",4 },
    { "2.16.0.1", 100 },
    { "12.16.0.1", 500 },
    { "19.16.0.1", 12345 },
    { "12.16.0.2", 567890 },
    { "12.168.0.1", 456 },
    { "12.178.0.1", 123456 },
    { "192.168.0.11", 345667 },
    { "192.16.0.17/16", 345667 },
    { "192.168.0.12", 10 },
    { "::FFFF:129.144.52.38", 120 },
    { "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32", 121 },
    { "1001:db8:85a3::/29", 122 },
    { "255.255.255.255", 0 }
};

//---------------------------------------------------------------

static int s_debug = 0;

/* Add one ip, then delete that IP*/
static void test_sfrt_remove_after_insert()
{
    table_t* dir;
    unsigned num_entries;
    unsigned index;

    num_entries = sizeof(ip_lists)/sizeof(ip_lists[0]);
    if ( s_debug )
        printf("Number of entries: %u \n",num_entries);

    dir = sfrt_new(DIR_16_4x4_16x5_4x4, IPv6, num_entries + 1, 200);

    CHECK(dir != nullptr); // "sfrt_new()"

    for (index=0; index<num_entries; index++)
    {
        SfCidr ip;
        SfIp ip2;
        int val;
        int* result = nullptr;

        IP_entry* ip_entry =  &(ip_lists[index]);

        /*Parse IP*/
        ip.set(ip_entry->ip_str);
        char* ip2_str = snort_strdup(ip_entry->ip_str);
        char* p = strchr(ip2_str, '/');
        if (p)
            *p = '\0';
        ip2.set(ip2_str);
        snort_free(ip2_str);

        if ( s_debug )
        {
            SfIpString ip_str;
            printf("Insert IP addr: %s, family: %d\n", ip.get_addr()->ntop(ip_str), ip.get_family());
        }
        CHECK(sfrt_insert(&ip, ip.get_bits(), &(ip_entry->value), RT_FAVOR_TIME, dir) ==
            RT_SUCCESS); // "sfrt_insert()"

        if ( s_debug )
        {
            SfIpString ip_str;
            printf("Lookup IP addr: %s, family: %d\n", ip2.ntop(ip_str), ip2.get_family());
        }
        result = (int*)sfrt_lookup(&ip2, dir);
        if ( s_debug )
        {
            if (result)
                printf("value input: %d, output: %d\n", ip_entry->value, *result);
            else
                printf("value input: %d, output: nullptr\n", ip_entry->value);
        }

        CHECK(result != nullptr); // "sfrt_lookup()"

        if ( s_debug )
        {
            SfIpString ip_str;
            printf("IP addr: %s, family: %d\n", ip.get_addr()->ntop(ip_str), ip.get_family());
            printf("value input: %d, output: %d\n", ip_entry->value, *result);
        }

        CHECK(sfrt_remove(&ip, ip.get_bits(), (void**)&result, RT_FAVOR_TIME, dir) == RT_SUCCESS);
        CHECK(result != nullptr); //sfrt_remove()"

        val = *result;
        if ( s_debug )
            printf("value expected: %d, actual: %d\n", ip_entry->value, val);

        CHECK(val == ip_entry->value); //sfrt_remove(): value return"
        CHECK(sfrt_lookup(ip.get_addr(), dir) == nullptr); // "sfrt_lookup(): value return"
    }

    if ( s_debug )
    {
        printf("Usage: %u bytes\n", sfrt_usage(dir));
        printf("Number of entries: %u \n", sfrt_num_entries(dir));
    }

    sfrt_free(dir);
}

/*Add all IPs, then delete all of them*/
static void test_sfrt_remove_after_insert_all()
{
    table_t* dir;
    unsigned num_entries;
    unsigned index;

    num_entries = sizeof(ip_lists)/sizeof(ip_lists[0]);

    if ( s_debug )
        printf("Number of entries: %u \n",num_entries);

    dir = sfrt_new(DIR_16_4x4_16x5_4x4, IPv6, num_entries + 1, 200);

    CHECK(dir != nullptr); // "sfrt_new()"

    /*insert all entries*/
    for (index=0; index<num_entries; index++)
    {
        SfCidr ip;
        SfIp ip2;
        int* result;

        IP_entry* ip_entry =  &(ip_lists[index]);
        /*Parse IP*/
        ip.set(ip_entry->ip_str);
        char* ip2_str = snort_strdup(ip_entry->ip_str);
        char* p = strchr(ip2_str, '/');
        if (p)
            *p = '\0';
        ip2.set(ip2_str);
        snort_free(ip2_str);

        CHECK(sfrt_insert(&ip, ip.get_bits(), &(ip_entry->value), RT_FAVOR_TIME, dir) ==
            RT_SUCCESS); // "sfrt_insert()"

        result = (int*)sfrt_lookup(ip.get_addr(), dir);

        if ( s_debug )
            printf("value input: %d, output: %d\n", ip_entry->value, result ? *result : -1);

        CHECK(result != nullptr); // "sfrt_lookup()"
    }

    if ( s_debug )
    {
        printf("Usage: %u bytes\n", sfrt_usage(dir));
        printf("Number of entries: %u \n", sfrt_num_entries(dir));
    }

    /*remove all entries*/
    for (index=0; index<num_entries; index++)
    {
        SfCidr ip;
        int val;
        int* result = nullptr;

        IP_entry* ip_entry =  &(ip_lists[index]);
        /*Parse IP*/
        ip.set(ip_entry->ip_str);

        CHECK(sfrt_remove(&ip, ip.get_bits(), (void**)&result, RT_FAVOR_TIME, dir) == RT_SUCCESS);

        REQUIRE(result != nullptr);

        val = *result;
        if ( s_debug )
            printf("value expected: %d, actual: %d\n", ip_entry->value, val);

        CHECK(val == ip_entry->value); //sfrt_remove(): value return"
        CHECK(!sfrt_lookup(ip.get_addr(), dir));

        /*check the next entry still exist*/
        if (index + 1 < num_entries)
        {
            ip_entry =  &(ip_lists[index + 1]);
            /*Parse IP*/
            ip.set(ip_entry->ip_str);
            CHECK(sfrt_lookup(ip.get_addr(), dir)); // "sfrt_lookup(): value return"
        }
    }

    if ( s_debug )
    {
        printf("Usage: %u bytes\n", sfrt_usage(dir));
        printf("Number of entries: %u \n", sfrt_num_entries(dir));
    }

    sfrt_free(dir);
}

TEST_CASE("sfrt", "[sfrt]")
{
    SECTION("remove after insert")
    {
        test_sfrt_remove_after_insert();
    }
    SECTION("remove after insert all")
    {
        test_sfrt_remove_after_insert_all();
    }
}

