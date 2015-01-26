//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>


#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#include <check.h>


#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include "snort_types.h"
#include "sfrt/sfrt.h"
#include "sfip/sf_ip.h"

#define NUM_IPS 32
#define NUM_DATA 4

typedef struct {
    const char* ip_str;
    int value;
} IP_entry;

static IP_entry ip_lists[] =
{
    {"192.168.0.1",4},
    {"2.16.0.1", 100},
    {"12.16.0.1", 500},
    {"19.16.0.1", 12345},
    {"12.16.0.2", 567890},
    {"12.168.0.1", 456},
    {"12.178.0.1", 123456},
    {"192.168.0.11", 345667},
    {"192.16.0.17/16", 345667},
    {"192.168.0.12", 10},
    {"::FFFF:129.144.52.38", 120},
    {"ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32", 121},
    {"1001:db8:85a3::/29", 122},
    {"255.255.255.255", 0}
};
//---------------------------------------------------------------

static int s_debug = 0;

//---------------------------------------------------------------
// check specific stuff: http://check.sourceforge.net/
//
// you can run gcc with -fprofile-arcs -ftest-coverage
// and then gcov foo.c to determine coverage of unit tests

/* Add one ip, then delete that IP*/
START_TEST (test_sfrt_remove_after_insert)
{
    table_t *dir;
    unsigned num_entries;
    unsigned index;

    num_entries = sizeof(ip_lists)/sizeof(ip_lists[0]);
    if ( s_debug )
        printf("Number of entries: %d \n",num_entries);

    dir = sfrt_new(DIR_16_4x4_16x5_4x4, IPv6, num_entries + 1, 200);

    fail_unless( dir != NULL, "sfrt_new()");

    for(index=0; index<num_entries; index++)
    {
        sfip_t ip;
        sfip_t ip2;
        int val;
        int *result = NULL;

        IP_entry *ip_entry =  &(ip_lists[index]);
        /*Parse IP*/
        if (ip_entry->ip_str)
        {
            char *p;
            char *ip2_str;

            sfip_pton(ip_entry->ip_str, &ip);

            ip2_str = strdup(ip_entry->ip_str);
            p = strchr(ip2_str, '/');
            if (p)
            {
                *p = 0;
            }
            sfip_pton(ip2_str, &ip2);
            free(ip2_str);
        }

        if ( s_debug )
        {
            printf("Insert IP addr: %s, family: %d\n", sfip_to_str(&ip), ip.family );
        }
        fail_unless(sfrt_insert(&ip, ip.bits, &(ip_entry->value), RT_FAVOR_TIME, dir) == RT_SUCCESS,"sfrt_insert()");

        if ( s_debug )
        {
            printf("Lookup IP addr: %s, family: %d\n", sfip_to_str(&ip2), ip2.family );
        }
        result = (int*)sfrt_lookup(&ip2, dir);
        if ( s_debug )
        {
            if (result)
                printf("value input: %d, output: %d\n", ip_entry->value, *result);
            else
                printf("value input: %d, output: NULL\n", ip_entry->value);
        }

        fail_unless(result != NULL, "sfrt_lookup()");

        if ( s_debug )
        {
            printf("IP addr: %s, family: %d\n", sfip_to_str(&ip), ip.family );
            printf("value input: %d, output: %d\n", ip_entry->value, *result);
        }

        fail_unless(sfrt_remove(&ip, ip.bits, (void**)&result, RT_FAVOR_TIME, dir) == RT_SUCCESS,"sfrt_remove()");
        fail_unless(result != NULL,"sfrt_remove()");

        val = *result;
        if ( s_debug )
            printf("value expected: %d, actual: %d\n", ip_entry->value, val);

        fail_unless(val == ip_entry->value,"sfrt_remove(): value return");
        fail_unless(sfrt_lookup(&ip, dir) == NULL,"sfrt_lookup(): value return");
    }

    if ( s_debug )
    {
        printf("Usage: %d bytes\n", sfrt_usage(dir));
        printf("Number of entries: %d \n", sfrt_num_entries(dir));
    }

    sfrt_free(dir);

}
END_TEST

/*Add all IPs, then delete all of them*/
START_TEST (test_sfrt_remove_after_insert_all)
{
    table_t *dir;
    unsigned num_entries;
    unsigned index;

    num_entries = sizeof(ip_lists)/sizeof(ip_lists[0]);

    if ( s_debug )
        printf("Number of entries: %d \n",num_entries);

    dir = sfrt_new(DIR_16_4x4_16x5_4x4, IPv6, num_entries + 1, 200);

    fail_unless( dir != NULL, "sfrt_new()");

    /*insert all entries*/
    for(index=0; index<num_entries; index++)
    {
        sfip_t ip;
        sfip_t ip2;
        int *result;

        IP_entry *ip_entry =  &(ip_lists[index]);
        /*Parse IP*/
        if (ip_entry->ip_str)
        {
            char *p;
            char *ip2_str;

            sfip_pton(ip_entry->ip_str, &ip);

            ip2_str = strdup(ip_entry->ip_str);
            p = strchr(ip2_str, '/');
            if (p)
            {
                *p = 0;
            }
            sfip_pton(ip2_str, &ip2);
            free(ip2_str);
        }

        fail_unless(sfrt_insert(&ip, ip.bits, &(ip_entry->value), RT_FAVOR_TIME, dir) == RT_SUCCESS,"sfrt_insert()");

        result = (int*)sfrt_lookup(&ip, dir);

        if ( s_debug )
            printf("value input: %d, output: %d\n", ip_entry->value, result ? *result : -1);

        fail_unless(result != NULL, "sfrt_lookup()");
    }


    if ( s_debug )
    {
        printf("Usage: %d bytes\n", sfrt_usage(dir));
        printf("Number of entries: %d \n", sfrt_num_entries(dir));
    }

    /*remove all entries*/
    for(index=0; index<num_entries; index++)
    {
        sfip_t ip;
        int val;
        int *result;

        IP_entry *ip_entry =  &(ip_lists[index]);
        /*Parse IP*/
        if (ip_entry->ip_str)
            sfip_pton(ip_entry->ip_str, &ip);

        fail_unless(sfrt_remove(&ip, ip.bits, (void**)&result, RT_FAVOR_TIME, dir) == RT_SUCCESS,"sfrt_remove()");

        val = *result;
        if ( s_debug )
            printf("value expected: %d, actual: %d\n", ip_entry->value, val);

        fail_unless(val == ip_entry->value,"sfrt_remove(): value return");
        fail_unless(sfrt_lookup(&ip, dir) == NULL,"sfrt_lookup(): value return");

        /*check the next entry still exist*/
        if (index + 1 < num_entries)
        {
            IP_entry *ip_entry =  &(ip_lists[index + 1]);
            /*Parse IP*/
            if (ip_entry->ip_str)
                sfip_pton(ip_entry->ip_str, &ip);
            fail_unless(sfrt_lookup(&ip, dir) != NULL,"sfrt_lookup(): value return");
        }
    }

    if ( s_debug )
    {
        printf("Usage: %d bytes\n", sfrt_usage(dir));
        printf("Number of entries: %d \n", sfrt_num_entries(dir));
    }

    sfrt_free(dir);

}
END_TEST

Suite* TEST_SUITE_sfrt(void)
{
    Suite* ps = suite_create("sfrt");

    TCase* tc = tcase_create("sfrt_remove");
    tcase_add_test(tc, test_sfrt_remove_after_insert);
    tcase_add_test(tc, test_sfrt_remove_after_insert_all);

    suite_add_tcase(ps, tc);
    return ps;
}

