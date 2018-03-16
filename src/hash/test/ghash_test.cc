//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// ghash_test.cc author Steven Baigal <sbaigal@cisco.com>
// unit tests for ghash utility functions

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/ghash.h"

#include "main/snort_config.h"
#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

// Stubs whose sole purpose is to make the test code link
static SnortConfig my_config;
THREAD_LOCAL SnortConfig *snort_conf = &my_config;

SnortConfig::SnortConfig(const SnortConfig* const)
{ snort_conf->run_flags = 0;} // run_flags is used indirectly from HashFnc class by calling SnortConfig::static_hash()

SnortConfig::~SnortConfig() = default;

SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

// user free function
static void myfree(void* p)
{
    snort_free(p);
}

TEST_GROUP(ghash)
{
};

//  Test create a hash table, add nodes, find and delete.
TEST(ghash, create_find_delete_test)
{
    int i;
    char str[256];
    int num=100;

    // Create a Hash Table
    GHash* t = ghash_new(1000, 0, GH_COPYKEYS, nullptr);

    // Add Nodes to the Hash Table
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        ghash_add(t, str, (void *)(str + (i+1)));
    }

    // find those nodes
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char* p = (char*)ghash_find(t, str);

        CHECK(p != nullptr);
        CHECK(p == (void *)(str + (i+1)));
    }

    for (GHashNode* n = ghash_findfirst(t); n; n = ghash_findnext(t) )
    {
        i = ghash_remove(t,n->key);

        CHECK(i==0);
    }

    ghash_delete(t);
}

// test to generate collisions and increase test code coverage
TEST(ghash, collision_test)
{
    int i;
    char str[256];
    int num=100;

    // Create a Hash Table with smaller entries
    GHash* t = ghash_new(-10, 0, GH_COPYKEYS, nullptr);

    CHECK(t != nullptr);

    // Add Nodes to the Hash Table
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        ghash_add(t, str, (void *)(str + (i+1)));
    }

    // try to add an existed entry
    snprintf(str, sizeof(str), "KeyWord%d",1);
    str[sizeof(str) - 1] = '\0';
    i = ghash_add(t, str, (void *)(str + (1)));
    CHECK(i == GHASH_INTABLE);

    // find those nodes
    for (i=num-1; i>=0; i--)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char* p = (char*)ghash_find(t, str);

        CHECK(p != nullptr);
        CHECK(p == (void *)(str + (i+1)));
    }

    // remove one node
    GHashNode* n = ghash_findfirst(t);
    if (n)
    {
        n = ghash_findnext(t);
        i = ghash_remove(t,n->key);

        CHECK(i==0);
    }

    // remove rest of nodes
    for ( n = ghash_findfirst(t); n; n = ghash_findnext(t) )
    {
        i = ghash_remove(t,n->key);

        CHECK(i==0);
    }

    ghash_delete(t);
}

TEST(ghash, userfree_test)
{
    char str[256];
    int i;

    // Create a small Hash Table with user free
    GHash* t = ghash_new(-5, 0, GH_COPYKEYS, myfree);
    // add 5 nodes
    for (i=0; i<5; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        char* p = (char*)snort_alloc(32);
        p[0] = (char)(i+1);
        p[1] = '\0';
        ghash_add(t, str, (void *)p);
    }

    // find those nodes
    for (i=0; i<5; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char *p = (char*)ghash_find(t, str);

        CHECK(p != nullptr);
        CHECK(p[0] == (i+1));
    }

    // generate a key not in the table
    snprintf(str, sizeof(str), "NotInTable");
    str[sizeof(str) - 1] = '\0';

    // it should not be found
    CHECK(ghash_find(t, str) == nullptr);
    
    // try to remove a node that is not in the table
    CHECK(ghash_remove(t, str) == GHASH_ERR);

    for ( GHashNode* n = ghash_findfirst(t); n; n = ghash_findnext(t) )
    {
        // user free should be called here, no memory leak should be detected
        i = ghash_remove(t,n->key);

        CHECK(i==0);
    }

    ghash_delete(t);
}

TEST(ghash, nullptr_test)
{
    CHECK(GHASH_ERR == ghash_add(nullptr, nullptr, nullptr));
    ghash_delete(nullptr);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
