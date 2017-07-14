//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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

// sfg_hash_test.cc author Steven Baigal <sbaigal@cisco.com>
// unit tests for sfghash utility functions

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/sfghash.h"

#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

// Stubs whose sole purpose is to make the test code link
SnortConfig my_config;
THREAD_LOCAL SnortConfig *snort_conf = &my_config;
SnortConfig::SnortConfig() { snort_conf->run_flags = 0;} // run_flags is used indirectly from SFHASHFCN class by calling SnortConfig::static_hash()
SnortConfig::~SnortConfig() {}
// implement functions for virtual
FileVerdict FilePolicy::type_lookup(Flow* , FileContext* ) { return FILE_VERDICT_UNKNOWN;}
FileVerdict FilePolicy::type_lookup(Flow* , FileInfo* ) { return FILE_VERDICT_UNKNOWN;}
FileVerdict FilePolicy::signature_lookup(Flow* , FileContext* ) { return FILE_VERDICT_UNKNOWN;}
FileVerdict FilePolicy::signature_lookup(Flow* , FileInfo* ) { return FILE_VERDICT_UNKNOWN;}

FileIdentifier::~FileIdentifier() {}

// user free function
void myfree(void* p)
{
    snort_free(p);
}

TEST_GROUP(sfghash)
{
};

//  Test create a hash table, add nodes, find and delete.
TEST(sfghash, create_find_delete_test)
{
    int i;
    char str[256], *p;
    int num=100;

    // Create a Hash Table
    SFGHASH* t = sfghash_new(1000, 0, GH_COPYKEYS, nullptr);

    // Add Nodes to the Hash Table
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        sfghash_add(t, str, (void *)(str + (i+1)));
    }

    // find those nodes
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        p = (char*)sfghash_find(t, str);

        CHECK(p != nullptr);
        CHECK(p == (void *)(str + (i+1)));
    }

    for (SFGHASH_NODE* n = sfghash_findfirst(t); n; n = sfghash_findnext(t) )
    {
        i = sfghash_remove(t,n->key);

        CHECK(i==0);
    }

    sfghash_delete(t);
}

// test to generate collisions and increase test code coverage
TEST(sfghash, collision_test)
{
    int i;
    char str[256], * p;
    int num=100;

    // Create a Hash Table with smaller entries
    SFGHASH* t = sfghash_new(-10, 0, GH_COPYKEYS, nullptr);

    CHECK(t != nullptr);

    // Add Nodes to the Hash Table
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        sfghash_add(t, str, (void *)(str + (i+1)));
    }

    // try to add an existed entry
    snprintf(str, sizeof(str), "KeyWord%d",1);
    str[sizeof(str) - 1] = '\0';
    i = sfghash_add(t, str, (void *)(str + (1)));
    CHECK(i == SFGHASH_INTABLE);

    // find those nodes
    for (i=num-1; i>=0; i--)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        p = (char*)sfghash_find(t, str);

        CHECK(p != nullptr);
        CHECK(p == (void *)(str + (i+1)));
    }

    // remove one node
    SFGHASH_NODE* n = sfghash_findfirst(t);
    if (n)
    {
        n = sfghash_findnext(t);
        i = sfghash_remove(t,n->key);

        CHECK(i==0);
    }

    // remove rest of nodes
    for ( n = sfghash_findfirst(t); n; n = sfghash_findnext(t) )
    {
        i = sfghash_remove(t,n->key);

        CHECK(i==0);
    }

    sfghash_delete(t);
}

TEST(sfghash, userfree_test)
{
    char str[256];
    int i;

    // Create a small Hash Table with user free
    SFGHASH* t = sfghash_new(-5, 0, GH_COPYKEYS, myfree);
    // add 5 nodes
    for (i=0; i<5; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        char* p = (char*)snort_alloc(32);
        p[0] = (char)(i+1);
        p[1] = '\0';
        sfghash_add(t, str, (void *)p);
    }

    // find those nodes
    for (i=0; i<5; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char *p = (char*)sfghash_find(t, str);

        CHECK(p != nullptr);
        CHECK(p[0] == (i+1));
    }

    // generate a key not in the table
    snprintf(str, sizeof(str), "NotInTable");
    str[sizeof(str) - 1] = '\0';

    // it should not be found
    CHECK(sfghash_find(t, str) == nullptr);
    
    // try to remove a node that is not in the table
    CHECK(sfghash_remove(t, str) == SFGHASH_ERR);

    for ( SFGHASH_NODE* n = sfghash_findfirst(t); n; n = sfghash_findnext(t) )
    {
        // user free should be called here, no memory leak should be detected
        i = sfghash_remove(t,n->key);

        CHECK(i==0);
    }

    sfghash_delete(t);
}

TEST(sfghash, nullptr_test)
{
    CHECK(SFGHASH_ERR == sfghash_add(nullptr, nullptr, nullptr));
    sfghash_delete(nullptr);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
