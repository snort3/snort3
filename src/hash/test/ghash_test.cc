//--------------------------------------------------------------------------
// Copyright (C) 2017-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "hash/hash_defs.h"
#include "main/snort_config.h"
#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

// Stubs whose sole purpose is to make the test code link
static SnortConfig my_config;
THREAD_LOCAL SnortConfig* snort_conf = &my_config;

// run_flags is used indirectly from HashFnc class by calling SnortConfig::static_hash()
SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{ snort_conf->run_flags = 0;}

SnortConfig::~SnortConfig() = default;

const SnortConfig* SnortConfig::get_conf()
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
    GHash* t = new GHash(1000, 0, false, nullptr);

    // Add Nodes to the Hash Table
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        t->insert(str, (void *)(str + (i+1)));
    }

    // find those nodes
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char* p = (char*)t->find(str);

        CHECK(p != nullptr);
        CHECK(p == (void *)(str + (i+1)));
    }

    for (GHashNode* n = t->find_first(); n; n = t->find_next() )
    {
        i = t->remove(n->key);

        CHECK(i==0);
    }

    delete t;
}

// test to generate collisions and increase test code coverage
TEST(ghash, collision_test)
{
    int i;
    char str[256];
    int num=100;

    // Create a Hash Table with smaller entries
    GHash* t = new GHash(-10, 0, false, nullptr);

    // Add Nodes to the Hash Table
    for (i=0; i<num; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        t->insert(str, (void *)(str + (i+1)));
    }

    // try to add an existed entry
    snprintf(str, sizeof(str), "KeyWord%d",1);
    str[sizeof(str) - 1] = '\0';
    i = t->insert(str, (void *)(str + (1)));
    CHECK(i == HASH_INTABLE);

    // find those nodes
    for (i=num-1; i>=0; i--)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char* p = (char*)t->find(str);

        CHECK(p != nullptr);
        CHECK(p == (void *)(str + (i+1)));
    }

    // remove one node
    GHashNode* n = t->find_first();
    if (n)
    {
        n = t->find_next();
        i = t->remove(n->key);

        CHECK(i==0);
    }

    // remove rest of nodes
    for ( n = t->find_first(); n; n = t->find_next() )
    {
        i = t->remove(n->key);

        CHECK(i==0);
    }

    delete t;
}

TEST(ghash, userfree_test)
{
    char str[256];
    int i;

    // Create a small Hash Table with user free
    GHash* t = new GHash(-5, 0, false, myfree);
    // add 5 nodes
    for (i=0; i<5; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';
        char* p = (char*)snort_alloc(32);
        p[0] = (char)(i+1);
        p[1] = '\0';
        t->insert(str, (void *)p);
    }

    // find those nodes
    for (i=0; i<5; i++)
    {
        snprintf(str, sizeof(str), "KeyWord%d",i+1);
        str[sizeof(str) - 1] = '\0';

        char *p = (char*)t->find(str);

        CHECK(p != nullptr);
        CHECK(p[0] == (i+1));
    }

    // generate a key not in the table
    snprintf(str, sizeof(str), "NotInTable");
    str[sizeof(str) - 1] = '\0';

    // it should not be found
    CHECK(t->find(str) == nullptr);

    // try to remove a node that is not in the table
    CHECK(t->remove( str) == HASH_NOT_FOUND);

    for ( GHashNode* n = t->find_first(); n; n = t->find_next() )
    {
        // user free should be called here, no memory leak should be detected
        i = t->remove(n->key);

        CHECK(i==0);
    }

    delete t;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
