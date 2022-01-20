//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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

// xhash_test.cc author Pratik Shinde <pshinde2@cisco.com>
// unit tests for xhash utility functions

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/xhash.h"

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

struct xhash_test_key
{
    int key;
};

TEST_GROUP(xhash)
{ };

//  Test create a hash table, add nodes, find and delete.
TEST(xhash, create_xhash_test)
{
    XHash* test_table = new XHash(4, sizeof(struct xhash_test_key), 0, 0);
    CHECK(test_table);

    void* data = test_table->get_mru_user_data();
    CHECK(data == nullptr);

    for (unsigned i = 1; i <= 4; i++)
    {
        xhash_test_key xtk;
        xtk.key = 10 * i;
        int ret = test_table->insert(&xtk, nullptr);
        CHECK(ret == HASH_OK);
    }

    xhash_test_key xtk;
    xtk.key = 10;
    HashNode* xnode = test_table->find_node(&xtk);
    CHECK(xnode != nullptr);
    int ret = test_table->release_node(xnode);
    CHECK(ret == HASH_OK);

    delete test_table;
}

// Create a free node in xhash and verifies if xhash_free_anr_lru() deletes it
TEST(xhash, free_anr_lru_delete_free_node_test)
{
    XHash* test_table = new XHash(3, sizeof(struct xhash_test_key), 1, 1040);
    CHECK(test_table);

    xhash_test_key xtk;
    xtk.key = 10;
    int ret = test_table->insert(&xtk, nullptr);
    CHECK(ret == HASH_OK);

     HashNode* xnode = test_table->find_node(&xtk);
    CHECK(xnode);

    ret = test_table->release_node(xnode);
    CHECK(ret == HASH_OK);

    ret = test_table->delete_lru_node();
    CHECK(ret == HASH_OK);

    HashNode* xhnode = test_table->find_node(&xtk);
    CHECK(!xhnode);

    delete test_table;
}

// No free node is available, verifies the LRU node is deleted
TEST(xhash, free_anr_lru_delete_tail_node_test)
{
    XHash* test_table = new XHash(3, sizeof(struct xhash_test_key), 1, 1040);
    CHECK(test_table);

    xhash_test_key xtk;
    int ret = test_table->insert(&xtk, nullptr);
    CHECK(ret == HASH_OK);

    CHECK(test_table->delete_lru_node());

    HashNode* xhnode = test_table->find_node(&xtk);
    CHECK(xhnode == nullptr);

    delete test_table;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
