//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

struct xhash_test_key
{
    int key;
};

TEST_GROUP(xhash)
{ };

//  Test create a hash table, add nodes, find and delete.
TEST(xhash, create_xhash_test)
{
    XHash* test_table = xhash_new(4, sizeof(struct xhash_test_key),
                                  0, 0, 0, nullptr, nullptr, 0);
    CHECK(test_table->keysize == sizeof(struct xhash_test_key));
    xhash_delete(test_table);
}

// Test verifies if free_anr_lru_function() throws error on invalid table
TEST(xhash, free_anr_lru_invalid_test)
{
    int ret = xhash_free_anr_lru(nullptr);
    CHECK(ret == XHASH_ERR); 
}

// Create a free node in xhash and verifies if xhash_free_anr_lru() deletes it 
TEST(xhash, free_anr_lru_delete_free_node_test)
{
    XHash* test_table = xhash_new(3, sizeof(struct xhash_test_key),
                                  1, 1040, 0, nullptr, nullptr, 1);
    xhash_test_key xtk;
    xtk.key = 10;
    int ret = xhash_add(test_table, &xtk, nullptr);
    CHECK(ret == XHASH_OK);

    XHashNode *xnode = xhash_get_node(test_table, &xtk);
    CHECK(xnode != nullptr);

    ret = xhash_free_node(test_table, xnode);
    CHECK(ret == XHASH_OK);

    ret = xhash_free_anr_lru(test_table);
    CHECK(ret == XHASH_OK); 

    XHashNode* xhnode = xhash_find_node(test_table, &xtk);
    CHECK(xhnode == nullptr);
    xhash_delete(test_table);
}

// No free node is available, verifies if xhash_free_anr_lru() deletes the last node
TEST(xhash, free_anr_lru_delete_tail_node_test)
{
    XHash* test_table = xhash_new(3, sizeof(struct xhash_test_key),
                                  1, 1040, 0, nullptr, nullptr, 1);
    xhash_test_key xtk;
    int ret = xhash_add(test_table, &xtk, nullptr);
    CHECK(ret == XHASH_OK);

    XHashNode* orig_gtail = test_table->gtail;
    ret = xhash_free_anr_lru(test_table);
    CHECK(ret == XHASH_OK);
    CHECK(orig_gtail != test_table->gtail);

    xhash_delete(test_table);
}

// No free node is available [recycle is not enabled], verifies if last node is deleted
TEST(xhash, free_anr_lru_usr_free_delete_tail_node_test)
{
    XHash* test_table = xhash_new(3, sizeof(struct xhash_test_key),
                                  1, 1040, 0, nullptr, nullptr, 0);
    xhash_test_key xtk;
    int ret = xhash_add(test_table, &xtk, nullptr);
    CHECK(ret == XHASH_OK);

    XHashNode* orig_gtail = test_table->gtail;
    ret = xhash_free_anr_lru(test_table);
    CHECK(ret == XHASH_OK);
    CHECK(orig_gtail != test_table->gtail);
    xhash_delete(test_table);
}

// if new memcap is same as old memcap, do nothing
TEST(xhash, change_memcap_same_memcap_test)
{
    XHash* test_table = xhash_new(5, sizeof(struct xhash_test_key),
                                  0, 80, 0, nullptr, nullptr, 1);
    unsigned max_work = 0;
    int ret = xhash_change_memcap(test_table, 80, &max_work);
    CHECK(ret == XHASH_OK);
    CHECK(test_table->mc.memcap == 80);
    xhash_delete(test_table);
}

// if new memcap is more than old memcap, only change the memcap
TEST(xhash, change_memcap_more_memcap_test)
{
    XHash* test_table = xhash_new(5, sizeof(struct xhash_test_key),
                                  0, 80, 0, nullptr, nullptr, 1);

    unsigned max_work = 0;
    int ret = xhash_change_memcap(test_table, 100, &max_work);
    CHECK(ret == XHASH_OK);
    CHECK(test_table->mc.memcap == 100);
    xhash_delete(test_table);
}

// IF new memcap is is less than overhead bytes, throw an error
TEST(xhash, change_memcap_less_than_overhead_memcap_test)
{
    XHash* test_table = xhash_new(5, sizeof(struct xhash_test_key),
                                  0, 80, 0, nullptr, nullptr, 1);

    unsigned max_work = 0;
    int ret = xhash_change_memcap(test_table, test_table->overhead_bytes-1, &max_work);
    CHECK(ret == XHASH_ERR);
    CHECK(test_table->mc.memcap == 80);
    xhash_delete(test_table);
}

//if new memcap is less than used memcap, do the pruning
TEST(xhash, xhash_change_memcap_less_than_used_test)
{
    XHash* test_table = xhash_new(3, sizeof(struct xhash_test_key),
                                  1, 1040, 0, nullptr, nullptr, 1);
    xhash_test_key xtk[2];
    int ret = xhash_add(test_table, &xtk[0], nullptr);
    CHECK(ret == XHASH_OK);

    xtk[1].key = 100;
    ret = xhash_add(test_table, &xtk[1], nullptr);
    CHECK(ret == XHASH_OK);

    unsigned max_work = 0;
    unsigned new_memcap = test_table->mc.memused-1;
    ret = xhash_change_memcap(test_table, new_memcap, &max_work);  
    CHECK(ret == XHASH_OK);
    CHECK(test_table->mc.memcap == new_memcap);
    xhash_delete(test_table);
}

// new memcap is less than old memcap and cannot prune
TEST(xhash, xhash_change_memcap_nofree_nodes_test)
{
    XHash* test_table = xhash_new(3, sizeof(struct xhash_test_key),
                                  1, 1040, 0, nullptr, nullptr, 0);
    xhash_test_key xtk;

    int ret = xhash_add(test_table, &xtk, nullptr);
    CHECK(ret == XHASH_OK);
    unsigned new_memcap = test_table->mc.memused-1;


    unsigned max_work = 0;
    test_table->gtail = nullptr;
    ret = xhash_change_memcap(test_table, new_memcap, &max_work);
    CHECK(ret == XHASH_NOMEM);
    xhash_delete(test_table);
}

// new memcap is less than old memcap and max_work is than needed
TEST(xhash, xhash_change_memcap_less_max_work_test)
{
    XHash* test_table = xhash_new(3, sizeof(struct xhash_test_key),
                                  142, 1040, 0, nullptr, nullptr, 0);
    xhash_test_key xtk;

    int ret = xhash_add(test_table, &xtk, nullptr);
    CHECK(ret == XHASH_OK);
    unsigned new_memcap = test_table->mc.memused-1;

    xhash_test_key xtk1;
    xtk1.key = 100;
    ret = xhash_add(test_table, &xtk1, nullptr);
    CHECK(ret == XHASH_OK);

    unsigned max_work = 1;
    ret = xhash_change_memcap(test_table, new_memcap, &max_work);
    CHECK(ret == XHASH_PENDING);
    CHECK(max_work == 0);
    xhash_delete(test_table);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
