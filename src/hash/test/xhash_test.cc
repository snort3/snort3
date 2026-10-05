//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <set>
#include <vector>

#include "hash/hash_defs.h"
#include "hash/hash_key_operations.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

// Stubs whose sole purpose is to make the test code link
static SnortConfig my_config;
THREAD_LOCAL SnortConfig* snort_conf = &my_config;

unsigned snort::get_instance_id() { return 0; }

DataBus::DataBus() = default;
DataBus::~DataBus() = default;

// run_flags is used indirectly from HashFnc class by calling SnortConfig::static_hash()
SnortConfig::SnortConfig(const char*) : daq_config(nullptr), thread_config(nullptr)
{ snort_conf->run_flags = 0;}

SnortConfig::~SnortConfig() = default;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

unsigned int get_random_seed()
{ return 3193; }
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

    const void* data = test_table->get_mru_user_data();
    CHECK(data == nullptr);

    for (unsigned i = 1; i <= 4; i++)
    {
        xhash_test_key xtk;
        xtk.key = 10 * i;
        int ret = test_table->insert(&xtk, nullptr);
        CHECK(ret == HASH_OK);
    }

    xhash_test_key xtk{};
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

    const HashNode* xhnode = test_table->find_node(&xtk);
    CHECK(!xhnode);

    delete test_table;
}

// No free node is available, verifies the LRU node is deleted
TEST(xhash, free_anr_lru_delete_tail_node_test)
{
    XHash* test_table = new XHash(3, sizeof(struct xhash_test_key), 1, 1040);
    CHECK(test_table);

    xhash_test_key xtk{};
    int ret = test_table->insert(&xtk, nullptr);
    CHECK(ret == HASH_OK);

    CHECK(test_table->delete_lru_node());

    const HashNode* xhnode = test_table->find_node(&xtk);
    CHECK(xhnode == nullptr);

    delete test_table;
}

// every node pinned: release_lru_node must evict nothing and leave the LRU
// intact, so an insert at capacity fails rather than dropping a pinned node
class all_pinned_xhash : public XHash
{
public:
    all_pinned_xhash(int rows, int keysize, int datasize, unsigned long memcap)
        : XHash(rows, keysize, datasize, memcap) { }

protected:
    bool is_node_recovery_ok(HashNode*) override
    { return false; }
};

TEST(xhash, release_lru_node_never_evicts_pinned)
{
    all_pinned_xhash* test_table = new all_pinned_xhash(4, sizeof(struct xhash_test_key), 0, 0);
    CHECK(test_table);
    test_table->set_max_nodes(4);

    for (int i = 1; i <= 4; i++)
    {
        xhash_test_key xtk { i };
        CHECK(test_table->insert(&xtk, nullptr) == HASH_OK);
    }
    CHECK(test_table->get_num_nodes() == 4);

    xhash_test_key ins { 99 };
    CHECK(test_table->insert(&ins, nullptr) == HASH_NOMEM);
    CHECK(test_table->get_num_nodes() == 4);

    xhash_test_key first { 1 };
    CHECK(test_table->find_node(&first) != nullptr);

    delete test_table;
}

class selective_pinned_xhash : public XHash
{
public:
    selective_pinned_xhash(int rows, int keysize, int datasize, unsigned long memcap)
        : XHash(rows, keysize, datasize, memcap) { }

    std::set<int> pinned;

protected:
    bool is_node_recovery_ok(HashNode* hnode) override
    { return pinned.find(((xhash_test_key*)hnode->key)->key) == pinned.end(); }
};

// a recoverable node sitting behind pinned nodes at the tail is reclaimed
TEST(xhash, release_lru_node_reclaims_recoverable_behind_pinned)
{
    selective_pinned_xhash* test_table =
        new selective_pinned_xhash(8, sizeof(struct xhash_test_key), 0, 0);
    CHECK(test_table);
    test_table->set_max_nodes(4);

    // insertion order 1..4: node 1 is the LRU tail; pin the two oldest
    test_table->pinned = { 1, 2 };
    for (int i = 1; i <= 4; i++)
    {
        xhash_test_key xtk { i };
        CHECK(test_table->insert(&xtk, nullptr) == HASH_OK);
    }
    CHECK(test_table->get_num_nodes() == 4);

    xhash_test_key ins { 5 };
    CHECK(test_table->insert(&ins, nullptr) == HASH_OK);
    CHECK(test_table->get_num_nodes() == 4);

    xhash_test_key n1 { 1 };
    xhash_test_key n2 { 2 };
    xhash_test_key n3 { 3 };
    xhash_test_key n5 { 5 };
    CHECK(test_table->find_node(&n1) != nullptr);
    CHECK(test_table->find_node(&n2) != nullptr);
    CHECK(test_table->find_node(&n3) == nullptr);
    CHECK(test_table->find_node(&n5) != nullptr);

    delete test_table;
}

// a recoverable node past the bounded window is not reached: the walk stops
// and the insert fails rather than scanning the whole list
TEST(xhash, release_lru_node_walk_is_bounded)
{
    const int cap = 80;
    selective_pinned_xhash* test_table =
        new selective_pinned_xhash(128, sizeof(struct xhash_test_key), 0, 0);
    CHECK(test_table);
    test_table->set_max_nodes(cap);

    // pin every node except the head (key cap), which is the furthest from the
    // tail; recovering it would require walking all cap nodes
    for (int i = 1; i < cap; i++)
        test_table->pinned.insert(i);

    for (int i = 1; i <= cap; i++)
    {
        xhash_test_key xtk { i };
        CHECK(test_table->insert(&xtk, nullptr) == HASH_OK);
    }
    CHECK(test_table->get_num_nodes() == cap);

    xhash_test_key ins { 999 };
    CHECK(test_table->insert(&ins, nullptr) == HASH_NOMEM);
    CHECK(test_table->get_num_nodes() == cap);

    delete test_table;
}

static const unsigned collapsing_scales[] =
{ 131071, 524287, 1310719, 1966079, 4194301 };

struct forced_scale : public HashKeyOperations
{
    forced_scale(unsigned s, unsigned h) : HashKeyOperations(1024)
    {
        seed = 3191;
        scale = s;
        hardener = h;
    }

    unsigned unfinalized(const unsigned char* key, int len) const
    {
        unsigned hash = seed;

        while ( len-- )
        {
            hash *= scale;
            hash += *key++;
        }

        return hash ^ hardener;
    }
};

static unsigned rows_reached(const std::vector<unsigned>& indices, unsigned nrows)
{
    std::vector<bool> seen(nrows, false);
    unsigned reached = 0;

    for ( unsigned index : indices )
        if ( !seen[index] )
        {
            seen[index] = true;
            ++reached;
        }

    return reached;
}

static const unsigned hardeners[] = { 133824503, 0x9e3779b9, 3, 0x00010001, 0 };

TEST_GROUP(hash_row_distribution)
{ };

TEST(hash_row_distribution, row_stays_in_range)
{
    const unsigned sizes[] = { 1, 2, 64, 1021, 1u << 21 };
    forced_scale hash_ops(719, 133824503);

    for ( unsigned nrows : sizes )
        for ( unsigned i = 0; i < 10000; ++i )
            CHECK(hash_ops.get_row(i * 2654435761u + 17, nrows) < nrows);
}

TEST(hash_row_distribution, row_takes_the_top_bits_on_powers_of_two)
{
    forced_scale hash_ops(719, 133824503);

    for ( unsigned k = 1; k <= 22; ++k )
        for ( unsigned i = 0; i < 1000; ++i )
        {
            const unsigned hashkey = i * 2246822519u + 5;
            CHECK(hash_ops.get_row(hashkey, 1u << k) == (hashkey >> (32 - k)));
        }
}

TEST(hash_row_distribution, row_reaches_every_row_when_nrows_is_not_a_power_of_two)
{
    const unsigned nrows = 1021;
    forced_scale hash_ops(719, 133824503);
    std::vector<unsigned> masked, reduced;

    for ( unsigned i = 0; i < 200000; ++i )
    {
        const unsigned hashkey = i * 2654435761u;
        masked.push_back(hashkey & (nrows - 1));
        reduced.push_back(hash_ops.get_row(hashkey, nrows));
    }

    CHECK(rows_reached(masked, nrows) < nrows / 2);
    CHECK(rows_reached(reduced, nrows) == nrows);
}

TEST(hash_row_distribution, do_hash_spreads_a_collapsed_scale)
{
    const unsigned nrows = 1u << 21;
    const unsigned keys = 20000;

    for ( unsigned scale : collapsing_scales )
        for ( unsigned hardener : hardeners )
        {
            forced_scale hash_ops(scale, hardener);
            std::vector<unsigned> masked, reduced;

            for ( unsigned i = 0; i < keys; ++i )
            {
                const unsigned key = i * 7919;
                const auto bytes = reinterpret_cast<const unsigned char*>(&key);

                masked.push_back(hash_ops.unfinalized(bytes, sizeof(key)) & (nrows - 1));
                reduced.push_back(
                    hash_ops.get_row(hash_ops.do_hash(bytes, sizeof(key)), nrows));
            }

            CHECK(rows_reached(masked, nrows) < keys / 2);
            CHECK(rows_reached(reduced, nrows) > keys - keys / 4);
        }
}

TEST(hash_row_distribution, the_hardener_moves_the_rows)
{
    const unsigned nrows = 1u << 16;
    const unsigned keys = 4096;
    std::set<unsigned> first_rows;

    for ( unsigned hardener : hardeners )
    {
        forced_scale hash_ops(719, hardener);
        unsigned same = 0;

        for ( unsigned i = 0; i < keys; ++i )
        {
            const unsigned key = i * 7919;
            const auto bytes = reinterpret_cast<const unsigned char*>(&key);
            const unsigned row =
                hash_ops.get_row(hash_ops.do_hash(bytes, sizeof(key)), nrows);

            if ( i == 0 )
                first_rows.insert(row);
            if ( row == i % nrows )
                ++same;
        }

        CHECK(same < keys / 8);
    }

    CHECK(first_rows.size() == sizeof(hardeners) / sizeof(hardeners[0]));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
