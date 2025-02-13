//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// hash_lru_cache_test.cc author davis mcpherson <davmcphe@cisco.com>
// unit tests for the HashLruCache class

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../hash_lru_cache.h"

#include "../../utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

HashLruCache* lru = nullptr;

TEST_GROUP(hash_lru_cache)
{
    void setup() override
    {
        lru = new HashLruCache;
        CHECK(lru);
    }

    void teardown() override
    {
        unsigned node_id = 1;
        HashNode* node = lru->remove_lru_node();
        while( node )
        {
            CHECK(*(unsigned*)node->data == node_id);
            unsigned* data = (unsigned *)lru->get_mru_user_data();
            if ( data )
                CHECK(*data == 5);
            data = (unsigned *)lru->get_lru_user_data();
            if ( data )
                CHECK(*data == node_id + 1);
            ++node_id;
            delete (unsigned*)node->data;
            snort_free(node);
            node = lru->remove_lru_node();
        }

        delete lru;
    }
};

TEST(hash_lru_cache, create_hash_lru_cache_test)
{
    CHECK(!lru->get_next_lru_node());
    CHECK(!lru->get_current_node());
    CHECK(!lru->get_mru_user_data());
    CHECK(!lru->get_lru_user_data());
    CHECK(!lru->remove_lru_node());
}

TEST(hash_lru_cache, hash_lru_cache_insert_test)
{
    HashNode* node;
    for (unsigned i = 0; i < 5; i++)
    {
        node = (HashNode*)snort_calloc(sizeof(HashNode));
        unsigned* data = new unsigned;
        *data = i + 1;
        node->data = data;
        lru->insert(node);
        CHECK(*((unsigned *)lru->get_mru_user_data()) == i + 1);
        CHECK(*((unsigned *)lru->get_lru_user_data()) == 1);
    }

    for (unsigned i = 0; i < 5; i++)
    {
        node = lru->get_lru_node();
        CHECK(node);
        CHECK(*((unsigned*)node->data) == i + 1);
        lru->touch(node);
        CHECK(*((unsigned *)lru->get_mru_user_data()) == i + 1);
        CHECK(*((unsigned *)lru->get_lru_user_data()) == ((i + 1) % 5) + 1);
    }

    node = lru->get_lru_node();
    CHECK(node);
    CHECK(*((unsigned*)node->data) == 1);
}

TEST(hash_lru_cache, hash_lru_cache_browse_test)
{
    HashNode* node;
    for (unsigned i = 0; i < 5; i++)
    {
        node = (HashNode*)snort_calloc(sizeof(HashNode));
        unsigned* data = new unsigned;
        *data = i + 1;
        node->data = data;
        lru->insert(node);
    }

    for (unsigned i = 0; i < 5; i++)
    {
        node = lru->get_lru_node();
        CHECK(node);
        CHECK(*((unsigned*)node->data) == (i + 1));
        lru->touch(node);
    }

    node = lru->get_lru_node();
    unsigned i = 1;
    while( node )
    {
        CHECK(*(unsigned*)node->data == i);
        CHECK(*(unsigned*)lru->get_current_node()->data == i);
        node = lru->get_next_lru_node();
        ++i;
    }
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
