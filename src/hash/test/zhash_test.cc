//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// zhash_test.cc author davis mcpherson <davmcphe@cisco.com>
// unit tests for the HashLruCache class

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "../zhash.h"
#include "../hash_key_operations.h"

#include "flow/flow_key.h"
#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
unsigned FlowHashKeyOps::do_hash(const unsigned char* k, int len)
{
    unsigned hash = seed;
    while ( len )
    {
        hash *= scale;
        hash += *k++;
        len--;
    }
    return hash ^ hardener;
}

bool FlowHashKeyOps::key_compare(const void* k1, const void* k2, size_t len)
{
    if ( memcmp(k1, k2, len ) == 0 )
        return true;
    else
        return false;
}
}

// Stubs whose sole purpose is to make the test code link
static SnortConfig my_config;
THREAD_LOCAL SnortConfig *snort_conf = &my_config;

DataBus::DataBus() = default;
DataBus::~DataBus() = default;

// run_flags is used indirectly from HashFnc class by calling SnortConfig::static_hash()
SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{ snort_conf->run_flags = 0;}

SnortConfig::~SnortConfig() = default;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

const unsigned ZHASH_ROWS = 50;
const unsigned ZHASH_KEY_SIZE = 100;
const unsigned MAX_ZHASH_NODES = 100;
char key_buf[ZHASH_KEY_SIZE];

ZHash* zh = nullptr;

TEST_GROUP(zhash)
{
    void setup() override
    {
        zh = new ZHash(ZHASH_ROWS, ZHASH_KEY_SIZE);
        CHECK(zh);

        memset(key_buf, '\0', ZHASH_KEY_SIZE);
    }

    void teardown() override
    {
        delete zh;
    }
};

TEST(zhash, create_zhash_test)
{
    for (unsigned i = 0; i < MAX_ZHASH_NODES; i++ )
    {
        unsigned* data;
        data = (unsigned*)snort_calloc(sizeof(unsigned));
        *data = 0;
        zh->push(data);
    }

    UNSIGNED_LONGS_EQUAL(0, zh->get_num_nodes());
    UNSIGNED_LONGS_EQUAL(MAX_ZHASH_NODES, zh->get_num_free_nodes());

    std::string key_prefix = "foo";
    for (unsigned i = 0; i < MAX_ZHASH_NODES; i++ )
    {
        std::string key;
        key = key_prefix + std::to_string(i + 1);
        memcpy(key_buf, key.c_str(), key.size());
        unsigned* data = (unsigned*)zh->get(key_buf);
        CHECK(*data == 0);
        *data = i + 1;
    }

    UNSIGNED_LONGS_EQUAL(MAX_ZHASH_NODES, zh->get_num_nodes());
    UNSIGNED_LONGS_EQUAL(0, zh->get_num_free_nodes());

    unsigned nodes_walked = 0;
    unsigned* data = (unsigned*)zh->lru_first();
    while ( data )
    {
        CHECK(*data == ++nodes_walked);
        data = (unsigned*)zh->lru_next();
    }

    CHECK(nodes_walked == MAX_ZHASH_NODES);

    data = (unsigned*)zh->lru_first();
    CHECK(*data == 1);
    data = (unsigned*)zh->remove();
    CHECK(*data == 1);
    snort_free(data);
    data = (unsigned*)zh->lru_current();
    CHECK(*data == 2);
    data = (unsigned*)zh->lru_first();
    CHECK(*data == 2);

    for (unsigned i = 1; i < MAX_ZHASH_NODES; i++ )
     {
        data = (unsigned*)zh->remove();
        CHECK(*data == (i + 1));
        snort_free(data);
     }
}

TEST(zhash, zhash_pop_test)
{
    unsigned* pop_data = (unsigned*)zh->pop();
    CHECK_TEXT(nullptr == pop_data, "Empty pop should return nullptr");
    unsigned* data = (unsigned*)snort_calloc(sizeof(unsigned));
    zh->push(data);
    pop_data = (unsigned*)zh->pop();
    CHECK_TEXT(pop_data == data, "Pop from free list should return pushed data");
    snort_free(pop_data);
    pop_data = (unsigned*)zh->pop();
    CHECK_TEXT(nullptr == pop_data, "Pop after pop should return nullptr");
}

TEST(zhash, zhash_get_test)
{
    unsigned* data = (unsigned*)snort_calloc(sizeof(unsigned));
    zh->push(data);
    key_buf[0] = 'a';
    unsigned* get_data = (unsigned*)zh->get(key_buf);
    CHECK_TEXT(get_data == data, "Get should return pushed data");
    get_data = (unsigned*)zh->get(key_buf);
    CHECK_TEXT(get_data == data, "Second get should return data");
    key_buf[0] = 'b';
    get_data = (unsigned*)zh->get(key_buf);
    CHECK_TEXT(nullptr == get_data, "Get with nonexistent key should return nullptr");
    get_data = (unsigned*)zh->lru_first();
    CHECK_TEXT(data == get_data, "Lru first should return data");
    get_data = (unsigned*)zh->remove();
    CHECK_TEXT(get_data == data, "Remove node should return data");
    snort_free(get_data);
}

TEST(zhash, zhash_lru_test)
{
    unsigned* data1 = (unsigned*)snort_calloc(sizeof(unsigned));
    zh->push(data1);
    key_buf[0] = '1';
    unsigned* get_data = (unsigned*)zh->get(key_buf);
    CHECK_TEXT(get_data == data1, "Get should return pushed data1");
    unsigned* data2 = (unsigned*)snort_calloc(sizeof(unsigned));
    zh->push(data2);
    key_buf[0] = '2';
    get_data = (unsigned*)zh->get(key_buf);
    CHECK_TEXT(get_data == data2, "Get should return pushed data2");

    get_data = (unsigned*)zh->lru_first();
    CHECK_TEXT(get_data == data1, "Lru first should return data1");

    zh->lru_touch();
    get_data = (unsigned*)zh->lru_first();
    CHECK_TEXT(get_data == data2, "Lru first should return data2 after touch");
    get_data = (unsigned*)zh->remove();
    CHECK_TEXT(get_data == data2, "Remove node should return data2");
    snort_free(get_data);

    get_data = (unsigned*)zh->lru_first();
    CHECK_TEXT(get_data == data1, "Lru first should return data1");
    get_data = (unsigned*)zh->remove();
    CHECK_TEXT(get_data == data1, "Remove node should return data1");
    snort_free(get_data);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
