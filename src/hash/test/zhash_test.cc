//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// run_flags is used indirectly from HashFnc class by calling SnortConfig::static_hash()
SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{ snort_conf->run_flags = 0;}

SnortConfig::~SnortConfig() = default;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

const unsigned ZHASH_ROWS = 1000;
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

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
