//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

// flow_stash_test.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "flow/flow_stash.h"
#include "pub_sub/stash_events.h"
#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace std;

template<class Type>
class DBConsumer : public DataHandler
{
public:

    static const char* STASH_EVENT;

    DBConsumer(const char* mod_name) : DataHandler(mod_name) {}

    void handle(DataEvent& e, Flow*) override
    {
        const StashEvent* se = static_cast<const StashEvent*>(&e);
        se->get_item()->get_val(value);
    }

    Type get_from_stash(FlowStash& stash)
    {
        stash.get(STASH_EVENT, value);
        return value;
    }

    Type get_value() const { return value; }

private:
    Type value;
};

template<class Type>
const char* DBConsumer<Type>::STASH_EVENT = "foo.stash.event";

static DataHandler* s_handler = nullptr;

void DataBus::subscribe(const PubKey&, unsigned, snort::DataHandler* h)
{ s_handler = h; }

void DataBus::publish(unsigned, unsigned evid, snort::DataEvent& e, snort::Flow* f)
{
    if ( s_handler and evid )
        s_handler->handle(e, f);
}

static SnortConfig snort_conf;

namespace snort
{
SnortConfig::SnortConfig(const SnortConfig* const, const char*) { }
SnortConfig::~SnortConfig() = default;
const SnortConfig* SnortConfig::get_conf() { return &snort_conf; }

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
}

TEST_GROUP(stash_tests)
{ };

// DataBus tests
TEST(stash_tests, data_bus_publish_test)
{
    typedef int32_t value_t;

    DBConsumer<value_t> c("foo");
    PubKey pub_key { };

    DataBus::subscribe(pub_key, 0, &c);

    FlowStash stash;
    value_t vin, vout;

    // stash/publish 10
    vin = 10;
    stash.store(DBConsumer<value_t>::STASH_EVENT, vin, 1, 1);
    vout = c.get_value();
    CHECK_EQUAL(vin, vout);

    // stash/publish 20, with the same key as before
    vin = 20;
    stash.store(DBConsumer<value_t>::STASH_EVENT, vin, 1, 1);
    vout = c.get_value();
    CHECK_EQUAL(vin, vout);

    // do we get some event that we're not listening to?
    value_t before = c.get_value();
    stash.store("bar.stash.event", 30);
    value_t after = c.get_value();
    CHECK_EQUAL(before, after);

    // do we still get our own STASH_EVENT from the stash, at a later time?
    vout = c.get_from_stash(stash);
    CHECK_EQUAL(vin, vout);
}

// Stash tests
TEST(stash_tests, new_int32_item)
{
    FlowStash stash;

    stash.store("item_1", 10);

    int32_t val;

    CHECK(stash.get("item_1", val));
    CHECK_EQUAL(val, 10);
}

TEST(stash_tests, update_int32_item)
{
    FlowStash stash;

    stash.store("item_1", 10);
    stash.store("item_1", 20);

    int32_t val;

    CHECK(stash.get("item_1", val));
    CHECK_EQUAL(val, 20);
}

TEST(stash_tests, new_uint32_item)
{
    FlowStash stash;

    stash.store("item_1", 10u);

    uint32_t val;

    CHECK(stash.get("item_1", val));
    CHECK_EQUAL(val, 10u);
}

TEST(stash_tests, update_uint32_item)
{
    FlowStash stash;

    stash.store("item_1", 10u);
    stash.store("item_1", 20u);

    uint32_t val;

    CHECK(stash.get("item_1", val));
    CHECK_EQUAL(val, 20u);
}

TEST(stash_tests, new_str_item_ref)
{
    FlowStash stash;

    stash.store("item_1", "value_1");

    string val;

    CHECK(stash.get("item_1", val));
    STRCMP_EQUAL(val.c_str(), "value_1");
}

TEST(stash_tests, new_str_item_ptr)
{
    FlowStash stash;

    stash.store("item_1", new string("value_1"));

    string val;

    CHECK(stash.get("item_1", val));
    STRCMP_EQUAL(val.c_str(), "value_1");
}

TEST(stash_tests, update_str_item)
{
    FlowStash stash;

    stash.store("item_1", "value_1");
    stash.store("item_1", new string("value_2"));

    string val;

    CHECK(stash.get("item_1", val));
    STRCMP_EQUAL(val.c_str(), "value_2");
}

TEST(stash_tests, non_existent_item)
{
    FlowStash stash;

    stash.store("item_1", 10);

    int32_t val;

    CHECK_FALSE(stash.get("item_2", val));
}

TEST(stash_tests, new_generic_object)
{
    FlowStash stash;
    StashGenericObject *test_object = new StashGenericObject(111);

    stash.store("item_1", test_object);

    StashGenericObject *retrieved_object;
    CHECK(stash.get("item_1", retrieved_object));
    POINTERS_EQUAL(test_object, retrieved_object);
    CHECK_EQUAL(test_object->get_object_type(), ((StashGenericObject*)retrieved_object)->get_object_type());
}

TEST(stash_tests, update_generic_object)
{
    FlowStash stash;
    StashGenericObject *test_object = new StashGenericObject(111);
    stash.store("item_1", test_object);

    StashGenericObject *new_test_object = new StashGenericObject(111);
    stash.store("item_1", new_test_object);

    StashGenericObject *retrieved_object;
    CHECK(stash.get("item_1", retrieved_object));
    POINTERS_EQUAL(new_test_object, retrieved_object);
}

TEST(stash_tests, non_existent_generic_object)
{
    FlowStash stash;
    StashGenericObject *retrieved_object;
    CHECK_FALSE(stash.get("item_1", retrieved_object));
}

TEST(stash_tests, mixed_items)
{
    FlowStash stash;
    StashGenericObject *test_object = new StashGenericObject(111);

    stash.store("item_1", 10);
    stash.store("item_2", "value_2");
    stash.store("item_3", 30);
    stash.store("item_4", test_object);

    int32_t int32_val;
    string str_val;

    CHECK(stash.get("item_1", int32_val));
    CHECK_EQUAL(int32_val, 10);
    CHECK(stash.get("item_2", str_val));
    STRCMP_EQUAL(str_val.c_str(), "value_2");
    CHECK(stash.get("item_3", int32_val));
    CHECK_EQUAL(int32_val, 30);

    StashGenericObject *retrieved_object;
    CHECK(stash.get("item_4", retrieved_object));
    POINTERS_EQUAL(test_object, retrieved_object);
    CHECK_EQUAL(test_object->get_object_type(), ((StashGenericObject*)retrieved_object)->get_object_type());
}

TEST(stash_tests, store_ip)
{
    FlowStash stash;
    SfIp ip;
    CHECK(ip.set("1.1.1.1") == SFIP_SUCCESS);

    // Disabled
    snort_conf.max_aux_ip = -1;
    CHECK_FALSE(stash.store(ip));

    // Enabled without stashing, no duplicate IP checking
    snort_conf.max_aux_ip = 0;
    CHECK_TRUE(stash.store(ip));
    CHECK_TRUE(stash.store(ip));

    // Enabled with FIFO stashing, duplicate IP checking
    snort_conf.max_aux_ip = 2;
    CHECK_TRUE(stash.store(ip));
    CHECK_FALSE(stash.store(ip));

    SfIp ip2;
    CHECK(ip2.set("1.1.1.2") == SFIP_SUCCESS);
    CHECK_TRUE(stash.store(ip2));
    CHECK_FALSE(stash.store(ip2));

    SfIp ip3;
    CHECK(ip3.set("1111::8888") == SFIP_SUCCESS);
    CHECK_TRUE(stash.store(ip3));
    CHECK_FALSE(stash.store(ip3));
    CHECK_FALSE(stash.store(ip2));
    CHECK_TRUE(stash.store(ip));
    CHECK_FALSE(stash.store(ip));
    CHECK_FALSE(stash.store(ip3));
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

