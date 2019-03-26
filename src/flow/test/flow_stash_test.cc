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

// flow_stash_test.cc author Shravan Rangaraju <shrarang@cisco.com>

#include <string>

#include "flow/flow_stash.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace std;

class TestStashObject : public StashGenericObject
{
public:
    TestStashObject(int type) : StashGenericObject(type)
    {

    }
};

TEST_GROUP(stash_tests)
{

};

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
    TestStashObject *test_object = new TestStashObject(111);

    stash.store("item_1", test_object);

    StashGenericObject *retrieved_object;
    CHECK(stash.get("item_1", retrieved_object));
    POINTERS_EQUAL(test_object, retrieved_object);
    CHECK_EQUAL(test_object->get_object_type(), ((TestStashObject*)retrieved_object)->get_object_type());
}

TEST(stash_tests, update_generic_object)
{
    FlowStash stash;
    TestStashObject *test_object = new TestStashObject(111);
    stash.store("item_1", test_object);

    TestStashObject *new_test_object = new TestStashObject(111);
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
    TestStashObject *test_object = new TestStashObject(111);

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
    CHECK_EQUAL(test_object->get_object_type(), ((TestStashObject*)retrieved_object)->get_object_type());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
