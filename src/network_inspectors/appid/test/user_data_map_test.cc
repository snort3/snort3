//--------------------------------------------------------------------------
// Copyright (C) 2018-2026 Cisco and/or its affiliates. All rights reserved.
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

// user_data_map_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/thread.h"

#include "../user_data_map.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

static unsigned int appid_log_call_count = 0;
void appid_log(const snort::Packet*, unsigned char, char const*, ...) { appid_log_call_count++; }

SThreadType test_thread_type = SThreadType::STHREAD_TYPE_MAIN;

namespace snort
{
    SThreadType get_thread_type()
    {
        return test_thread_type;
    }
}

TEST_GROUP(user_data_map_test)
{
    UserDataMap* test_user_data_map;

    void setup() override
    {
        test_user_data_map = new UserDataMap();
        test_user_data_map->set_configuration_completed(false);
    }

    void teardown() override
    {
        test_user_data_map->set_configuration_completed(false);
        delete test_user_data_map;
    }
};

TEST(user_data_map_test, add_and_get_user_data)
{
    const std::string table = "test_table";
    const std::string key = "test_key";
    const std::string value = "test_value";

    bool added = test_user_data_map->add_user_data(table, key, value);
    CHECK_TRUE(added);

    const char* retrieved_value = test_user_data_map->get_user_data_value_str(table, key);
    STRCMP_EQUAL(value.c_str(), retrieved_value);
}

TEST(user_data_map_test, add_duplicate_key_without_override)
{
    appid_log_call_count = 0;
    const std::string table = "test_table";
    const std::string key = "test_key";
    const std::string value1 = "test_value1";
    const std::string value2 = "test_value2";

    bool first_add = test_user_data_map->add_user_data(table, key, value1);
    CHECK_TRUE(first_add);

    bool second_add = test_user_data_map->add_user_data(table, key, value2);
    CHECK_EQUAL(1, appid_log_call_count);
    CHECK_FALSE(second_add);

    auto get_value = test_user_data_map->get_user_data_value_str(table, key);
    STRCMP_EQUAL(get_value, value1.c_str());
}

TEST(user_data_map_test, add_duplicate_key_with_override)
{
    const std::string table = "test_table";
    const std::string key = "test_key";
    const std::string value1 = "test_value1";
    const std::string value2 = "test_value2";

    bool first_add = test_user_data_map->add_user_data(table, key, value1);
    CHECK_TRUE(first_add);

    bool second_add = test_user_data_map->add_user_data(table, key, value2, true);
    const char* retrieved_value = test_user_data_map->get_user_data_value_str(table, key);
    CHECK_TRUE(second_add);
    STRCMP_EQUAL(value2.c_str(), retrieved_value);
}

TEST(user_data_map_test, get_nonexistent_key)
{
    const std::string table = "test_table";
    const std::string key = "test_key";
    const std::string value = "test_value";

    test_user_data_map->add_user_data(table, key, value);

    const char* retrieved_value = test_user_data_map->get_user_data_value_str(table, "some_other_key");
    CHECK_TRUE(retrieved_value == nullptr);
}

TEST(user_data_map_test, get_from_nonexistent_table)
{
    const std::string table = "nonexistent_table";
    const std::string key = "test_key";

    const char* retrieved_value = test_user_data_map->get_user_data_value_str(table, key);
    CHECK_TRUE(retrieved_value == nullptr);
}

TEST(user_data_map_test, add_user_data_from_non_main_thread_before_configuration_completed)
{
    test_thread_type = SThreadType::STHREAD_TYPE_PACKET;
    appid_log_call_count = 0;

    const std::string table = "test_table";
    const std::string key = "test_key";
    const std::string value = "test_value";

    bool added = test_user_data_map->add_user_data(table, key, value);
    CHECK_FALSE(added);
    CHECK_EQUAL(0, appid_log_call_count);

    test_thread_type = SThreadType::STHREAD_TYPE_MAIN;
}

TEST(user_data_map_test, add_user_data_from_non_main_thread_after_configuration_completed)
{
    test_thread_type = SThreadType::STHREAD_TYPE_PACKET;
    appid_log_call_count = 0;

    const std::string table = "test_table";
    const std::string key = "test_key";
    const std::string value = "test_value";

    test_user_data_map->set_configuration_completed(true);
    bool added = test_user_data_map->add_user_data(table, key, value);
    CHECK_FALSE(added);
    CHECK_EQUAL(1, appid_log_call_count);

    test_thread_type = SThreadType::STHREAD_TYPE_MAIN;
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);

    return rc;
}
