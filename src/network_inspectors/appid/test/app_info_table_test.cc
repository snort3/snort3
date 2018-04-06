//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// appid_info_table_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/app_info_table.cc"

#include <string>
#include <map>
#include "protocols/protocol_ids.h"
#include "appid_mock_inspector.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}

void ErrorMessage(const char*,...) { }
void WarningMessage(const char*,...) { }
void LogMessage(const char*,...) { }
void ParseWarning(WarningGroup, const char*, ...) { }

const char* UT_TEST_APP_NAME_001 = "ut_app_001";
const char* UT_TEST_APP_NAME_002 = "ut_app_002";
const char* UT_TEST_APP_NAME_TOO_LONG =
    "ut_app78901234567890123456789012345678901234567890123456789012345";

#define UT_TEST_APP_ID_001 111
#define UT_TEST_APP_ID_002 222

AppInfoManager& app_info_mgr = AppInfoManager::get_instance();
std::unordered_map<AppId, AppIdPegCounts>* appid_peg_counts;

AppInfoTableEntry* add_static_entry(AppId id, const char* name)
{
    AppInfoTableEntry* entry = new AppInfoTableEntry(id, snort_strdup(name));
    app_info_table[id] = entry;
    bool rc = add_entry_to_app_info_name_table(entry->app_name_key, entry);
    CHECK_TRUE(rc);
    return entry;
}

TEST_GROUP(app_info_table)
{
    void setup()
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    }

    void teardown()
    {
        app_info_mgr.cleanup_appid_info_table();
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(app_info_table, get_app_name)
{
    AppInfoTableEntry* entry = add_static_entry(UT_TEST_APP_ID_001, UT_TEST_APP_NAME_001);
    CHECK_TRUE(entry);
    entry = app_info_mgr.add_dynamic_app_entry(UT_TEST_APP_NAME_002);
    CHECK_TRUE(entry);
    const char* app_name = app_info_mgr.get_app_name(UT_TEST_APP_ID_001);
    STRCMP_EQUAL(app_name, UT_TEST_APP_NAME_001);
}

TEST(app_info_table, dump_app_info_table)
{
    AppInfoTableEntry* entry = add_static_entry(UT_TEST_APP_ID_001, UT_TEST_APP_NAME_001);
    CHECK_TRUE(entry);
    entry = app_info_mgr.add_dynamic_app_entry(UT_TEST_APP_NAME_002);
    CHECK_TRUE(entry);
    app_info_mgr.dump_app_info_table();
}

TEST(app_info_table, add_dynamic_app_entry)
{
    AppInfoTableEntry* entry = app_info_mgr.add_dynamic_app_entry(nullptr);
    CHECK_TRUE(!entry);
    entry = app_info_mgr.add_dynamic_app_entry(UT_TEST_APP_NAME_TOO_LONG);
    CHECK_TRUE(!entry);
    entry = app_info_mgr.add_dynamic_app_entry(UT_TEST_APP_NAME_002);
    CHECK_TRUE(entry);
    CHECK_TRUE(entry->appId == SF_APPID_DYNAMIC_MIN);
    entry = app_info_mgr.get_app_info_entry(entry->appId);
    CHECK_TRUE(entry);
    CHECK_TRUE(entry->appId == SF_APPID_DYNAMIC_MIN);
}

TEST(app_info_table, duplicate_app_info_entry)
{
    AppInfoTableEntry* entry = add_static_entry(UT_TEST_APP_ID_001, UT_TEST_APP_NAME_001);
    bool rc = add_entry_to_app_info_name_table(entry->app_name_key, entry);
    CHECK_TRUE(!rc);
}

TEST(app_info_table, get_priority)
{
    AppInfoTableEntry* entry = add_static_entry(UT_TEST_APP_ID_001, UT_TEST_APP_NAME_001);
    CHECK_TRUE(entry);
    unsigned priority = app_info_mgr.get_priority(UT_TEST_APP_ID_001);
    CHECK_TRUE(priority == APP_PRIORITY_DEFAULT);
    priority = app_info_mgr.get_priority(UT_TEST_APP_ID_002);
    CHECK_TRUE(priority == 0);
}

TEST(app_info_table, get_static_app_info_entry)
{
    AppId appid = SF_APPID_CSD_MIN + 1;
    AppId mapped_id;

    mapped_id = get_static_app_info_entry(appid);
    CHECK_TRUE(mapped_id == (SF_APPID_BUILDIN_MAX + appid - SF_APPID_CSD_MIN));
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

