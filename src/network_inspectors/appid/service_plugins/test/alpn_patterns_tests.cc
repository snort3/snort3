//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
//
// alpn_patterns_tests.cc author Pranav Bhalerao <prbhaler@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_inspector.h"
#include "service_plugins/alpn_patterns.cc"
#include "service_alpn_patterns_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

static AlpnPatternMatchers* alpn_matcher = nullptr;
AlpnPattern alpn_pattern(APPID_UT_ID, "h3");

namespace snort
{
int SearchTool::find_all(const char* pattern, unsigned, MpseMatch, bool, void* data)
{
    if (strcmp(pattern, "h3") == 0)
        alpn_pattern_match(&alpn_pattern, nullptr, 0, data, nullptr);
    return 0;
}
}

Inspector* InspectorManager::get_inspector(char const*, bool, const snort::SnortConfig*)
{
    return nullptr;
}

AppIdContext* ctxt;
AppIdContext& AppIdInspector::get_ctxt() const { return *ctxt; }

TEST_GROUP(alpn_patterns_tests)
{
    void setup() override
    {
        alpn_matcher = new AlpnPatternMatchers();
    }
    void teardown() override
    {
        delete alpn_matcher;
    }
};


TEST(alpn_patterns_tests, alpn_pattern_match)
{
    AlpnPatternList data;
    AlpnPattern alpn1(APPID_UT_ID + 1, "h3");
    alpn_pattern_match(&alpn1, nullptr, 0, &data, nullptr);
    AlpnPattern* alpn = data.back();
    CHECK(alpn->app_id == alpn1.app_id);
    CHECK(alpn->pattern == alpn1.pattern);

    AlpnPattern alpn2(APPID_UT_ID + 2, "smb");
    alpn_pattern_match(&alpn2, nullptr, 0, &data, nullptr);
    alpn = data.back();
    CHECK(alpn->app_id == alpn2.app_id);
    CHECK(alpn->pattern == alpn2.pattern);
}

TEST(alpn_patterns_tests, match_alpn_pattern)
{
    // 1. pattern not present in pattern matcher list
    CHECK(alpn_matcher->match_alpn_pattern("smb") == 0);

    // 2. pattern present in pattern matcher list
    CHECK(alpn_matcher->match_alpn_pattern("h3") == APPID_UT_ID);
}

TEST(alpn_patterns_tests, add_alpn_pattern)
{
    // same alpn mapped to different appid
    alpn_matcher->add_alpn_pattern(APPID_UT_ID + 1, "h3", "custom_detector.lua");
    alpn_matcher->add_alpn_pattern(APPID_UT_ID + 2, "h3", "odp_detector.lua");

    CHECK(alpn_matcher->get_alpn_load_list().size() == 1);
    CHECK(alpn_matcher->get_alpn_load_list()[0]->app_id == APPID_UT_ID + 1);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

