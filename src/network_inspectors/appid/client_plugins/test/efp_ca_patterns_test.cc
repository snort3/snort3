//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// efp_ca_patterns_test.cc author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_plugins/efp_ca_patterns.cc"
#include "client_plugins_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

static EfpCaPatternMatchers* efp_matcher = nullptr;
EfpCaPattern efp_ca(APPID_UT_ID, "firefox", 90);

namespace snort
{
int SearchTool::find_all(const char* pattern, unsigned, MpseMatch, bool, void* data)
{
    if (strcmp(pattern, "firefox") == 0)
        efp_ca_pattern_match(&efp_ca, nullptr, 0, data, nullptr);
    return 0;
}
}

TEST_GROUP(efp_ca_patterns_tests)
{
    void setup() override
    {
        efp_matcher = new EfpCaPatternMatchers();
    }
    void teardown() override
    {
        delete efp_matcher;
    }
};


TEST(efp_ca_patterns_tests, efp_ca_pattern_match)
{
    EfpCaPatternList data;
    EfpCaPattern efp1(APPID_UT_ID + 1, "firefox", 80);
    efp_ca_pattern_match(&efp1, nullptr, 0, &data, nullptr);
    EfpCaPattern* efp = data.back();
    CHECK(efp->app_id == efp1.app_id);
    CHECK(efp->pattern == efp1.pattern);
    CHECK(efp->confidence == efp1.confidence);

    EfpCaPattern efp2(APPID_UT_ID + 2, "chrome", 95);
    efp_ca_pattern_match(&efp2, nullptr, 0, &data, nullptr);
    efp = data.back();
    CHECK(efp->app_id == efp2.app_id);
    CHECK(efp->pattern == efp2.pattern);
    CHECK(efp->confidence == efp2.confidence);
    CHECK(data.size() == 2);
}


TEST(efp_ca_patterns_tests, match_efp_ca_pattern)
{
    // 1. pattern not present in pattern matcher list
    CHECK(efp_matcher->match_efp_ca_pattern("chrome", 95) == 0);

    // 2. pattern matches, confidence doesn't match
    CHECK(efp_matcher->match_efp_ca_pattern("firefox", 60) == 0);

    // 3. pattern and confidence matches
    CHECK(efp_matcher->match_efp_ca_pattern("firefox", 90) == APPID_UT_ID);

    // 4. pattern matches, reported confidence > existing value
    CHECK(efp_matcher->match_efp_ca_pattern("firefox", 92) == APPID_UT_ID);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

