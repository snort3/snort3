//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../appid_peg_counts.h"
#include "../appid_debug.h"
#include "../app_info_table.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static std::vector<std::string> log_texts;

namespace snort
{
void LogLabel(const char*, FILE*) {}
void LogText(const char* s, FILE*) { log_texts.emplace_back(s); }

char* snort_strdup(const char* str)
{
    char* dup = static_cast<char*>(malloc(strlen(str) + 1));
    strcpy(dup, str);
    return dup;
}
}

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
THREAD_LOCAL bool appid_trace_enabled = false;
void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

TEST_GROUP(appid_peg_counts_tests)
{
    void setup() override
    {
        log_texts.clear();
        AppIdPegCounts::init_peg_info();
    }

    void teardown() override
    {
        AppIdPegCounts::cleanup_pegs();
        AppIdPegCounts::cleanup_dynamic_sum();
        AppIdPegCounts::cleanup_peg_info();
        std::vector<std::string>().swap(log_texts);
    }
};

TEST(appid_peg_counts_tests, over_limit_app_ids_are_reported_as_unknown)
{
    for (unsigned i = 0; i <= SF_APPID_MAX; ++i)
        AppIdPegCounts::add_app_peg_info("app_" + std::to_string(i), static_cast<AppId>(i));

    AppIdPegCounts::init_pegs();
    AppIdPegCounts::inc_service_count(static_cast<AppId>(SF_APPID_MAX));
    AppIdPegCounts::sum_stats();
    AppIdPegCounts::print();

    bool found_unknown = false;
    bool found_over_limit_app = false;

    for (const auto& line : log_texts)
    {
        found_unknown = found_unknown or line.find("unknown") != std::string::npos;
        found_over_limit_app = found_over_limit_app or line.find("app_40000") != std::string::npos;
    }

    CHECK_TRUE(found_unknown);
    CHECK_FALSE(found_over_limit_app);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
