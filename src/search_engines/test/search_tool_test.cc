//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// search_tool_test.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//  Change private to public to give access to private members.
#define private public
#include "search_engines/search_tool.h"
#undef private

#include <cstring>

#include "detection/fp_config.h"
#include "framework/base_api.h"
#include "framework/mpse_batch.h"
#include "main/snort_config.h"
#include "managers/mpse_manager.h"

#include "mpse_test_stubs.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

const MpseApi* get_test_api()
{ return (const MpseApi*) se_ac_full; }

//-------------------------------------------------------------------------
// ac_full tests
//-------------------------------------------------------------------------

TEST_GROUP(search_tool_full)
{
    SearchTool* stool;  // cppcheck-suppress variableScope

    void setup() override
    {
        stool = new SearchTool;
        CHECK(stool->mpsegrp->normal_mpse);

        int pattern_id = 1;
        stool->add("the", 3, pattern_id);
        CHECK(stool->max_len == 3);

        pattern_id = 77;
        stool->add("tuba", 4, pattern_id);
        CHECK(stool->max_len == 4);

        pattern_id = 78;
        stool->add("uba", 3, pattern_id);
        CHECK(stool->max_len == 4);

        pattern_id = 2112;
        stool->add("away", 4, pattern_id);
        CHECK(stool->max_len == 4);

        pattern_id = 1000;
        stool->add("nothere", 7, pattern_id);
        CHECK(stool->max_len == 7);

        stool->prep();

    }
    void teardown() override
    {
        delete stool;
    }
};

TEST(search_tool_full, search)
{
    //                     0         1         2         3
    //                     0123456789012345678901234567890
    const char* datastr = "the tuba ran away with the the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 78, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 1, 30 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;

    int result = stool->find(datastr, strlen(datastr), check_mpse_match);

    CHECK(result == 5);
    CHECK(s_found == 5);
}

TEST(search_tool_full, search_all)
{
    //                     0         1         2         3
    //                     01234567890123456789012345678901234
    const char* datastr = "the the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 1, 7 },
        { 78, 12 },
        { 77, 12 },
        { 2112, 21 },
        { 1, 30 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;

    int result = stool->find_all(datastr, strlen(datastr), check_mpse_match);

    CHECK(result == 6);
    CHECK(s_found == 6);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    ((MpseApi*)se_ac_full)->init();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

