//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "main/thread_config.h"
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
{ return (const MpseApi*) se_hyperscan; }

//-------------------------------------------------------------------------
// hyperscan tests
//-------------------------------------------------------------------------

TEST_GROUP(search_tool_full)
{
    Module* mod = nullptr;
    SearchTool* stool;  // cppcheck-suppress variableScope
    const MpseApi* mpse_api = (const MpseApi*)se_hyperscan;

    void setup() override
    {
        mod = mpse_api->base.mod_ctor();    // cppcheck-suppress unreadVariable
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
        scratcher->cleanup(snort_conf);
        mpse_api->base.mod_dtor(mod);
    }
};

TEST(search_tool_full, search)
{
    //                     0         1         2         3
    //                     0123456789012345678901234567890
    const char* datastr = "the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 77, 8 },
        { 78, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;
    scratcher->setup(snort_conf);

    int result = stool->find(datastr, strlen(datastr), check_mpse_match);

    CHECK(result == 5);
    CHECK(s_found == 5);
}

TEST(search_tool_full, search_all)
{
    //                     0         1         2         3
    //                     0123456789012345678901234567890
    const char* datastr = "the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 77, 8 },
        { 78, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;
    scratcher->setup(snort_conf);

    int result = stool->find_all(datastr, strlen(datastr), check_mpse_match);

    CHECK(result == 5);
    CHECK(s_found == 5);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    ((MpseApi*)se_hyperscan)->init();
    // FIXIT-L There is currently no external way to fully release the memory from the static
    //   s_scratch vector in hyperscan.cc
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

