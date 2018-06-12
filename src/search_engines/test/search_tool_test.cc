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

// search_tool_test.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//  Change private to public to give access to private members.
#define private public
#include "search_engines/search_tool.h"
#undef private

#include <string.h>

#include "framework/base_api.h"
#include "framework/mpse.h"
#include "managers/mpse_manager.h"
#include "main/snort_config.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// base stuff
//-------------------------------------------------------------------------

namespace snort
{
SnortConfig s_conf;

THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

static std::vector<void *> s_state;

SnortConfig::SnortConfig(const SnortConfig* const)
{
    state = &s_state;
    num_slots = 1;
    fast_pattern_config = nullptr;
}

SnortConfig::~SnortConfig() = default;

SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

unsigned get_instance_id()
{ return 0; }

void LogValue(const char*, const char*, FILE*) { }
SO_PUBLIC void LogMessage(const char*, ...) { }
[[noreturn]] void FatalError(const char*,...) { exit(1); }
void LogCount(char const*, uint64_t, FILE*) { }
void LogStat(const char*, double, FILE*) { }

static void* s_tree = (void*)"tree";
static void* s_list = (void*)"list";

static MpseAgent s_agent =
{
    [](struct SnortConfig* sc, void*, void** ppt)
    {
        CHECK(sc == nullptr);
        *ppt = s_tree;
        return 0;
    },
    [](void*, void** ppl)
    {
        *ppl = s_list;
        return 0;
    },

    [](void*) { },
    [](void** ppt) { CHECK(*ppt == s_tree); },
    [](void** ppl) { CHECK(*ppl == s_list); }
};

Mpse::Mpse(const char*) { }

int Mpse::search(
    const unsigned char* T, int n, MpseMatch match,
    void* context, int* current_state)
{
    return _search(T, n, match, context, current_state);
}

int Mpse::search_all(
    const unsigned char* T, int n, MpseMatch match,
    void* context, int* current_state)
{
    return _search(T, n, match, context, current_state);
}
}

extern const BaseApi* se_ac_bnfa;
Mpse* mpse = nullptr;

Mpse* MpseManager::get_search_engine(const char *type)
{
    assert(!strcmp(type, "ac_bnfa"));

    const MpseApi* mpse_api = (MpseApi*)se_ac_bnfa;
    mpse_api->init();
    mpse = mpse_api->ctor(snort_conf, nullptr, &s_agent);
    CHECK(mpse);

    return mpse;
}

void MpseManager::delete_search_engine(Mpse*)
{
    const MpseApi* mpse_api = (MpseApi*)se_ac_bnfa;
    mpse_api->dtor(mpse);
}


static int pattern_id = 0;
static int Test_SearchStrFound(
    void* /*id*/, void* /*tree*/, int /*index*/, void* /*context*/, void* /*neg_list*/)
{
    //printf("found str with id=%ld, index=%d\n", (long)id, index);
    return 0;
}

TEST_GROUP(search_tool_tests)
{
    void setup() override
    { CHECK(se_ac_bnfa); }
};

TEST(search_tool_tests, ac_bnfa)
{
    SearchTool *stool = new SearchTool("ac_bnfa");
    CHECK(stool->mpse);

    pattern_id = 1;
    stool->add("the", 3, pattern_id);
    CHECK(stool->max_len == 3);

    pattern_id = 77;
    stool->add("uba", 3, pattern_id);
    CHECK(stool->max_len == 3);

    pattern_id = 2112;
    stool->add("away", 4, pattern_id);
    CHECK(stool->max_len == 4);

    pattern_id = 1000;
    stool->add("nothere", 7, pattern_id);
    CHECK(stool->max_len == 7);

    stool->prep();

    const char *datastr = "the tuba ran away";
    int result = stool->find(datastr, strlen(datastr), Test_SearchStrFound);
    CHECK(result == 3);
    delete stool;
}

TEST(search_tool_tests, search_all_ac_bnfa)
{
    SearchTool *stool = new SearchTool("ac_bnfa");
    CHECK(stool->mpse);

    pattern_id = 1;
    stool->add("the", 3, pattern_id);
    CHECK(stool->max_len == 3);

    pattern_id = 77;
    stool->add("uba", 3, pattern_id);
    CHECK(stool->max_len == 3);

    pattern_id = 2112;
    stool->add("away", 4, pattern_id);
    CHECK(stool->max_len == 4);

    pattern_id = 1000;
    stool->add("nothere", 7, pattern_id);
    CHECK(stool->max_len == 7);

    stool->prep();

    const char *datastr = "the tuba ran away";
    int result = stool->find_all(datastr, strlen(datastr), Test_SearchStrFound);
    CHECK(result == 3);
    delete stool;
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

