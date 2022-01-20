//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "main/snort_config.h"
#include "managers/mpse_manager.h"

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

SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{
    state = &s_state;
    num_slots = 1;
    fast_pattern_config = nullptr;
}

SnortConfig::~SnortConfig() = default;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

unsigned get_instance_id()
{ return 0; }

void LogValue(const char*, const char*, FILE*) { }
void LogMessage(const char*, ...) { }
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

void Mpse::search(MpseBatch&, MpseType) { }
void Mpse::_search(MpseBatch&, MpseType) { }

}

const char* FastPatternConfig::get_search_method()
{ return "ac_bnfa"; }

extern const BaseApi* se_ac_bnfa;
extern const BaseApi* se_ac_full;
Mpse* mpse = nullptr;

void MpseManager::delete_search_engine(Mpse* eng)
{
    const MpseApi* api = eng->get_api();
    api->dtor(eng);
}

MpseGroup::~MpseGroup()
{
    if (normal_mpse)
    {
        MpseManager::delete_search_engine(normal_mpse);
        normal_mpse = nullptr;
    }
    if (offload_mpse)
    {
        MpseManager::delete_search_engine(offload_mpse);
        offload_mpse = nullptr;
    }
}

bool MpseGroup::create_normal_mpse(const SnortConfig*, const char* type)
{
    const MpseApi* api;

    if ( !strcmp(type, "ac_bnfa") )
        api = (const MpseApi*) se_ac_bnfa;

    else if ( !strcmp(type, "ac_full") )
        api = (const MpseApi*) se_ac_full;

    else
        return false;

    api->init();
    mpse = api->ctor(snort_conf, nullptr, &s_agent);

    CHECK(mpse);

    mpse->set_api(api);
    normal_mpse = mpse;

    return true;
}

bool MpseGroup::create_offload_mpse(const SnortConfig*)
{
    offload_mpse = nullptr;
    return false;
}

struct ExpectedMatch
{
    int id;
    int offset;
};

static const ExpectedMatch* s_expect = nullptr;
static int s_found = 0;

static int Test_SearchStrFound(
    void* pid, void* /*tree*/, int index, void* /*context*/, void* /*neg_list*/)
{
    auto id = reinterpret_cast<std::uintptr_t>(pid);

    if ( s_expect and s_found >= 0 and
        s_expect[s_found].id == (int)id and
        s_expect[s_found].offset == index )
    {
        ++s_found;
    }
    else s_found = -1;

    return s_found == -1;
}

//-------------------------------------------------------------------------
// ac_bnfa tests
//-------------------------------------------------------------------------

TEST_GROUP(search_tool_bnfa)
{
    SearchTool* stool;

    void setup() override
    {
        CHECK(se_ac_bnfa);
        SearchTool::set_conf(snort_conf);
        stool = new SearchTool("ac_bnfa");
        SearchTool::set_conf(nullptr);

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

TEST(search_tool_bnfa, search)
{
    //                     0         1         2         3
    //                     0123456789012345678901234567890
    const char* datastr = "the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 78, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;

    int result = stool->find(datastr, strlen(datastr), Test_SearchStrFound);

    CHECK(result == 4);
    CHECK(s_found == 4);
}

TEST(search_tool_bnfa, search_all)
{
    //                     0         1         2         3
    //                     0123456789012345678901234567890
    const char* datastr = "the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 78, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;

    int result = stool->find_all(datastr, strlen(datastr), Test_SearchStrFound);

    CHECK(result == 4);
    CHECK(s_found == 4);
}

//-------------------------------------------------------------------------
// ac_full tests
//-------------------------------------------------------------------------

TEST_GROUP(search_tool_full)
{
    SearchTool* stool;

    void setup() override
    {
        CHECK(se_ac_full);
        SearchTool::set_conf(snort_conf);
        stool = new SearchTool("ac_full", true);
        SearchTool::set_conf(nullptr);

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
    const char* datastr = "the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 78, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;

    int result = stool->find(datastr, strlen(datastr), Test_SearchStrFound);

    CHECK(result == 4);
    CHECK(s_found == 4);
}

TEST(search_tool_full, search_all)
{
    //                     0         1         2         3
    //                     0123456789012345678901234567890
    const char* datastr = "the tuba ran away with the tuna";
    const ExpectedMatch xm[] =
    {
        { 1, 3 },
        { 78, 8 },
        { 77, 8 },
        { 2112, 17 },
        { 1, 26 },
        { 0, 0 }
    };

    s_expect = xm;
    s_found = 0;

    int result = stool->find_all(datastr, strlen(datastr), Test_SearchStrFound);

    CHECK(result == 5);
    CHECK(s_found == 5);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

