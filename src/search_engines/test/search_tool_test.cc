//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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


//-------------------------------------------------------------------------
// base stuff
//-------------------------------------------------------------------------

SnortConfig s_conf;
THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

static SnortState s_state;

SnortConfig::SnortConfig()
{
    state = &s_state;
    memset(state, 0, sizeof(*state));
    num_slots = 1;
}

SnortConfig::~SnortConfig() { }

unsigned get_instance_id()
{ return 0; }

FileIdentifier::~FileIdentifier() { }

FileVerdict FilePolicy::type_lookup(Flow*, FileContext*)
{ return FILE_VERDICT_UNKNOWN; }

FileVerdict FilePolicy::type_lookup(Flow*, FileInfo*)
{ return FILE_VERDICT_UNKNOWN; }

FileVerdict FilePolicy::signature_lookup(Flow*, FileContext*)
{ return FILE_VERDICT_UNKNOWN; }

FileVerdict FilePolicy::signature_lookup(Flow*, FileInfo*)
{ return FILE_VERDICT_UNKNOWN; }

void LogValue(const char*, const char*, FILE* = stdout)
{
}

SO_PUBLIC void LogMessage(const char*, ...) 
{
}

void FatalError(const char*,...)
{
    exit(1);
}

void LogCount(char const*, uint64_t, FILE*)
{ }

void LogStat(const char*, double, FILE* = stdout)
{}

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

extern const BaseApi* se_ac_full;
const MpseApi* mpse_api = (MpseApi*)se_ac_full;
Mpse* acf = nullptr;

Mpse* MpseManager::get_search_engine(const char *type)
{
    acf = nullptr;

    if(strcmp(type, "ac_full") == 0)
    {
        CHECK(se_ac_full);
        mpse_api->init();
        acf = mpse_api->ctor(snort_conf, nullptr, false, &s_agent);
        CHECK(acf);
    }

    return acf;
}

void MpseManager::delete_search_engine(Mpse *)
{
    mpse_api->dtor(acf);
}

Mpse::Mpse(const char*, bool) { }

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

uint64_t Mpse::get_pattern_byte_count()
{ return 0; }

void Mpse::reset_pattern_byte_count()
{ }

int pattern_id = 0;
int Test_SearchStrFound(void* /* id */, void* /* tree */, int /* index */, void* /* context */, void* /* neg_list */)
{
    //printf("found str with id=%ld, index=%d\n", (long)id, index);
    return 0;
}

TEST_GROUP(search_tool_tests)
{
    void setup()
    {
        CHECK(se_ac_full);
    }
};

TEST(search_tool_tests, ac_full)
{
    // get_search_engine returns nullptr any search engine other than ac_full.
    SearchTool *stool = new SearchTool;
    CHECK(!stool->mpse);
    delete stool;

    stool = new SearchTool("ac_full");
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

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

