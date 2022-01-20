//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// hyperscan_test.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "framework/base_api.h"
#include "framework/counts.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "main/snort_config.h"
#include "utils/stats.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// base stuff
//-------------------------------------------------------------------------

namespace snort
{
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

void Mpse::search(MpseBatch& batch, MpseType mpse_type)
{
    _search(batch, mpse_type);
}

void Mpse::_search(MpseBatch& batch, MpseType mpse_type)
{
    int start_state;

    for ( auto& item : batch.items )
    {
        if (item.second.done)
            continue;

        item.second.error = false;
        item.second.matches = 0;

        for ( auto& so : item.second.so )
        {
            start_state = 0;
            switch (mpse_type)
            {
                case MPSE_TYPE_NORMAL:
                    item.second.matches += so->normal_mpse->search(item.first.buf, item.first.len,
                            batch.mf, batch.context, &start_state);
                    break;
                case MPSE_TYPE_OFFLOAD:
                    item.second.matches += so->offload_mpse->search(item.first.buf, item.first.len,
                            batch.mf, batch.context, &start_state);
                    break;
            }
        }
        item.second.done = true;
    }
}

SnortConfig s_conf;
THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

static std::vector<void *> s_state;
static ScratchAllocator* scratcher = nullptr;

SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{
    state = &s_state;
    num_slots = 1;
}

SnortConfig::~SnortConfig() = default;

int SnortConfig::request_scratch(ScratchAllocator* s)
{
    scratcher = s;
    s_state.resize(1);
    return 0;
}

void SnortConfig::release_scratch(int)
{
    scratcher = nullptr;
    s_state.clear();
    s_state.shrink_to_fit();
}

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

static unsigned parse_errors = 0;
void ParseError(const char*, ...)
{ parse_errors++; }
void ErrorMessage(const char*, ...) { }

void LogCount(char const*, uint64_t, FILE*)
{ }

unsigned get_instance_id()
{ return 0; }

void md5(const unsigned char*, size_t, unsigned char*) { }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

extern const BaseApi* se_hyperscan;

static unsigned hits = 0;

static int match(
    void* /*user*/, void* /*tree*/, int /*index*/, void* /*context*/, void* /*list*/)
{ ++hits; return 0; }

static void* s_user = (void*)"user";
static void* s_tree = (void*)"tree";
static void* s_list = (void*)"list";

static MpseAgent s_agent =
{
    [](struct SnortConfig* sc, void*, void** ppt)
    {
        CHECK(sc == snort_conf);
        *ppt = s_tree;
        return 0;
    },
    [](void*, void** ppl)
    {
        *ppl = s_list;
        return 0;
    },

    [](void* pu) { CHECK(pu == s_user); },
    [](void** ppt) { CHECK(*ppt == s_tree); },
    [](void** ppl) { CHECK(*ppl == s_list); }
};

//-------------------------------------------------------------------------
// base tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_hs_base)
{
    void setup() override
    {
        CHECK(se_hyperscan);
    }
};

TEST(mpse_hs_base, base)
{
    CHECK(se_hyperscan->type == PT_SEARCH_ENGINE);
    CHECK(se_hyperscan->name);
    CHECK(se_hyperscan->help);

    CHECK(!strcmp(se_hyperscan->name, "hyperscan"));
}

TEST(mpse_hs_base, mpse)
{
    const MpseApi* mpse_api = (const MpseApi*)se_hyperscan;
    CHECK(mpse_api->flags == (MPSE_REGEX | MPSE_MTBLD));

    CHECK(mpse_api->ctor);
    CHECK(mpse_api->dtor);

    CHECK(mpse_api->init);
    CHECK(mpse_api->print);

    mpse_api->init();
    Mpse* p = mpse_api->ctor(snort_conf, nullptr, &s_agent);
    mpse_api->print();

    CHECK(p);
    mpse_api->dtor(p);
}

//-------------------------------------------------------------------------
// fp tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_hs_match)
{
    Module* mod = nullptr;
    Mpse* hs = nullptr;
    bool do_cleanup = false;
    const MpseApi* mpse_api = (const MpseApi*)se_hyperscan;

    void setup() override
    {
        CHECK(se_hyperscan);
        mod = mpse_api->base.mod_ctor();
        hs = mpse_api->ctor(snort_conf, nullptr, &s_agent);
        CHECK(hs);
        hits = 0;
        parse_errors = 0;
    }
    void teardown() override
    {
        mpse_api->dtor(hs);
        if ( do_cleanup )
            scratcher->cleanup(snort_conf);
        mpse_api->base.mod_dtor(mod);
    }
};

TEST(mpse_hs_match, empty)
{
    CHECK(hs->prep_patterns(snort_conf) != 0);
    CHECK(parse_errors == 0);
    CHECK(hs->get_pattern_count() == 0);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 0);
    CHECK(hits == 0);
}

TEST(mpse_hs_match, single)
{
    Mpse::PatternDescriptor desc;

    CHECK(hs->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(hs->prep_patterns(snort_conf) == 0);
    CHECK(hs->get_pattern_count() == 1);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 1);
    CHECK(hits == 1);
}

TEST(mpse_hs_match, nocase)
{
    Mpse::PatternDescriptor desc(true, true, false);

    CHECK(hs->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(hs->prep_patterns(snort_conf) == 0);
    CHECK(hs->get_pattern_count() == 1);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 1);
    CHECK(hs->search((const uint8_t*)"fOo", 3, match, nullptr, &state) == 1);
    CHECK(hits == 2);
}

TEST(mpse_hs_match, other)
{
    Mpse::PatternDescriptor desc(false, true, false);

    CHECK(hs->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(hs->prep_patterns(snort_conf) == 0);
    CHECK(hs->get_pattern_count() == 1);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 1);
    CHECK(hs->search((const uint8_t*)"fOo", 3, match, nullptr, &state) == 0);
    CHECK(hits == 1);
}

TEST(mpse_hs_match, multi)
{
    Mpse::PatternDescriptor desc;

    CHECK(hs->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(hs->add_pattern((const uint8_t*)"bar", 3, desc, s_user) == 0);
    CHECK(hs->add_pattern((const uint8_t*)"baz", 3, desc, s_user) == 0);

    CHECK(hs->prep_patterns(snort_conf) == 0);
    CHECK(hs->get_pattern_count() == 3);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)"foo bar baz", 11, match, nullptr, &state) == 3);
    CHECK(hits == 3);
}

#if 0
TEST(mpse_hs_match, regex)
{
    Mpse::PatternDescriptor desc;

    CHECK(hs->add_pattern((const uint8_t*)"(foo)|(bar)|(baz)", 17, desc, s_user) == 0);

    CHECK(hs->prep_patterns(snort_conf) == 0);
    CHECK(hs->get_pattern_count() == 1);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)"foo bar baz", 11, match, nullptr, &state) == 0);
    CHECK(hits == 3);
}

TEST(mpse_hs_match, pcre)
{
    Mpse::PatternDescriptor desc;

    // from sid 23286
    CHECK(hs->add_pattern((const uint8_t*)"\\.definition\\s*\\(", 21, desc, s_user) == 0);

    CHECK(hs->prep_patterns(snort_conf) == 0);
    CHECK(hs->get_pattern_count() == 1);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs->search((const uint8_t*)":definition(", 12, match, nullptr, &state) == 0);
    CHECK(hs->search((const uint8_t*)".definition(", 12, match, nullptr, &state) == 0);
    CHECK(hs->search((const uint8_t*)".definition (", 13, match, nullptr, &state) == 0);
    CHECK(hs->search((const uint8_t*)".definition\r\n(", 16, match, nullptr, &state) == 0);
    CHECK(hits == 4);
}
#endif

//-------------------------------------------------------------------------
// multi fp tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_hs_multi)
{
    Module* mod = nullptr;
    Mpse* hs1 = nullptr;
    Mpse* hs2 = nullptr;
    bool do_cleanup = false;
    const MpseApi* mpse_api = (const MpseApi*)se_hyperscan;

    void setup() override
    {
        CHECK(se_hyperscan);

        mod = mpse_api->base.mod_ctor();

        hs1 = mpse_api->ctor(snort_conf, nullptr, &s_agent);
        CHECK(hs1);

        hs2 = mpse_api->ctor(snort_conf, nullptr, &s_agent);
        CHECK(hs2);

        hits = 0;
        parse_errors = 0;
    }
    void teardown() override
    {
        mpse_api->dtor(hs1);
        mpse_api->dtor(hs2);
        if ( do_cleanup )
            scratcher->cleanup(snort_conf);
        mpse_api->base.mod_dtor(mod);
    }
};

TEST(mpse_hs_multi, single)
{
    Mpse::PatternDescriptor desc;

    CHECK(hs1->add_pattern((const uint8_t*)"uba", 3, desc, s_user) == 0);
    CHECK(hs2->add_pattern((const uint8_t*)"tuba", 4, desc, s_user) == 0);

    CHECK(hs1->prep_patterns(snort_conf) == 0);
    CHECK(hs2->prep_patterns(snort_conf) == 0);

    CHECK(hs1->get_pattern_count() == 1);
    CHECK(hs2->get_pattern_count() == 1);

    do_cleanup = scratcher->setup(snort_conf);

    int state = 0;
    CHECK(hs1->search((const uint8_t*)"fubar", 5, match, nullptr, &state) == 1 );
    CHECK(hits == 1);

    CHECK(hs2->search((const uint8_t*)"fubar", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);

    CHECK(hs1->search((const uint8_t*)"snafu", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // FIXIT-L There is currently no external way to fully release the memory from the static
    //   s_scratch vector in hyperscan.cc
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

