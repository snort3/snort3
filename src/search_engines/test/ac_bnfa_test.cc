//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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

// ac_bnfa_test.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "framework/base_api.h"
#include "framework/counts.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "main/snort_config.h"

#include "mpse_test_stubs.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

const MpseApi* get_test_api()
{ return nullptr; }

static unsigned hits = 0;

static int match(
    void* /*user*/, void* /*tree*/, int /*index*/, void* /*context*/, void* /*list*/)
{
    ++hits;
    return 0;
}

//-------------------------------------------------------------------------
// fp tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_bnfa_match)
{
    const MpseApi* mpse_api = (const MpseApi*)se_ac_bnfa;
    Mpse* bnfa = nullptr;

    void setup() override
    {
        CHECK(se_ac_bnfa);
        bnfa = mpse_api->ctor(snort_conf, nullptr, &s_agent);
        CHECK(bnfa);
        hits = 0;
        parse_errors = 0;
    }
    void teardown() override
    {
        mpse_api->dtor(bnfa);
    }
};

TEST(mpse_bnfa_match, empty)
{
    CHECK(bnfa->prep_patterns(snort_conf) == 0);
    CHECK(parse_errors == 0);
    CHECK(bnfa->get_pattern_count() == 0);

    int state = 0;
    CHECK(bnfa->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 0);
    CHECK(hits == 0);
}

TEST(mpse_bnfa_match, single)
{
    Mpse::PatternDescriptor desc;

    CHECK(bnfa->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(bnfa->prep_patterns(snort_conf) == 0);
    CHECK(bnfa->get_pattern_count() == 1);

    int state = 0;
    CHECK(bnfa->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 1);
    CHECK(hits == 1);
}

TEST(mpse_bnfa_match, nocase)
{
    Mpse::PatternDescriptor desc(true, true, false);

    CHECK(bnfa->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(bnfa->prep_patterns(snort_conf) == 0);
    CHECK(bnfa->get_pattern_count() == 1);

    int state = 0;
    CHECK(bnfa->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 1);
    CHECK(bnfa->search((const uint8_t*)"fOo", 3, match, nullptr, &state) == 1);
    CHECK(hits == 2);
}

TEST(mpse_bnfa_match, other)
{
    Mpse::PatternDescriptor desc(false, true, false);

    CHECK(bnfa->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(bnfa->prep_patterns(snort_conf) == 0);
    CHECK(bnfa->get_pattern_count() == 1);

    int state = 0;
    CHECK(bnfa->search((const uint8_t*)"foo", 3, match, nullptr, &state) == 1);
    CHECK(bnfa->search((const uint8_t*)"fOo", 3, match, nullptr, &state) == 1);
    CHECK(hits == 2);
}

TEST(mpse_bnfa_match, multi)
{
    Mpse::PatternDescriptor desc;

    CHECK(bnfa->add_pattern((const uint8_t*)"foo", 3, desc, s_user) == 0);
    CHECK(bnfa->add_pattern((const uint8_t*)"bar", 3, desc, s_user) == 0);
    CHECK(bnfa->add_pattern((const uint8_t*)"baz", 3, desc, s_user) == 0);

    CHECK(bnfa->prep_patterns(snort_conf) == 0);
    CHECK(bnfa->get_pattern_count() == 3);

    // __STRDUMP_DISABLE__
    // ac_bnfa deficiency: does not match the final "baz"
    // more generally, won't match repeated pattern w/o other pattern between
    // such as "foo barfoo"
    // this is ok for fp_detect but unacceptable for SearchTool
    int state = 0;
    CHECK(bnfa->search((const uint8_t*)"foo barfoo bazookibaz", 17, match, nullptr, &state) == 4);
    // __STRDUMP_ENABLE__
    CHECK(hits == 4);
}

//-------------------------------------------------------------------------
// multi fp tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_bnfa_multi)
{
    const MpseApi* mpse_api = (const MpseApi*)se_ac_bnfa;
    Mpse* bnfa1 = nullptr;
    Mpse* bnfa2 = nullptr;

    void setup() override
    {
        CHECK(se_ac_bnfa);

        bnfa1 = mpse_api->ctor(snort_conf, nullptr, &s_agent);
        CHECK(bnfa1);

        bnfa2 = mpse_api->ctor(snort_conf, nullptr, &s_agent);
        CHECK(bnfa2);

        hits = 0;
        parse_errors = 0;
    }
    void teardown() override
    {
        mpse_api->dtor(bnfa1);
        mpse_api->dtor(bnfa2);
    }
};

TEST(mpse_bnfa_multi, single)
{
    Mpse::PatternDescriptor desc;

    CHECK(bnfa1->add_pattern((const uint8_t*)"uba", 3, desc, s_user) == 0);
    CHECK(bnfa2->add_pattern((const uint8_t*)"tuba", 4, desc, s_user) == 0);

    CHECK(bnfa1->prep_patterns(snort_conf) == 0);
    CHECK(bnfa2->prep_patterns(snort_conf) == 0);

    CHECK(bnfa1->get_pattern_count() == 1);
    CHECK(bnfa2->get_pattern_count() == 1);

    int state = 0;
    CHECK(bnfa1->search((const uint8_t*)"fubar", 5, match, nullptr, &state) == 1 );
    CHECK(hits == 1);

    CHECK(bnfa2->search((const uint8_t*)"fubar", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);

    CHECK(bnfa1->search((const uint8_t*)"snafu", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    ((MpseApi*)se_ac_bnfa)->init();
    // FIXIT-L There is currently no external way to fully release the memory from the static
    //   s_scratch vector in hyperscan.cc
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

