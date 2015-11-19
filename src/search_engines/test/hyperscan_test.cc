//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "search_engines/hyperscan.h"

#include <string.h>

#include "framework/base_api.h"
#include "framework/mpse.h"
#include "main/snort_config.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

extern const BaseApi* se_hyperscan;

static unsigned hits = 0;
static unsigned parse_errors = 0;

void ParseError(const char*, ...)
{ parse_errors++; }

static int match(
    void* /*user*/, void* /*tree*/, int /*index*/, void* /*context*/, void* /*list*/)
{ ++hits; return 0; }

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

//-------------------------------------------------------------------------
// base tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_hs_base)
{
    void setup()
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
    const MpseApi* mpse_api = (MpseApi*)se_hyperscan;
    CHECK(!mpse_api->trim);

    CHECK(mpse_api->ctor);
    CHECK(mpse_api->dtor);

    Mpse* p = mpse_api->ctor(nullptr, nullptr, false, nullptr);
    CHECK(p);

    mpse_api->dtor(p);
}

//-------------------------------------------------------------------------
// fp tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_hs_match)
{
    Mpse* hs = nullptr;
    const MpseApi* mpse_api = (MpseApi*)se_hyperscan;

    void setup()
    {
        CHECK(se_hyperscan);
        hs = mpse_api->ctor(nullptr, nullptr, false, nullptr);
        CHECK(hs);
        hits = 0;
        parse_errors = 0;
    }
    void teardown()
    {
        mpse_api->dtor(hs);
        hyperscan_cleanup(snort_conf);
    }
};

TEST(mpse_hs_match, empty)
{
    CHECK(hs->prep_patterns(nullptr) != 0);
    CHECK(parse_errors == 1);
    CHECK(hs->get_pattern_count() == 0);

    int state = 0;
    CHECK(hs->search((uint8_t*)"foo", 3, match, nullptr, &state) == 0);
    CHECK(hits == 0);
}

TEST(mpse_hs_match, single)
{
    CHECK(hs->add_pattern(nullptr, (uint8_t*)"foo", 3, false, false, nullptr) == 0);
    CHECK(hs->prep_patterns(nullptr) == 0);
    CHECK(hs->get_pattern_count() == 1);

    hyperscan_setup(snort_conf);

    int state = 0;
    CHECK(hs->search((uint8_t*)"foo", 3, match, nullptr, &state) == 0);
    CHECK(hits == 1);
}

TEST(mpse_hs_match, multi)
{
    CHECK(hs->add_pattern(nullptr, (uint8_t*)"foo", 3, false, false, nullptr) == 0);
    CHECK(hs->add_pattern(nullptr, (uint8_t*)"bar", 3, false, false, nullptr) == 0);
    CHECK(hs->add_pattern(nullptr, (uint8_t*)"baz", 3, false, false, nullptr) == 0);

    CHECK(hs->prep_patterns(nullptr) == 0);
    CHECK(hs->get_pattern_count() == 3);
    hyperscan_setup(snort_conf);

    int state = 0;
    CHECK(hs->search((uint8_t*)"foo bar baz", 11, match, nullptr, &state) == 0);
    CHECK(hits == 3);
}

TEST(mpse_hs_match, regex)
{
    CHECK(hs->add_pattern(
            nullptr, (uint8_t*)"(foo)|(bar)|(baz)", 17, false, false, nullptr) == 0);

    CHECK(hs->prep_patterns(nullptr) == 0);
    CHECK(hs->get_pattern_count() == 1);
    hyperscan_setup(snort_conf);

    int state = 0;
    CHECK(hs->search((uint8_t*)"foo bar baz", 11, match, nullptr, &state) == 0);
    CHECK(hits == 3);
}

TEST(mpse_hs_match, pcre)
{
    // from sid 23286
    CHECK(hs->add_pattern(
            nullptr, (uint8_t*)"\\.definition\\s*\\(", 21, false, false, nullptr) == 0);

    CHECK(hs->prep_patterns(nullptr) == 0);
    CHECK(hs->get_pattern_count() == 1);
    hyperscan_setup(snort_conf);

    int state = 0;
    CHECK(hs->search((uint8_t*)":definition(", 12, match, nullptr, &state) == 0);
    CHECK(hs->search((uint8_t*)".definition(", 12, match, nullptr, &state) == 0);
    CHECK(hs->search((uint8_t*)".definition (", 13, match, nullptr, &state) == 0);
    CHECK(hs->search((uint8_t*)".definition\r\n(", 16, match, nullptr, &state) == 0);
    CHECK(hits == 3);
}

//-------------------------------------------------------------------------
// multi fp tests
//-------------------------------------------------------------------------

TEST_GROUP(mpse_hs_multi)
{
    Mpse* hs1 = nullptr;
    Mpse* hs2 = nullptr;
    const MpseApi* mpse_api = (MpseApi*)se_hyperscan;

    void setup()
    {
        CHECK(se_hyperscan);

        hs1 = mpse_api->ctor(nullptr, nullptr, false, nullptr);
        CHECK(hs1);

        hs2 = mpse_api->ctor(nullptr, nullptr, false, nullptr);
        CHECK(hs2);

        hits = 0;
        parse_errors = 0;
    }
    void teardown()
    {
        mpse_api->dtor(hs1);
        mpse_api->dtor(hs2);
        hyperscan_cleanup(snort_conf);
    }
};

TEST(mpse_hs_multi, single)
{
    CHECK(hs1->add_pattern(nullptr, (uint8_t*)"uba", 3, false, false, nullptr) == 0);
    CHECK(hs2->add_pattern(nullptr, (uint8_t*)"tuba", 4, false, false, nullptr) == 0);

    CHECK(hs1->prep_patterns(nullptr) == 0);
    CHECK(hs2->prep_patterns(nullptr) == 0);

    CHECK(hs1->get_pattern_count() == 1);
    CHECK(hs2->get_pattern_count() == 1);

    hyperscan_setup(snort_conf);

    int state = 0;
    CHECK(hs1->search((uint8_t*)"fubar", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);

    CHECK(hs2->search((uint8_t*)"fubar", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);

    CHECK(hs1->search((uint8_t*)"snafu", 5, match, nullptr, &state) == 0);
    CHECK(hits == 1);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

