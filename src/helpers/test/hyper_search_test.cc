//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// hyper_search_test.cc author Russ Combs <rucombs@cisco.com>
// with tests ripped from boyer_moore_search_test.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../hyper_search.h"

#include "main/snort_config.h"

#include <algorithm>
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTestExt/MockSupport.h>
#include <CppUTest/TestHarness.h>
#include <string>

using namespace std;
using namespace snort;

//-------------------------------------------------------------------------
// mock snort config scratch handling
//-------------------------------------------------------------------------

namespace snort
{

SnortConfig s_conf;
THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

static std::vector<void *> s_state;
static ScratchAllocator* scratcher = nullptr;

static unsigned s_parse_errors = 0;

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

void ParseError(const char*, ...)
{ ++s_parse_errors; }

unsigned get_instance_id()
{ return 0; }

}

//-------------------------------------------------------------------------
// tests
//-------------------------------------------------------------------------

enum TestType
{
    CASE,
    NOCASE,
};

class Tester
{
public:
    Tester(const char* pat_str, const char* buf_str, TestType typ, int idx)
        : pat(pat_str), buf(buf_str), type(typ), index(idx)
    {
        if ( type == NOCASE )
            transform(pat.begin(), pat.end(), pat.begin(), ::toupper);

        pattern_len = pat.length();
        buffer_len = buf.length();

        pattern = (const uint8_t*)(pat.c_str());
        buffer = (const uint8_t*)(buf.c_str());
    }

    bool run(HyperSearch::Handle*);

private:
    string pat;
    string buf;

    TestType type;

    int index;

    unsigned pattern_len;
    unsigned buffer_len;

    const uint8_t* pattern;
    const uint8_t* buffer;
};

bool Tester::run(HyperSearch::Handle* handle)
{
    HyperSearch hs(handle, pattern, pattern_len, (type == NOCASE));
    bool do_cleanup = scratcher->setup(snort_conf);
    int pos = hs.search(handle, buffer, buffer_len);

    if ( do_cleanup )
        scratcher->cleanup(snort_conf);

    return pos == index;
}

TEST_GROUP(hyper_search_test_group)
{
    HyperSearch::Handle* handle = nullptr;

    void setup() override
    {
        s_parse_errors = 0;
        handle = HyperSearch::setup();
        CHECK(handle);
    }

    void teardown() override
    {
        HyperSearch::cleanup(handle);
        CHECK(s_parse_errors == 0);
    }
};

TEST(hyper_search_test_group, binary)
{
    const uint8_t pat[] = { 0xCA, 0xFE, 0xBA, 0xBE, 0x00 };

    const uint8_t buf[] = {
        0x00, 0x01, 0x02, 0x03,
        0x72, 0x01, 0x3F, 0x2B,
        0x1F, 0xCA, 0xFE, 0xBA,
        0xBE, 0x01, 0x02, 0x03,
    };

    HyperSearch hs(handle, pat, sizeof(pat)-1, true);
    bool do_cleanup = scratcher->setup(snort_conf);
    int pos = hs.search(handle, buf, sizeof(buf));

    if ( do_cleanup )
        scratcher->cleanup(snort_conf);

    CHECK(pos == 9);
}

TEST(hyper_search_test_group, empty)
{
    Tester t = Tester("abc", "", CASE, -1);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, start)
{
    Tester t = Tester("abc", "abc", CASE, 0);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, start_nocase)
{
    Tester t = Tester("abc", "aBc", NOCASE, 0);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, found1)
{
    Tester t = Tester("d", "abcdefg", CASE, 3);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, found2)
{
    Tester t = Tester("nan", "banana", CASE, 2);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, found3)
{
    Tester t = Tester("pan", "anpanman", CASE, 2);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, found4)
{
    Tester t = Tester("bcd", "abcd", CASE, 1);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, found5)
{
    Tester t = Tester("aa", "aaa", CASE, 0);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, found6)
{
    Tester t = Tester(
        "that", "which finally halts at tHaT point", NOCASE, 23);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, not_found1)
{
    Tester t = Tester("nnaaman", "anpanmanam", CASE, -1);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, not_found2)
{
    Tester t = Tester("abcd", "abc", CASE, -1);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, not_found3)
{
    Tester t = Tester("abcd", "bcd", CASE, -1);
    CHECK(t.run(handle));
}

TEST(hyper_search_test_group, not_found4)
{
    Tester t = Tester("baa", "aaaaa", CASE, -1);
    CHECK(t.run(handle));
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

