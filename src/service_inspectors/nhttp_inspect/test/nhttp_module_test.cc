//--------------------------------------------------------------------------
// Copyright (C) 2016 Cisco and/or its affiliates. All rights reserved.
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

// nhttp_module_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#include "log/messages.h"
#include "events/event_queue.h"

#include "service_inspectors/nhttp_inspect/nhttp_module.h"
#include "service_inspectors/nhttp_inspect/nhttp_test_manager.h"
#include "service_inspectors/nhttp_inspect/nhttp_str_to_code.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace NHttpEnums;

// Stubs whose sole purpose is to make the test code link
void ParseWarning(WarningGroup, const char*, ...) {}
void ParseError(const char*, ...) {}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }
void show_stats(SimpleStats*, const char*) { }

void Value::get_bits(std::bitset<256ul>&) const {}
int SnortEventqAdd(unsigned int, unsigned int, RuleType) { return 0; }

int32_t str_to_code(const uint8_t*, const int32_t, const StrCode []) { return 0; }
long NHttpTestManager::print_amount {};
bool NHttpTestManager::print_hex {};

TEST_GROUP(nhttp_peg_count_test)
{
    NHttpModule mod;

    void setup()
    {
        PegCount* counts = mod.get_counts();
        for (unsigned k=0; k < PEG_COUNT_MAX; k++)
        {
            CHECK(counts[k] == 0);
        }
    }

    void teardown()
    {
        PegCount* counts = mod.get_counts();
        for (unsigned k=0; k < PEG_COUNT_MAX; k++)
        {
            counts[k] = 0;
        }
    }
};

TEST(nhttp_peg_count_test, increment)
{
    for (unsigned k=0; k < 13; k++)
    {
        NHttpModule::increment_peg_counts(PEG_SCAN);
    }
    for (unsigned k=0; k < 27816; k++)
    {
       NHttpModule::increment_peg_counts(PEG_INSPECT);
    }
    PegCount* counts = mod.get_counts();
    CHECK(counts[PEG_SCAN] == 13);
    CHECK(counts[PEG_INSPECT] == 27816);
}

TEST(nhttp_peg_count_test, zero_out)
{
    for (unsigned k=0; k < 12; k++)
    {
        NHttpModule::increment_peg_counts(PEG_INSPECT);
    }
    PegCount* counts = mod.get_counts();
    CHECK(counts[PEG_INSPECT] == 12);
    counts[PEG_INSPECT] = 0;
    NHttpModule::increment_peg_counts(PEG_INSPECT);
    counts = mod.get_counts();
    CHECK(counts[PEG_INSPECT] == 1);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

