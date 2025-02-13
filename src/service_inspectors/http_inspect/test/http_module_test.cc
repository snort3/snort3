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

// http_module_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "helpers/literal_search.h"
#include "log/messages.h"

#include "main/thread_config.h"
#include "service_inspectors/http_inspect/http_js_norm.h"
#include "service_inspectors/http_inspect/http_module.h"
#include "service_inspectors/http_inspect/http_str_to_code.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpEnums;

namespace snort
{
// Stubs whose sole purpose is to make the test code link
void ParseWarning(WarningGroup, const char*, ...) {}
void ParseError(const char*, ...) {}

void Value::get_bits(std::bitset<256ul>&) const {}
void Value::set_first_token() {}
bool Value::get_next_csv_token(std::string&) { return false; }
bool Value::get_next_token(std::string& ) { return false; }

int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
LiteralSearch::Handle* LiteralSearch::setup() { return nullptr; }
void LiteralSearch::cleanup(LiteralSearch::Handle*) {}
LiteralSearch* LiteralSearch::instantiate(LiteralSearch::Handle*, const uint8_t*, unsigned, bool,
    bool) { return nullptr; }
void DecodeConfig::set_decompress_pdf(bool) {}
void DecodeConfig::set_decompress_swf(bool) {}
void DecodeConfig::set_decompress_zip(bool) {}
void DecodeConfig::set_decompress_vba(bool) {}

SearchTool::~SearchTool() {}
unsigned get_instance_id()
{ return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

int32_t str_to_code(const char*, const StrCode []) { return 0; }
int32_t str_to_code(const uint8_t*, const int32_t, const StrCode []) { return 0; }
int32_t substr_to_code(const uint8_t*, const int32_t, const StrCode []) { return 0; }
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

snort::SearchTool* js_create_mpse_open_tag() { return nullptr; }
snort::SearchTool* js_create_mpse_tag_type() { return nullptr; }
snort::SearchTool* js_create_mpse_tag_attr() { return nullptr; }

int64_t Parameter::get_int(char const*) { return 0; }

TEST_GROUP(http_peg_count_test)
{
    HttpModule mod;

    void setup() override
    {
        PegCount* counts = mod.get_counts();
        for (unsigned k=0; k < PEG_COUNT_MAX; k++)
        {
            CHECK(counts[k] == 0);
        }
    }

    void teardown() override
    {
        PegCount* counts = mod.get_counts();
        for (unsigned k=0; k < PEG_COUNT_MAX; k++)
        {
            counts[k] = 0;
        }
    }
};

TEST(http_peg_count_test, increment)
{
    for (unsigned k=0; k < 13; k++)
    {
        HttpModule::increment_peg_counts(PEG_SCAN);
    }
    for (unsigned k=0; k < 27816; k++)
    {
       HttpModule::increment_peg_counts(PEG_INSPECT);
    }
    PegCount* counts = mod.get_counts();
    CHECK(counts[PEG_SCAN] == 13);
    CHECK(counts[PEG_INSPECT] == 27816);
}

TEST(http_peg_count_test, zero_out)
{
    for (unsigned k=0; k < 12; k++)
    {
        HttpModule::increment_peg_counts(PEG_INSPECT);
    }
    PegCount* counts = mod.get_counts();
    CHECK(counts[PEG_INSPECT] == 12);
    counts[PEG_INSPECT] = 0;
    HttpModule::increment_peg_counts(PEG_INSPECT);
    counts = mod.get_counts();
    CHECK(counts[PEG_INSPECT] == 1);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

