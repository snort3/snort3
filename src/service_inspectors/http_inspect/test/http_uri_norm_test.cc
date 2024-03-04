//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// http_uri_norm_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "helpers/literal_search.h"
#include "log/messages.h"

#include "main/thread_config.h"
#include "service_inspectors/http_inspect/http_js_norm.h"
#include "service_inspectors/http_inspect/http_uri_norm.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

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

snort::SearchTool* js_create_mpse_open_tag() { return nullptr; }
snort::SearchTool* js_create_mpse_tag_type() { return nullptr; }
snort::SearchTool* js_create_mpse_tag_attr() { return nullptr; }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

int64_t Parameter::get_int(char const*) { return 0; }

TEST_GROUP(http_inspect_uri_norm)
{
    uint8_t buffer[1000];
    HttpParaList::UriParam uri_param;
    HttpInfractions infractions;
    HttpEventGen events;
};

TEST(http_inspect_uri_norm, normalize)
{
    Field input(20, (const uint8_t*) "/uri//to/%6eormalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

TEST_GROUP(http_double_decode_test)
{
    uint8_t buffer[1000];
    HttpParaList::UriParam uri_param;
    HttpInfractions infractions;
    HttpEventGen events;

    void setup() override
    {
        uri_param.percent_u = true; // cppcheck-suppress unreadVariable
        uri_param.iis_unicode = true;   // cppcheck-suppress unreadVariable
        uri_param.utf8_bare_byte = true;    // cppcheck-suppress unreadVariable
        uri_param.iis_double_decode = true; // cppcheck-suppress unreadVariable
        uri_param.backslash_to_slash = true;    // cppcheck-suppress unreadVariable
    }
};

TEST(http_double_decode_test, single)
{
    Field input(19, (const uint8_t*) "/uri/to%5Cnormalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

TEST(http_double_decode_test, encoded_percent)
{
    Field input(21, (const uint8_t*) "/uri/to%255Cnormalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

TEST(http_double_decode_test, double_percent)
{
    Field input(20, (const uint8_t*) "/uri/to%%5Cnormalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

TEST(http_double_decode_test, encoded_all)
{
    Field input(25, (const uint8_t*) "/uri/to%25%35%43normalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

TEST(http_double_decode_test, utf8_all)
{
    Field input(24, (const uint8_t*) "/uri/to\xE0\x80\xA5\xC0\xB5\xE0\x81\x83normalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

TEST(http_double_decode_test, u_encode_percent)
{
    Field input(24, (const uint8_t*) "/%%uri/to%u005cnormalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 18);
    CHECK(memcmp(result.start(), "/%uri/to/normalize", 17) == 0);
}

TEST(http_double_decode_test, u_encode_all)
{
    Field input(52, (const uint8_t*) "/uri/to%u0025%U0075%u0030%U0030%u0035%U0063normalize");
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    CHECK(result.length() == 17);
    CHECK(memcmp(result.start(), "/uri/to/normalize", 17) == 0);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

