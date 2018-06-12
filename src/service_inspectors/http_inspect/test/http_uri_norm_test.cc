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

// http_uri_norm_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log/messages.h"
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
int DetectionEngine::queue_event(unsigned int, unsigned int, Actions::Type) { return 0; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats( PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }
void show_stats(SimpleStats*, const char*) { }

HttpJsNorm::HttpJsNorm(int, const HttpParaList::UriParam& uri_param_) :
    max_javascript_whitespaces(0), uri_param(uri_param_), javascript_search_mpse(nullptr),
    htmltype_search_mpse(nullptr) {}
HttpJsNorm::~HttpJsNorm() = default;
void HttpJsNorm::configure() {}

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
        uri_param.percent_u = true;
        uri_param.iis_unicode = true;
        uri_param.utf8_bare_byte = true;
        uri_param.iis_double_decode = true;
        uri_param.backslash_to_slash = true;
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

