//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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

// http_msg_head_shared_util_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_head_shared.h"
#include "service_inspectors/http_inspect/http_str_to_code.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

// Stubs whose sole purpose is to make the test code link
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

namespace snort
{
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
}

// Tests for get_next_code()
TEST_GROUP(get_next_code)
{
    enum Color { COLOR_OTHER=1, COLOR_GREEN, COLOR_BLUE, COLOR_RED, COLOR_YELLOW, COLOR_PURPLE };
    int32_t offset = 0;
    const StrCode color_table[6] =
    {
        { COLOR_GREEN,  "green" },
        { COLOR_BLUE,   "blue" },
        { COLOR_RED,    "red" },
        { COLOR_YELLOW, "yellow" },
        { COLOR_PURPLE, "purple" },
        { 0,            nullptr }
    };

    // This allows access to test a protected static member function
    class HttpMsgHeadTest : public HttpMsgHeadShared
    {
    public:
        static int32_t get_next_code_test(const Field& field, int32_t& next_offset,
            const StrCode table[])
        {
            return HttpMsgHeadShared::get_next_code(field, next_offset, table);
        }
    };
};

TEST(get_next_code, basic)
{
    Field input(10, (const uint8_t*) "green,blue");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 6);
    CHECK(color == COLOR_GREEN);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 11);
    CHECK(color == COLOR_BLUE);
}

TEST(get_next_code, single_token)
{
    Field input(6, (const uint8_t*) "purple");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_PURPLE);
}

TEST(get_next_code, unknown_token)
{
    Field input(14, (const uint8_t*) "madeup,red,red");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_OTHER);
}

TEST(get_next_code, null_token)
{
    Field input(11, (const uint8_t*) "green,,blue");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 6);
    CHECK(color == COLOR_GREEN);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_OTHER);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 12);
    CHECK(color == COLOR_BLUE);
}

// Tests for boundary_present()
TEST_GROUP(boundary_present)
{
    // This allows access to test a protected static member function
    class HttpMsgHeadTest : public HttpMsgHeadShared
    {
    public:
        static bool boundary_present_test(const Field& field)
        {
            return HttpMsgHeadShared::boundary_present(field);
        }
    };
};

TEST(boundary_present, present)
{
    Field input(20, (const uint8_t*) "xxxxxboundary=cccccc");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, not_present)
{
    Field input(20, (const uint8_t*) "xxxxx123456789cccccc");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, equal_only)
{
    Field input(20, (const uint8_t*) "xxxxx12345=789cccccc");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, several_missing)
{
    Field input(16, (const uint8_t*) "123456b789ccry=c");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, b_missing)
{
    Field input(50, (const uint8_t*) "12345678901234567890oundary=9012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, equal_missing)
{
    Field input(50, (const uint8_t*) "12345678901234567890boundary9012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, d_missing)
{
    Field input(50, (const uint8_t*) "12345678901234567890bounxary=012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, front)
{
    Field input(50, (const uint8_t*) "boundary=01234567890123456789012345678901234567890");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, end)
{
    Field input(50, (const uint8_t*) "01234567890123456789012345678901234567890boundary=");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, front_edge_case)
{
    Field input(49, (const uint8_t*) "oundary=01234567890123456789012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, whole_buffer)
{
    Field input(9, (const uint8_t*) "boundary=");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, all_upper)
{
    Field input(50, (const uint8_t*) "12345678901234567890BOUNDARY=012345678901234567890");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, mixed_case)
{
    Field input(50, (const uint8_t*) "12345678901234567890BoUnDaRy=012345678901234567890");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, false_starts)
{
    Field input(42, (const uint8_t*) "ARy=56789foundary=\0==ry=1234boundary=kkkkk");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, just_one_char)
{
    Field input(1, (const uint8_t*) "=");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

// Tests for content_type_matches()
TEST_GROUP(content_type_matches)
{
    class HttpMsgHeadTest : public HttpMsgHeadShared
    {
    public:
        static bool match(const char* pattern, const char* value)
        {
            return HttpMsgHeadShared::content_type_matches(pattern,
                (const uint8_t*)value, (int32_t)strlen(value));
        }
    };
};

TEST(content_type_matches, literal_entry_matches_itself)
{
    CHECK(HttpMsgHeadTest::match("application/json", "application/json"));
}

TEST(content_type_matches, literal_entry_rejects_a_different_type)
{
    CHECK(!HttpMsgHeadTest::match("application/json", "application/xml"));
}

TEST(content_type_matches, literal_entry_is_not_a_prefix_match)
{
    CHECK(!HttpMsgHeadTest::match("application/json", "application/jsonevil"));
}

TEST(content_type_matches, literal_entry_is_not_a_suffix_match)
{
    CHECK(!HttpMsgHeadTest::match("application/json", "xapplication/json"));
}

TEST(content_type_matches, wildcard_covers_a_structured_suffix)
{
    CHECK(HttpMsgHeadTest::match("application/*+json", "application/vnd.api+json"));
    CHECK(HttpMsgHeadTest::match("application/*+json", "application/ld+json"));
    CHECK(HttpMsgHeadTest::match("application/*+json", "application/problem+json"));
}

TEST(content_type_matches, wildcard_does_not_cover_the_bare_subtype)
{
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/json"));
}

TEST(content_type_matches, wildcard_must_consume_at_least_one_character)
{
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/+json"));
}

TEST(content_type_matches, wildcard_respects_the_suffix)
{
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/vnd.api+xml"));
}

TEST(content_type_matches, wildcard_does_not_cross_the_type_separator)
{
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/x/evil+json"));
    CHECK(!HttpMsgHeadTest::match("application/*", "application/x/evil"));
}

TEST(content_type_matches, wildcard_does_not_cross_a_list_separator)
{
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/evil,x+json"));
    CHECK(!HttpMsgHeadTest::match("application/*+json", "evil/x,application/vnd.api+json"));
    CHECK(!HttpMsgHeadTest::match("application/*", "application/x,evil"));
}

TEST(content_type_matches, wildcard_does_not_cross_a_fold)
{
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/evil\r\n\tx: y+json"));
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/evil\n\tx: y+json"));
    CHECK(!HttpMsgHeadTest::match("application/*", "application/evil\r\n\tx: y"));
}

TEST(content_type_matches, wildcard_covers_only_token_characters)
{
    CHECK(!HttpMsgHeadTest::match("application/*", "application/not valid"));
    CHECK(!HttpMsgHeadTest::match("application/*+json", "application/a b+json"));
    CHECK(!HttpMsgHeadTest::match("application/*", "application/x\"y"));
    CHECK(!HttpMsgHeadTest::match("application/*", "application/x\x80"));
}

TEST(content_type_matches, trailing_wildcard_covers_any_subtype)
{
    CHECK(HttpMsgHeadTest::match("application/*", "application/octet-stream"));
    CHECK(!HttpMsgHeadTest::match("application/*", "text/plain"));
}

TEST(content_type_matches, trailing_wildcard_needs_a_subtype)
{
    CHECK(!HttpMsgHeadTest::match("application/*", "application/"));
}

TEST(content_type_matches, empty_value_never_matches)
{
    CHECK(!HttpMsgHeadTest::match("application/json", ""));
    CHECK(!HttpMsgHeadTest::match("application/*+json", ""));
}

TEST(content_type_matches, matching_ignores_case)
{
    CHECK(HttpMsgHeadTest::match("application/json", "Application/JSON"));
    CHECK(HttpMsgHeadTest::match("application/*+json", "Application/VND.API+Json"));
    CHECK(!HttpMsgHeadTest::match("application/json", "Application/XML"));
}

TEST(content_type_matches, an_apostrophe_is_not_ignored)
{
    CHECK(!HttpMsgHeadTest::match("application/json", "application/j'son"));
}

TEST(content_type_matches, a_wildcard_in_the_type_stays_within_the_type)
{
    CHECK(HttpMsgHeadTest::match("*/json", "text/json"));
    CHECK(HttpMsgHeadTest::match("*/json", "application/json"));
    CHECK(!HttpMsgHeadTest::match("*/json", "application/vnd+json"));
    CHECK(!HttpMsgHeadTest::match("*/json", "/json"));
}

// Reaches the protected Content-Type helpers
class ContentTypeHelpers : public HttpMsgHeadShared
{
public:
    using HttpMsgHeadShared::content_type_is_list;
    using HttpMsgHeadShared::content_type_matches;
    using HttpMsgHeadShared::content_type_media_type;
};

// Tests for content_type_is_list()
TEST_GROUP(content_type_is_list) {};

static bool is_list(const char* value)
{
    return ContentTypeHelpers::content_type_is_list((const uint8_t*)value, (int32_t)strlen(value));
}

TEST(content_type_is_list, a_single_media_type_is_not_a_list)
{
    CHECK(!is_list("application/json"));
    CHECK(!is_list("multipart/mixed; boundary=abc"));
}

TEST(content_type_is_list, a_list_is_a_list_even_of_allowed_types)
{
    CHECK(is_list("evil/x, application/json"));
    CHECK(is_list("application/json, text/plain"));
    CHECK(is_list("application/json,"));
}

TEST(content_type_is_list, a_list_behind_a_parameter_is_a_list)
{
    CHECK(is_list("text/plain; x=1, application/evil"));
}

// A quoted boundary may hold a comma and a later parameter a '/' (the MTOM shape)
TEST(content_type_is_list, a_comma_inside_a_quoted_parameter_is_not_a_list)
{
    CHECK(!is_list("text/plain; title=\"a,b\""));
    CHECK(!is_list("multipart/related; boundary=\"a,b\"; type=\"application/xop+xml\""));
}

TEST(content_type_is_list, a_comma_after_the_quotes_close_is_a_list)
{
    CHECK(is_list("a/b; x=\"1,2\", c/d"));
}

TEST(content_type_is_list, an_escaped_quote_does_not_end_the_quoted_string)
{
    CHECK(!is_list("text/plain; title=\"a\\\",b\""));
}

// A comma is not a token character, so unquoted it can only be a list or malformed
TEST(content_type_is_list, an_unquoted_comma_in_a_parameter_is_a_list)
{
    CHECK(is_list("text/plain; charset=a,b"));
}

TEST(content_type_is_list, quoting_that_never_closes_is_not_one_media_type)
{
    CHECK(is_list("text/plain; title=\"unfinished"));
    CHECK(is_list("text/plain; title=\"a,b"));
    CHECK(is_list("text/plain; x=\", application/evil"));
}

TEST(content_type_is_list, an_empty_value_is_not_a_list)
{
    CHECK(!is_list(""));
}

// Tests for content_type_media_type()
TEST_GROUP(content_type_media_type) {};

static std::string media_type(const char* value)
{
    int32_t offset;
    const int32_t len = ContentTypeHelpers::content_type_media_type((const uint8_t*)value,
        (int32_t)strlen(value), offset);
    return std::string(value + offset, len > 0 ? len : 0);
}

TEST(content_type_media_type, a_fold_is_trimmed_only_when_it_adds_whitespace)
{
    CHECK_EQUAL(std::string("application/json"), media_type("application/json\r\n\t "));
    CHECK_EQUAL(std::string("application/json\r\n\tx: y"),
        media_type("application/json\r\n\tx: y"));
}

TEST(content_type_media_type, a_bare_media_type_is_the_whole_value)
{
    CHECK_EQUAL(std::string("application/json"), media_type("application/json"));
}

TEST(content_type_media_type, surrounding_whitespace_is_trimmed)
{
    CHECK_EQUAL(std::string("application/json"), media_type(" application/json"));
    CHECK_EQUAL(std::string("application/json"), media_type("\tapplication/json  "));
}

TEST(content_type_media_type, an_obs_folded_value_is_trimmed)
{
    CHECK_EQUAL(std::string("application/json"), media_type("\r\n application/json\r\n"));
}

TEST(content_type_media_type, parameters_are_dropped)
{
    CHECK_EQUAL(std::string("multipart/mixed"), media_type("multipart/mixed; boundary=abc"));
    CHECK_EQUAL(std::string("multipart/mixed"), media_type(" multipart/mixed ; boundary=abc"));
}

TEST(content_type_media_type, the_case_of_the_original_is_kept)
{
    CHECK_EQUAL(std::string("Application/JSON"), media_type("Application/JSON"));
}

TEST(content_type_media_type, a_value_with_no_media_type_has_no_span)
{
    CHECK_EQUAL(std::string(""), media_type("; charset=utf-8"));
    CHECK_EQUAL(std::string(""), media_type("   "));
    CHECK_EQUAL(std::string(""), media_type(""));
}

TEST(content_type_media_type, a_negative_length_has_no_span)
{
    int32_t offset;
    CHECK_EQUAL(0, ContentTypeHelpers::content_type_media_type((const uint8_t*)"x",
        HttpCommon::STAT_NO_SOURCE, offset));
}

// Mirrors check_allowed_content_type(): trim the raw value, then match the span
TEST(content_type_media_type, the_trimmed_span_matches_an_allow_list_entry)
{
    const char* const raw = " application/json";
    int32_t offset;
    const int32_t len = ContentTypeHelpers::content_type_media_type((const uint8_t*)raw,
        (int32_t)strlen(raw), offset);
    CHECK_EQUAL(16, len);
    CHECK_EQUAL(1, offset);
    CHECK(ContentTypeHelpers::content_type_matches("application/json", (const uint8_t*)raw + offset,
        len));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
