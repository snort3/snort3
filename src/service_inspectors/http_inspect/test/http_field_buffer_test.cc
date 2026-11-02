//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_field_buffer_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>
#include <cstring>
#include <string>

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "service_inspectors/http_inspect/http_cache_data.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_context_data.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_field_buffer.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_test_manager.h"
#include "service_inspectors/http_inspect/http_transaction.h"
#include "service_inspectors/http_inspect/http_uri.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace HttpCommon;
using namespace HttpEnums;

long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

static std::array<snort::IpsContextData*, 4> test_context_data = {};

static void clear_test_context_data()
{
    for (auto*& data : test_context_data)
    {
        if (data)
        {
            data->clear();
            delete data;
            data = nullptr;
        }
    }
}

namespace snort
{
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
IpsContext* DetectionEngine::get_next_context() { return nullptr; }
void DetectionEngine::wait_for_context() { }
// cppcheck-suppress functionStatic
void IpsContext::set_context_data(unsigned, IpsContextData*) { }

unsigned IpsContextData::get_ips_id()
{
    return 1;
}

IpsContextData* DetectionEngine::get_data(unsigned id)
{
    return id < test_context_data.size() ? test_context_data[id] : nullptr;
}

IpsContextData* DetectionEngine::get_data(unsigned id, IpsContext*)
{
    return get_data(id);
}

void DetectionEngine::set_data(unsigned id, IpsContextData* data)
{
    if (id < test_context_data.size())
        test_context_data[id] = data;
}
}

static Field test_content_type;

// cppcheck-suppress functionStatic
const Field& HttpMsgSection::get_classic_buffer(unsigned buffer, uint64_t sub_id, uint64_t)
{
    if (buffer == HTTP_BUFFER_RAW_HEADER and sub_id == HEAD_CONTENT_TYPE)
        return test_content_type;
    return Field::FIELD_NULL;
}

// cppcheck-suppress functionStatic
const Field& HttpMsgSection::get_classic_buffer(const HttpBufferInfo&)
{
    return Field::FIELD_NULL;
}

// cppcheck-suppress functionStatic
int32_t HttpMsgSection::get_num_headers(const HttpBufferInfo&) const
{
    return STAT_NOT_PRESENT;
}

// cppcheck-suppress functionStatic
VersionId HttpMsgSection::get_version_id(const HttpBufferInfo&) const
{
    return VERS__NOT_PRESENT;
}

// cppcheck-suppress functionStatic
uint64_t HttpTransaction::get_message_length(const HttpMsgSection*, SourceId, bool) const
{
    return 0;
}

// cppcheck-suppress functionStatic
void HttpUri::fill_decoded_uri(Field& decoded_uri_out, Field& decoded_path_out)
{
    decoded_uri_out.set(STAT_NOT_PRESENT);
    decoded_path_out.set(STAT_NOT_PRESENT);
}

static uint32_t read_u32(const Field& field)
{
    CHECK_EQUAL(static_cast<int32_t>(sizeof(uint32_t)), field.length());

    uint32_t value;
    memcpy(&value, field.start(), sizeof(value));
    return value;
}

static std::string field_to_string(const Field& field)
{
    CHECK(field.length() >= 0);
    return std::string(reinterpret_cast<const char*>(field.start()), field.length());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

TEST_GROUP(http_field_buffer_wire_domain_test)
{
    void setup() override
    {
        HttpContextData::ips_id = 1;
    }

    void teardown() override
    {
        clear_test_context_data();
        HttpContextData::ips_id = 0;
    }
};

TEST_GROUP(version_id_to_str_test) {};

TEST(version_id_to_str_test, maps_every_known_version)
{
    STRCMP_EQUAL("1.0", version_id_to_str(VERS_1_0));
    STRCMP_EQUAL("1.1", version_id_to_str(VERS_1_1));
    STRCMP_EQUAL("2.0", version_id_to_str(VERS_2_0));
    STRCMP_EQUAL("3.0", version_id_to_str(VERS_3_0));
    STRCMP_EQUAL("0.9", version_id_to_str(VERS_0_9));
}

TEST(version_id_to_str_test, returns_null_for_unmapped_version)
{
    POINTERS_EQUAL(nullptr, version_id_to_str(VERS__NOT_PRESENT));
    POINTERS_EQUAL(nullptr, version_id_to_str(VERS__PROBLEMATIC));
    POINTERS_EQUAL(nullptr, version_id_to_str(VERS__OTHER));
}

TEST(http_field_buffer_wire_domain_test, reports_only_snapshot_supported_tmp_buffers_as_wire_reportable)
{
    CHECK_FALSE(is_wire_reportable_buffer(HTTP_BUFFER_URI));
    CHECK_FALSE(is_wire_reportable_buffer(HTTP_BUFFER_DECODED_URI));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_METHOD_STR));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_REQUEST_SIZE));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_REQUEST_LINE_LENGTH));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_RESPONSE_SIZE));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_VERSION_STR));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_USER_AGENT_STR));
    CHECK(is_wire_reportable_buffer(HTTP_BUFFER_REFERER_STR));
    CHECK_FALSE(is_wire_reportable_buffer(DETAIL_119_20));
    CHECK_FALSE(is_wire_reportable_buffer(DETAIL_119_287));
    CHECK(is_wire_reportable_buffer(DETAIL_119_298));
    CHECK(is_wire_reportable_buffer(DETAIL_119_299));
    CHECK(is_wire_reportable_buffer(DETAIL_119_300));
    CHECK_FALSE(is_wire_reportable_buffer(DETAIL_119_301));
    CHECK_FALSE(is_wire_reportable_buffer(DETAIL_119_302));
    CHECK_FALSE(is_wire_reportable_buffer(DETAIL_119_304));
    CHECK_FALSE(is_wire_reportable_buffer(DETAIL_119_305));
}

TEST(http_field_buffer_wire_domain_test, materializes_numeric_request_facts_from_snapshot)
{
    HttpSplitterSnapshot snap;
    snap.request_size = 1234;
    snap.request_line_length = 77;

    CHECK_EQUAL(1234, read_u32(get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_REQUEST_SIZE), nullptr, nullptr, &snap)));
    CHECK_EQUAL(77, read_u32(get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_REQUEST_LINE_LENGTH), nullptr, nullptr, &snap)));
}

TEST(http_field_buffer_wire_domain_test, returns_not_present_for_unavailable_wire_values)
{
    HttpSplitterSnapshot snap;

    CHECK_EQUAL(STAT_NOT_PRESENT, get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_RESPONSE_SIZE), nullptr, nullptr, &snap).length());
    CHECK_EQUAL(STAT_NOT_PRESENT, get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_METHOD_STR), nullptr, nullptr, &snap).length());
    CHECK_EQUAL(STAT_NOT_PRESENT, get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_VERSION_STR), nullptr, nullptr, &snap).length());
    CHECK_EQUAL(STAT_NOT_PRESENT, get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_USER_AGENT_STR), nullptr, nullptr, &snap).length());
    CHECK_EQUAL(STAT_NOT_PRESENT, get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_REFERER_STR), nullptr, nullptr, &snap).length());
}

TEST(http_field_buffer_wire_domain_test, returns_field_null_for_snapshot_unsupported_buffers)
{
    HttpSplitterSnapshot snap;

    const Field& classic = get_http_tmp_buffer(HttpBufferInfo(HTTP_BUFFER_URI),
        nullptr, nullptr, &snap);
    const Field& detail_20 = get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_20),
        nullptr, nullptr, &snap);
    const Field& detail_287 = get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_287),
        nullptr, nullptr, &snap);
    const Field& detail_301 = get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_301),
        nullptr, nullptr, &snap);
    const Field& detail_302 = get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_302),
        nullptr, nullptr, &snap);
    const Field& detail_305 = get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_305),
        nullptr, nullptr, &snap);

    POINTERS_EQUAL(&Field::FIELD_NULL, &classic);
    POINTERS_EQUAL(&Field::FIELD_NULL, &detail_20);
    POINTERS_EQUAL(&Field::FIELD_NULL, &detail_287);
    POINTERS_EQUAL(&Field::FIELD_NULL, &detail_301);
    POINTERS_EQUAL(&Field::FIELD_NULL, &detail_302);
    POINTERS_EQUAL(&Field::FIELD_NULL, &detail_305);
}

// method/user_agent/referer are never captured off the wire snapshot -- HttpHeaderCutter never
// returns SCAN_ABORT, so the only wire-time (ABORT) case never has headers to read them from.
// The FLUSH-bound 298 that used to populate them now reports through eval() reading its own
// live section instead (see HttpMsgHeadShared::analyze()), where the has_section() path below
// already covers them.
TEST(http_field_buffer_wire_domain_test, version_str_reflects_version_id)
{
    HttpSplitterSnapshot snap;
    snap.version_id = VERS_2_0;

    std::string value = field_to_string(get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_VERSION_STR), nullptr, nullptr, &snap));
    STRCMP_EQUAL("HTTP/2.0", value.c_str());
}

TEST(http_field_buffer_wire_domain_test, materializes_event_details_from_snapshot)
{
    HttpSplitterSnapshot snap;
    const char raw_request[] = "GET /x HTTP/1.1";
    snap.request_size = 2048;
    snap.request_line_length = 515;
    snap.reason_code_detail_300 = BAD_VERSION;
    snap.set_raw_request_line(reinterpret_cast<const uint8_t*>(raw_request),
        static_cast<uint16_t>(strlen(raw_request)));

    std::string value = field_to_string(get_http_tmp_buffer(
        HttpBufferInfo(DETAIL_119_298), &snap, &snap, &snap));
    STRCMP_EQUAL("Request Size: 2048", value.c_str());
    value = field_to_string(get_http_tmp_buffer(
        HttpBufferInfo(DETAIL_119_299), &snap, &snap, &snap));
    STRCMP_EQUAL("Request Line Length: 515, Request Line: GET /x HTTP/1.1", value.c_str());
    value = field_to_string(get_http_tmp_buffer(
        HttpBufferInfo(DETAIL_119_300), &snap, &snap, &snap));
    STRCMP_EQUAL("HTTP version is bad, Request Line: GET /x HTTP/1.1", value.c_str());
}

TEST(http_field_buffer_wire_domain_test, detail_messages_never_cross_slots)
{
    HttpSplitterSnapshot snap_300;
    const char request_1_line[] = "GET /index.html HTTP/1.1";
    snap_300.request_size = 25;
    snap_300.reason_code_detail_300 = BAD_REQUEST_TERMINATION;
    snap_300.set_raw_request_line(reinterpret_cast<const uint8_t*>(request_1_line),
        static_cast<uint16_t>(strlen(request_1_line)));

    HttpSplitterSnapshot snap_298;
    const char request_2_line[] = "GET /looong/path HTTP/1.1";
    snap_298.request_size = 330;
    snap_298.set_raw_request_line(reinterpret_cast<const uint8_t*>(request_2_line),
        static_cast<uint16_t>(strlen(request_2_line)));

    const std::string detail_300 = field_to_string(get_http_tmp_buffer(
        HttpBufferInfo(DETAIL_119_300), &snap_300, nullptr, &snap_298));
    STRCMP_EQUAL("HTTP request bad termination, Request Line: GET /index.html HTTP/1.1",
        detail_300.c_str());

    const std::string detail_298 = field_to_string(get_http_tmp_buffer(
        HttpBufferInfo(DETAIL_119_298), &snap_300, nullptr, &snap_298));
    STRCMP_EQUAL("Request Size: 330", detail_298.c_str());
}

TEST(http_field_buffer_wire_domain_test, context_clear_resets_cached_wire_slots)
{
    HttpSplitterSnapshot first;
    HttpSplitterSnapshot second;
    const char raw_request[] = "GET /first HTTP/1.1";
    first.request_size = 300;
    first.request_line_length = 515;
    first.set_raw_request_line(reinterpret_cast<const uint8_t*>(raw_request),
        static_cast<uint16_t>(strlen(raw_request)));
    second.request_size = 299;

    CHECK_EQUAL(300, read_u32(get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_REQUEST_SIZE), nullptr, nullptr, &first)));
    constexpr auto detail_index = get_tmp_buffer_index<DETAIL_119_299>();
    CHECK(get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_299),
        nullptr, &first, nullptr).length() > 0);
    HttpTmpBuffer* const detail_slot =
        HttpContextData::get_tmp_buffers().tmp_bufs[detail_index].get();
    CHECK(detail_slot != nullptr);

    HttpContextData::clear_tmp_buffers();

    CHECK_EQUAL(299, read_u32(get_http_tmp_buffer(
        HttpBufferInfo(HTTP_BUFFER_REQUEST_SIZE), nullptr, nullptr, &second)));
    POINTERS_EQUAL(detail_slot, HttpContextData::get_tmp_buffers().tmp_bufs[detail_index].get());
    CHECK_EQUAL(STAT_NOT_COMPUTE, detail_slot->field.length());
    CHECK(detail_slot->text.empty());
    CHECK_EQUAL(0, detail_slot->num);
}

// ---------------------------------------------------------------------------
// append_content_type_detail tests
// ---------------------------------------------------------------------------

TEST_GROUP(append_content_type_detail_test) {};

static std::string content_type_detail(const char* value, int32_t max_len = 256)
{
    std::string out = "Content Type: ";
    append_content_type_detail(out, reinterpret_cast<const uint8_t*>(value),
        static_cast<int32_t>(strlen(value)), max_len);
    return out;
}

TEST(append_content_type_detail_test, a_bare_media_type_is_reported_as_sent)
{
    CHECK_EQUAL(std::string("Content Type: application/xml"),
        content_type_detail("application/xml"));
}

TEST(append_content_type_detail_test, parameters_are_reported_with_the_media_type)
{
    CHECK_EQUAL(std::string("Content Type: multipart/form-data; boundary=abc123"),
        content_type_detail("multipart/form-data; boundary=abc123"));
}

TEST(append_content_type_detail_test, an_empty_media_type_still_reports_the_header)
{
    CHECK_EQUAL(std::string("Content Type: ;charset=utf-8"), content_type_detail(";charset=utf-8"));
}

// The placeholder is decided after the fold is cut off, so an empty pre-fold value still gets it
TEST(append_content_type_detail_test, an_empty_media_type_before_a_fold_reports_no_value)
{
    CHECK_EQUAL(std::string("Content Type: <no value><redacted>"),
        content_type_detail(" \r\n\tfoo/bar"));
}

TEST(append_content_type_detail_test, an_attacker_sized_boundary_is_capped)
{
    const std::string value = "multipart/form-data; boundary=" + std::string(400, 'a');
    const std::string out = content_type_detail(value.c_str());
    CHECK_EQUAL(256, static_cast<int>(out.length()));
    CHECK(out.compare(0, 33, "Content Type: multipart/form-data") == 0);
}

TEST(append_content_type_detail_test, a_negative_length_reports_no_value)
{
    std::string out = "Content Type: ";
    append_content_type_detail(out, reinterpret_cast<const uint8_t*>("x"), STAT_NO_SOURCE, 256);
    CHECK_EQUAL(std::string("Content Type: <no value>"), out);
}

TEST(append_content_type_detail_test, non_printable_bytes_are_escaped)
{
    CHECK_EQUAL(std::string("Content Type: text/plain\\x01"),
        content_type_detail("text/plain\x01"));
}

TEST(append_content_type_detail_test, the_value_is_trimmed)
{
    CHECK_EQUAL(std::string("Content Type: text/plain; x=1"),
        content_type_detail(" text/plain; x=1 "));
}

TEST(append_content_type_detail_test, the_value_keeps_case_and_quoting)
{
    CHECK_EQUAL(std::string("Content Type: multipart/form-data; boundary=\"AaB03x\""),
        content_type_detail("multipart/form-data; boundary=\"AaB03x\""));
}

TEST(append_content_type_detail_test, a_folded_value_does_not_report_the_continuation)
{
    CHECK_EQUAL(std::string("Content Type: application/xml; x=1<redacted>"),
        content_type_detail("application/xml; x=1\r\n\tCookie: session=secret123"));
}

TEST(append_content_type_detail_test, a_folded_value_is_redacted_without_parameters_too)
{
    CHECK_EQUAL(std::string("Content Type: application/xml<redacted>"),
        content_type_detail("application/xml\r\n\tCookie: session=secret123"));
}

TEST(append_content_type_detail_test, a_bare_lf_fold_is_also_redacted)
{
    CHECK_EQUAL(std::string("Content Type: application/xml<redacted>"),
        content_type_detail("application/xml\n\tCookie: session=secret123"));
}

TEST(append_content_type_detail_test, a_folded_value_respects_the_cap)
{
    const std::string value = "multipart/form-data; boundary=" + std::string(400, 'a') +
        "\r\n\tCookie: session=secret123";
    const std::string out = content_type_detail(value.c_str());
    CHECK_EQUAL(256, static_cast<int>(out.length()));
    CHECK(out.find("secret123") == std::string::npos);
}

// ---------------------------------------------------------------------------
// detail_119_306 materializer tests
// ---------------------------------------------------------------------------

TEST_GROUP(detail_119_306_test)
{
    void setup() override
    {
        HttpContextData::ips_id = 1;
    }

    void teardown() override
    {
        clear_test_context_data();
        HttpContextData::ips_id = 0;
        test_content_type.reset();
    }
};

static std::string detail_119_306(const char* raw_value)
{
    test_content_type.reset();
    if (raw_value)
        test_content_type.set(static_cast<int32_t>(strlen(raw_value)),
            reinterpret_cast<const uint8_t*>(raw_value));

    char section_storage;
    auto* section = reinterpret_cast<HttpMsgSection*>(&section_storage);
    return field_to_string(get_http_tmp_buffer(HttpBufferInfo(DETAIL_119_306), section));
}

TEST(detail_119_306_test, the_field_value_is_reported)
{
    CHECK_EQUAL(std::string("Content Type: multipart/form-data; boundary=AaB03x"),
        detail_119_306("multipart/form-data; boundary=AaB03x"));
}

TEST(detail_119_306_test, an_absent_header_reports_no_value)
{
    CHECK_EQUAL(std::string("Content Type: <no value>"), detail_119_306(nullptr));
}

TEST(detail_119_306_test, an_empty_media_type_still_reports_the_header)
{
    CHECK_EQUAL(std::string("Content Type: ;charset=utf-8"), detail_119_306(";charset=utf-8"));
}

TEST(detail_119_306_test, a_folded_value_does_not_report_the_continuation)
{
    const std::string out = detail_119_306("application/xml; x=1\r\n\tCookie: session=secret123");
    CHECK(out.find("secret123") == std::string::npos);
    CHECK_EQUAL(std::string("Content Type: application/xml; x=1<redacted>"), out);
}

TEST(detail_119_306_test, a_folded_value_is_redacted_without_parameters_too)
{
    const std::string out = detail_119_306("application/xml\r\n\tCookie: session=secret123");
    CHECK(out.find("secret123") == std::string::npos);
    CHECK_EQUAL(std::string("Content Type: application/xml<redacted>"), out);
}

// ---------------------------------------------------------------------------
// append_header_detail tests
// ---------------------------------------------------------------------------

TEST_GROUP(append_header_detail_test) {};

static std::string header_detail(const char* line)
{
    std::string out;
    append_header_detail(out, reinterpret_cast<const uint8_t*>(line),
        static_cast<int32_t>(strlen(line)), 256);
    return out;
}

TEST(append_header_detail_test, ordinary_header_keeps_its_value)
{
    CHECK_EQUAL(std::string("X-Custom: plain"), header_detail("X-Custom: plain"));
}

TEST(append_header_detail_test, credential_headers_have_values_redacted)
{
    CHECK_EQUAL(std::string("Cookie: <redacted>"), header_detail("Cookie: secret"));
    CHECK_EQUAL(std::string("Authorization: <redacted>"),
        header_detail("Authorization: Bearer abc"));
    CHECK_EQUAL(std::string("Proxy-Authorization: <redacted>"),
        header_detail("Proxy-Authorization: Basic abc"));
    CHECK_EQUAL(std::string("Set-Cookie: <redacted>"), header_detail("Set-Cookie: a=b"));
    CHECK_EQUAL(std::string("X-API-Key: <redacted>"), header_detail("X-API-Key: abc"));
    CHECK_EQUAL(std::string("X-Auth-Token: <redacted>"), header_detail("X-Auth-Token: abc"));
}

TEST(append_header_detail_test, credential_name_matches_case_insensitively)
{
    CHECK_EQUAL(std::string("cOOkIe: <redacted>"), header_detail("cOOkIe: secret"));
}

TEST(append_header_detail_test, non_token_bytes_cannot_evade_the_match)
{
    std::string out;
    const uint8_t mangled[] = { 'C', 'o', 'o', 'k', 'i', 'e', 0x01, ':', ' ', 's' };
    append_header_detail(out, mangled, sizeof(mangled), 256);
    CHECK_EQUAL(std::string("Cookie\\x01: <redacted>"), out);
    CHECK(out.find('s') == std::string::npos);
}

TEST(append_header_detail_test, padded_credential_name_cannot_evade_the_match)
{
    // derive_header_name_id() strips the padding and still recognizes Cookie, so a name
    // longer than any credential name must not skip redaction.
    const std::string line = "Cookie" + std::string(33, ' ') + ": session=secret";
    const std::string out = header_detail(line.c_str());
    CHECK(out.find("<redacted>") != std::string::npos);
    CHECK(out.find("session=secret") == std::string::npos);
}

TEST(append_header_detail_test, long_ordinary_name_keeps_its_value)
{
    const std::string line = std::string(40, 'x') + ": plain";
    const std::string out = header_detail(line.c_str());
    CHECK_EQUAL(line, out);
}

TEST(append_header_detail_test, header_with_non_token_name_has_its_value_redacted)
{
    std::string out;
    const uint8_t mangled[] = { 'X', '-', 'B', 'a', 'd', '{', ':', ' ', 'v' };
    append_header_detail(out, mangled, sizeof(mangled), 256);
    CHECK_EQUAL(std::string("X-Bad{: <redacted>"), out);
}

TEST(append_header_detail_test, credential_name_padded_with_a_token_byte_is_redacted)
{
    // Cookie@X drops to cookiex, so the credential list cannot match it; the non-token byte
    // in the name is what keeps the value out of the detail.
    const std::string out = header_detail("Cookie@X: secret123");
    CHECK_EQUAL(std::string("Cookie@X: <redacted>"), out);
    CHECK(out.find("secret123") == std::string::npos);
}

TEST(append_header_detail_test, whitespace_in_the_name_redacts_the_value)
{
    CHECK_EQUAL(std::string("Host : <redacted>"), header_detail("Host : example.com"));
}

TEST(append_header_detail_test, unparseable_line_is_redacted_entirely)
{
    CHECK_EQUAL(std::string("<redacted>"), header_detail("Cookie secret"));
}

TEST(append_header_detail_test, folded_line_has_its_value_redacted)
{
    const std::string out = header_detail("X-Custom: harmless\r\n\tCookie: secret");
    CHECK_EQUAL(std::string("X-Custom: <redacted>"), out);
    CHECK(out.find("secret") == std::string::npos);
}

TEST(append_header_detail_test, folded_line_keeps_the_separator_it_had)
{
    CHECK_EQUAL(std::string("Host:<redacted>"), header_detail("Host:t.com\r\n : topsecret"));
}

TEST(append_header_detail_test, fold_before_the_colon_redacts_the_name_too)
{
    const std::string out = header_detail("Foo\r\n Cookie: secret");
    CHECK_EQUAL(std::string("<redacted>"), out);
    CHECK(out.find("Cookie") == std::string::npos);
}

TEST(append_header_detail_test, folded_ordinary_value_is_redacted_as_well)
{
    CHECK_EQUAL(std::string("X-Custom: <redacted>"),
        header_detail("X-Custom: first\r\n continued"));
}

TEST(append_header_detail_test, bare_cr_fold_is_also_redacted)
{
    CHECK_EQUAL(std::string("X-Custom: <redacted>"),
        header_detail("X-Custom: first\r continued"));
}

TEST(append_header_detail_test, redacted_detail_respects_max_append)
{
    std::string out;
    const char* line = "Cookie: secret";
    append_header_detail(out, reinterpret_cast<const uint8_t*>(line),
        static_cast<int32_t>(strlen(line)), 12);
    CHECK(out.length() <= 12);
}

// append_escaped tests
// ---------------------------------------------------------------------------

TEST_GROUP(append_escaped_test) {};

TEST(append_escaped_test, printable_ascii_unchanged)
{
    std::string out;
    const uint8_t data[] = "GET / HTTP/1.1";
    append_escaped(out, data, sizeof(data) - 1, 256);
    CHECK_EQUAL(std::string("GET / HTTP/1.1"), out);
}

TEST(append_escaped_test, nonprintable_byte_escaped)
{
    std::string out;
    const uint8_t data[] = { 0x01 };
    append_escaped(out, data, 1, 256);
    CHECK_EQUAL(std::string("\\x01"), out);
    CHECK(out.find('\x01') == std::string::npos);
}

TEST(append_escaped_test, del_byte_escaped)
{
    std::string out;
    const uint8_t data[] = { 0x7F };
    append_escaped(out, data, 1, 256);
    CHECK_EQUAL(std::string("\\x7f"), out);
    CHECK(out.find('\x7F') == std::string::npos);
}

TEST(append_escaped_test, backslash_escaped)
{
    std::string out;
    const uint8_t data[] = { '\\' };
    append_escaped(out, data, 1, 256);
    CHECK_EQUAL(std::string("\\x5c"), out);
}

TEST(append_escaped_test, crlf_escaped)
{
    std::string out;
    const uint8_t data[] = { '\r', '\n' };
    append_escaped(out, data, 2, 256);
    CHECK_EQUAL(std::string("\\x0d\\x0a"), out);
}

TEST(append_escaped_test, stops_at_max_append)
{
    std::string out;
    const uint8_t data[] = "ABCDE";
    append_escaped(out, data, 5, 3);
    CHECK_EQUAL(std::string("ABC"), out);
}

TEST(append_escaped_test, backslash_dropped_when_fewer_than_4_remain)
{
    // 2 slots remain (max_append=2); backslash needs 4 → break, 'Z' also not written.
    std::string out;
    const uint8_t data[] = { '\\', 'Z' };
    append_escaped(out, data, 2, 2);
    CHECK(out.find("\\x5c") == std::string::npos);
    CHECK(out.find('Z') == std::string::npos);
}

TEST(append_escaped_test, nonprintable_dropped_when_fewer_than_4_remain)
{
    // 3 slots remain; 0x01 needs 4 → break.
    std::string out;
    const uint8_t data[] = { 0x01, 'Z' };
    append_escaped(out, data, 2, 3);
    CHECK(out.find("\\x01") == std::string::npos);
    CHECK(out.find('\x01') == std::string::npos);
    CHECK(out.find('Z') == std::string::npos);
}

TEST(append_escaped_test, appends_to_existing_content)
{
    std::string out = "prefix:";
    const uint8_t data[] = "val";
    append_escaped(out, data, 3, 256);
    CHECK_EQUAL(std::string("prefix:val"), out);
}

TEST(append_escaped_test, max_append_counts_from_current_length)
{
    // out already has 2 chars, max_append=3 → limit=5 → 3 more chars fit.
    std::string out = "AB";
    const uint8_t data[] = "CDEFG";
    append_escaped(out, data, 5, 3);
    CHECK_EQUAL(std::string("ABCDE"), out);
}
