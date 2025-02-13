//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_translate_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector/payload_injector.h"

#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(payload_injector_translate_test)
{
    uint8_t* http2_payload; // cppcheck-suppress unusedVariable
    uint32_t payload_len;   // cppcheck-suppress unusedVariable
    InjectionReturnStatus status;   // cppcheck-suppress unusedVariable
};

TEST(payload_injector_translate_test, basic_hdr_translation)
{
    char http_page[] = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: "
        "504\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html>\n<html><head>\n<meta"
        "http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\" />\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);
    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] =
    {
        0x0, 0x0, 0x28, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0x0, 0x7, 0x3a, 0x73, 0x74,
        0x61, 0x74, 0x75, 0x73, 0x3, 0x34, 0x30, 0x33, 0xf, 0x10, 0x18, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d,
        0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x55, 0x54, 0x46,
        0x2d, 0x38, 0x0, 0x0, 0x62, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x3c, 0x21, 0x44, 0x4f,
        0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0xa, 0x3c, 0x68, 0x74,
        0x6d, 0x6c, 0x3e, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0xa, 0x3c, 0x6d, 0x65, 0x74,
        0x61, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x65, 0x71, 0x75, 0x69, 0x76, 0x3d, 0x22, 0x63,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x22, 0x20, 0x63,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x3d, 0x22, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68,
        0x74, 0x6d, 0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x55,
        0x54, 0x46, 0x2d, 0x38, 0x22, 0x20, 0x2f, 0x3e, 0xa, 0x0, 0x0, 0x8, 0x7, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, basic_hdr_translation2)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] =
    {
        0x0, 0x0, 0x36, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0x0, 0x7, 0x3a, 0x73, 0x74,
        0x61, 0x74, 0x75, 0x73, 0x3, 0x33, 0x30, 0x37, 0xf, 0x1f, 0x8, 0x68, 0x74,
        0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0xf, 0x28, 0x1b, 0x30, 0x34, 0x66, 0x32, 0x3b, 0x20,
        0x4d, 0x61, 0x78, 0x2d, 0x41, 0x67, 0x65, 0x3a, 0x20, 0x36, 0x30, 0x30, 0x3b, 0x20,
        0x70, 0x61, 0x74, 0x68, 0x3d, 0x2f, 0x3b, 0x0, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0,
        0x1, 0x42, 0x6f, 0x64, 0x79, 0xa, 0x0, 0x0, 0x8, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

// Same like 2 , using \n instead of \r\n
TEST(payload_injector_translate_test, basic_hdr_translation3)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\nLocation: https://\nSet-Cookie: 04f2; Max-Age: 600; path=/;\n\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] =
    {
        0x0, 0x0, 0x36, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0x0, 0x7, 0x3a, 0x73, 0x74,
        0x61, 0x74, 0x75, 0x73, 0x3, 0x33, 0x30, 0x37, 0xf, 0x1f, 0x8, 0x68, 0x74,
        0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0xf, 0x28, 0x1b, 0x30, 0x34, 0x66, 0x32, 0x3b, 0x20,
        0x4d, 0x61, 0x78, 0x2d, 0x41, 0x67, 0x65, 0x3a, 0x20, 0x36, 0x30, 0x30, 0x3b, 0x20,
        0x70, 0x61, 0x74, 0x68, 0x3d, 0x2f, 0x3b, 0x0, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0,
        0x1, 0x42, 0x6f, 0x64, 0x79, 0xa, 0x0, 0x0, 0x8, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

// Mix of \r\n and \n, body length == 1
TEST(payload_injector_translate_test, mix_n_and_rn)
{
    char http_page[] =
        "HTTP/1.1 200 OK\nConnection: close\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\nContent-Length: 956\r\nContent-Type: text/html; charset=UTF-8\n\nb";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] =
    {
        0x0, 0x0, 0x3a, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0x88, 0xf, 0x28, 0x1b, 0x30, 0x34, 0x66,
        0x32, 0x3b, 0x20, 0x4d, 0x61, 0x78, 0x2d, 0x41,
        0x67, 0x65, 0x3a, 0x20, 0x36, 0x30, 0x30, 0x3b, 0x20, 0x70, 0x61, 0x74, 0x68, 0x3d,
        0x2f, 0x3b, 0xf, 0x10, 0x18, 0x74, 0x65, 0x78,
        0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74,
        0x3d, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1,
        0x62, 0x0, 0x0, 0x8, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, only_body)
{
    char http_page[] = "\r\nbody";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, no_body)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, missing_last_rn)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, missing_space_after_colon)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation:https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, extra_space_before_colon)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation :https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, unsupported_status)
{
    char http_page[] =
        "HTTP/1.1 201 Created\r\nLocation: https://\r\nSet-Cookie: 04f2; Max-Age: 600; path=/;\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, unsupported_hdr)
{
    char http_page[] =
        "HTTP/1.1 307 Proxy Redirect\r\nLocation:https://\r\nRetry-after: 120\r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, hdr_ends_wo_value)
{
    char http_page[] = "HTTP/1.1 307 Proxy Redirect\r\nLocation: ";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, missing_value)
{
    char http_page[] = "HTTP/1.1 307 Proxy Redirect\r\nLocation: \r\n\r\nBody\n";

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = (uint8_t*)http_page;
    control.http_page_len = strlen(http_page);
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_PAGE_TRANSLATION);
}

// Verify field value length is translated correctly
TEST(payload_injector_translate_test, val_len1)
{
    const uint32_t size = strlen("Location: ") + 128 + strlen("\r\n\r\nbody");
    uint8_t http_page[size];
    memset(http_page, 'a', size);
    memcpy(http_page, "Location: ", strlen("Location: "));
    memcpy(http_page+128+strlen("Location: "), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] =
    {
        0x0, 0x0, 0x84, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0xf, 0x1f, 0x7f, 0x1, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0, 0x0, 0x4,
        0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x62, 0x6f, 0x64, 0x79, 0x0, 0x0, 0x8, 0x7, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);

    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, val_len2)
{
    const uint32_t size = strlen("Location: ") + 127 + strlen("\r\n\r\nbody");
    uint8_t http_page[size];
    memset(http_page, 'a', size);
    memcpy(http_page, "Location: ", strlen("Location: "));
    memcpy(http_page+127+strlen("Location: "), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);
    uint8_t out[] =
    {
        0x0, 0x0, 0x83, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0xf, 0x1f, 0x7f, 0x0, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0, 0x0, 0x4, 0x0,
        0x1, 0x0, 0x0, 0x0, 0x1, 0x62, 0x6f, 0x64, 0x79, 0x0, 0x0, 0x8, 0x7, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);
    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, val_len3)
{
    const uint32_t size = strlen("Location: ") + 500 + strlen("\r\n\r\nbody");
    uint8_t http_page[size];
    memset(http_page, 'a', size);
    memcpy(http_page, "Location: ", strlen("Location: "));
    memcpy(http_page+500+strlen("Location: "), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);

    uint8_t out[] =
    {
        0x0, 0x1, 0xf9, 0x1, 0x4, 0x0, 0x0, 0x0, 0x1, 0xf, 0x1f, 0x7f, 0xf5, 0x2,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0,
        0x1, 0x62, 0x6f, 0x64, 0x79, 0x0, 0x0, 0x8, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
    };
    CHECK(payload_len == sizeof(out));
    CHECK(memcmp(http2_payload, out, payload_len) == 0);
    snort_free(http2_payload);
}

// Translated header is exactly 2000.
// Verify correct frame length when length is more than 1 byte.
// Verify correct behavior for body length is 1.
TEST(payload_injector_translate_test, http2_hdr_is_max)
{
    const uint32_t size = strlen("Location: myLocation12345\r\n") * 110 + strlen("Location: ") +
        strlen("\r\n\r\nb") + 17;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 110; i++)
    {
        memcpy(cur_pos, "Location: myLocation12345\r\n", strlen("Location: myLocation12345\r\n"));
        cur_pos += strlen("Location: myLocation12345\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(http_page+size-strlen("\r\n\r\nb"), "\r\n\r\nb", strlen("\r\n\r\nb"));

    InjectionControl control;
    control.http_page = http_page;
    control.http_page_len = size;
    control.stream_id = 0xf000;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == INJECTION_SUCCESS);
    CHECK(payload_len == 2036);
    uint8_t hdr[] = { 0x0, 0x7, 0xd0, 0x1, 0x4, 0x0, 0x0, 0xf0, 0x0 };
    CHECK(memcmp(http2_payload, hdr, sizeof(hdr))==0);
    uint8_t body[] = { 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xf0, 0x0, 'b' };
    CHECK(memcmp(http2_payload + 2009, body, sizeof(body))==0);
    snort_free(http2_payload);
}

// Translated header is 2001. Fails when trying to write field value.
TEST(payload_injector_translate_test, http2_hdr_too_big)
{
    const uint32_t size = strlen("Location: myLocation12345\r\n") * 110 + strlen("Location: ") +
        strlen("\r\n\r\nbody") + 18;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 110; i++)
    {
        memcpy(cur_pos, "Location: myLocation12345\r\n", strlen("Location: myLocation12345\r\n"));
        cur_pos += strlen("Location: myLocation12345\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(http_page+size-strlen("\r\n\r\nbody"), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_TRANSLATED_HDRS_SIZE);
}

// Translated header > 2000. Fails while trying to write Location field value length - failure when
// writing first byte of 2.
TEST(payload_injector_translate_test, http2_hdr_too_big3)
{
    const uint32_t size = strlen("Location: myLocation12345\r\n") * 111 + strlen("Location: ") +
        strlen("\r\n\r\nbody") + 130;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 111; i++)
    {
        memcpy(cur_pos, "Location: myLocation12345\r\n", strlen("Location: myLocation12345\r\n"));
        cur_pos += strlen("Location: myLocation12345\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(http_page+size-strlen("\r\n\r\nbody"), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_TRANSLATED_HDRS_SIZE);
}

// Translated header > 2000. Fails while trying to write Location field value length - failure when
// writing second byte of 3.
TEST(payload_injector_translate_test, http2_hdr_too_big4)
{
    const uint32_t size = strlen("Location: myLocation12345\r\n") * 110 + strlen("Location: ")*2 +
        strlen("\r\n\r\nbody") + 300 + 14;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 110; i++)
    {
        memcpy(cur_pos, "Location: myLocation12345\r\n", strlen("Location: myLocation12345\r\n"));
        cur_pos += strlen("Location: myLocation12345\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(cur_pos+strlen("Location: ")+14, "\r\nLocation: ", strlen("\r\nLocation: "));
    memcpy(http_page+size-strlen("\r\n\r\nbody"), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_TRANSLATED_HDRS_SIZE);
}

// Translated header > 2000. Fails while trying to write translation of second "Location: "
TEST(payload_injector_translate_test, http2_hdr_too_big5)
{
    const uint32_t size = strlen("Location: myLocation12345\r\n") * 110 + strlen("Location: ")*2 +
        strlen("\r\n\r\nbody") + 300 + 16;
    uint8_t http_page[size];

    memset(http_page, 'a', size);
    uint8_t* cur_pos = http_page;
    for (int i=0; i < 110; i++)
    {
        memcpy(cur_pos, "Location: myLocation12345\r\n", strlen("Location: myLocation12345\r\n"));
        cur_pos += strlen("Location: myLocation12345\r\n");
    }
    memcpy(cur_pos, "Location: ", strlen("Location: "));
    memcpy(cur_pos+strlen("Location: ")+16, "\r\nLocation: ", strlen("\r\nLocation: "));
    memcpy(http_page+size-strlen("\r\n\r\nbody"), "\r\n\r\nbody", strlen("\r\n\r\nbody"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);

    CHECK(status == ERR_TRANSLATED_HDRS_SIZE);
}

TEST(payload_injector_translate_test, payload_body_is_exactly_1_data_frame)
{
    static const uint32_t size = (1<<14) + strlen("HTTP/1.1 200 OK\r\n\r\n");
    uint8_t http_page[size];
    memset(http_page,'a',size);
    memcpy(http_page,"HTTP/1.1 200 OK\r\n\r\n", strlen("HTTP/1.1 200 OK\r\n\r\n"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);
    CHECK(status == INJECTION_SUCCESS);
    // Headers frame header + status ok + data frame header
    uint8_t out[] = { 0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88, 0, 0x40, 0, 0, 1, 0, 0, 0, 1 };
    CHECK(memcmp(http2_payload, out, sizeof(out))==0);
    // Data frame == http body
    CHECK(memcmp(http2_payload + sizeof(out), http_page + strlen("HTTP/1.1 200 OK\r\n\r\n"),
        1<<14)==0);
    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, payload_body_is_data_frame_plus_1)
{
    static const uint32_t size = (1<<14) + 1 + strlen("HTTP/1.1 200 OK\r\n\r\n");
    uint8_t http_page[size];
    memset(http_page,'a',size);
    memcpy(http_page,"HTTP/1.1 200 OK\r\n\r\n", strlen("HTTP/1.1 200 OK\r\n\r\n"));

    InjectionControl control;
    control.stream_id = 1;
    control.http_page = http_page;
    control.http_page_len = size;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);
    CHECK(status == INJECTION_SUCCESS);
    // Headers frame header + status ok + data frame header
    uint8_t out[] = { 0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88, 0, 0x40, 0, 0, 0, 0, 0, 0, 1 };
    CHECK(memcmp(http2_payload, out, sizeof(out))==0);
    // First data frame
    CHECK(memcmp(http2_payload + sizeof(out), http_page + strlen("HTTP/1.1 200 OK\r\n\r\n"),
        1<<14)==0);
    // Second data frame header + 1 last byte of body
    uint8_t out2[] = { 0, 0, 1, 0, 1, 0, 0, 0, 1, 'a' };
    CHECK(memcmp(http2_payload + sizeof(out) + (1<<14), out2, sizeof(out2))==0);
    snort_free(http2_payload);
}

TEST(payload_injector_translate_test, http_page_is_nullptr)
{
    InjectionControl control;
    control.http_page = nullptr;
    control.http_page_len = 1;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);
    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, http_page_is_0_length)
{
    uint8_t http_page[] = { 1 };

    InjectionControl control;
    control.http_page = http_page;
    control.http_page_len = 0;
    status = PayloadInjector::get_http2_payload(control, http2_payload, payload_len, false);
    CHECK(status == ERR_PAGE_TRANSLATION);
}

TEST(payload_injector_translate_test, 7_bit_int_min_max)
{
    uint8_t out[6];
    uint32_t out_free_space = sizeof(out);

    // Translate 0
    uint8_t* cur = out;
    InjectionReturnStatus status = write_7_bit_prefix_int(0, cur, out_free_space);
    uint8_t expected_out[] = { 0 };
    CHECK(status == INJECTION_SUCCESS);
    CHECK(out_free_space == 5);
    CHECK(memcmp(out, expected_out, 1) == 0);

    // Translate max uint_32
    cur = out;
    out_free_space = sizeof(out);
    status = write_7_bit_prefix_int(UINT32_MAX, cur, out_free_space);
    uint8_t expected_out2[] = { 0x7f, 0x80, 0xff, 0xff, 0xff, 0xf };
    CHECK(status == INJECTION_SUCCESS);
    CHECK(out_free_space == 0);
    CHECK(memcmp(out, expected_out2, 6) == 0);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

