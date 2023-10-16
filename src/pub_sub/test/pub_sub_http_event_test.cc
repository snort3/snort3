//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_event_test.cc author Katura Harvey <katharve@cisco.com>

// Unit test for the HttpEvent methods to retrieve HTTP/2 information

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pub_sub/http_events.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_uri.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpCommon;

// Stubs to make the code link
Field::Field(int32_t length, const uint8_t* start, bool own_the_buffer_) :
    strt(start), len(length), own_the_buffer(own_the_buffer_)
{}

void Field::set(const Field& input)
{
    strt = input.strt;
    len = input.len;
}

const Field Field::FIELD_NULL { STAT_NO_SOURCE };
const Field& HttpMsgSection::get_classic_buffer(unsigned, uint64_t, uint64_t)
{ return Field::FIELD_NULL; }
const Field& HttpMsgHeader::get_true_ip_addr()
{
    Field *out = (Field*)mock().getData("output").getObjectPointer();
    return (*out);
}
int32_t HttpUri::find_host_len(const Field&) { return 0; }

TEST_GROUP(pub_sub_http_event_test)
{
    void setup() override
    {
        mock().setDataObject("output", "Field", nullptr);
    }

    void teardown() override
    {
        mock().clear();
    }
};

TEST(pub_sub_http_event_test, http_traffic)
{
    int64_t stream_id = 0;
    HttpEvent event(nullptr, false, stream_id);
    CHECK_FALSE(event.get_is_httpx());
    CHECK(event.get_httpx_stream_id() == stream_id);
}

TEST(pub_sub_http_event_test, httpx_traffic)
{
    int64_t stream_id = 3;
    HttpEvent event(nullptr, true, stream_id);
    CHECK(event.get_is_httpx());
    CHECK(event.get_httpx_stream_id() == stream_id);
}

TEST(pub_sub_http_event_test, no_true_ip_addr)
{
    const uint8_t* header_start;
    int32_t header_length;
    Field input(0, nullptr);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_trueip_addr(header_length);
    CHECK(header_length == 0);
    CHECK(header_start == nullptr);
    mock().checkExpectations();
}

TEST(pub_sub_http_event_test, true_ip_addr)
{
    const uint8_t* header_start;
    int32_t header_length;
    Field input(7, (const uint8_t*) "1.1.1.1");
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_trueip_addr(header_length);
    CHECK(header_length == 7);
    CHECK(memcmp(header_start, "1.1.1.1", 7) == 0);
    mock().checkExpectations();
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

