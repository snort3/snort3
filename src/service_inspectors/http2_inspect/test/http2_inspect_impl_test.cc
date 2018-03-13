//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// http2_inspect_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/http2_inspect/http2_stream_splitter.h"

#include "protocols/packet.h"
#include "service_inspectors/http2_inspect/http2_enum.h"

#include "http2_flow_data_test.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace Http2Enums;

TEST_GROUP(http2_get_buf_test)
{
    Http2FlowDataTest* session_data = nullptr;
    InspectionBuffer b;

    void setup() override
    {
        session_data = new Http2FlowDataTest();
        CHECK(session_data != nullptr);
    }

    void teardown() override
    {
        delete session_data;
    }
};

TEST(http2_get_buf_test, frame_header)
{
    uint8_t* head_buf = new uint8_t[9];
    memcpy(head_buf, "\x01\x02\x03\x04\x05\x06\x07\x08\x09", 9);
    session_data->set_frame_header(head_buf, SRC_CLIENT);
    const bool result = implement_get_buf(HTTP2_BUFFER_FRAME_HEADER, session_data, SRC_CLIENT, b);
    CHECK(result == true);
    CHECK(b.len == 9);
    CHECK(memcmp(b.data, "\x01\x02\x03\x04\x05\x06\x07\x08\x09", 9) == 0);
}

TEST(http2_get_buf_test, frame_header_absent)
{
    const bool result = implement_get_buf(HTTP2_BUFFER_FRAME_HEADER, session_data, SRC_SERVER, b);
    CHECK(result == false);
    CHECK(b.len == 0);
    CHECK(b.data == nullptr);
}

TEST(http2_get_buf_test, frame_data)
{
    uint8_t* data_buf = new uint8_t[26];
    memcpy(data_buf, "zyxwvutsrqponmlkjihgfedcba", 26);
    session_data->set_frame_data(data_buf, SRC_SERVER);
    session_data->set_frame_data_size(26, SRC_SERVER);
    const bool result = implement_get_buf(HTTP2_BUFFER_FRAME_DATA, session_data, SRC_SERVER, b);
    CHECK(result == true);
    CHECK(b.len == 26);
    CHECK(memcmp(b.data, "zyxwvutsrqponmlkjihgfedcba", 26) == 0);
    delete[] data_buf;
}

TEST(http2_get_buf_test, frame_data_absent)
{
    const bool result = implement_get_buf(HTTP2_BUFFER_FRAME_DATA, session_data, SRC_CLIENT, b);
    CHECK(result == false);
    CHECK(b.len == 0);
    CHECK(b.data == nullptr);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

