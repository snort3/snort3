//--------------------------------------------------------------------------
// Copyright (C) 2018-2019 Cisco and/or its affiliates. All rights reserved.
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

// http2_stream_splitter_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_test_manager.h"
#include "service_inspectors/http2_inspect/http2_enum.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "service_inspectors/http2_inspect/http2_hpack_int_decode.h"
#include "service_inspectors/http2_inspect/http2_hpack_string_decode.h"
#include "service_inspectors/http2_inspect/http2_stream_splitter.h"

#include "http2_flow_data_test.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

// Stubs whose sole purpose is to make the test code link
unsigned HttpTestManager::test_input = IN_NONE;
unsigned HttpTestManager::test_output = IN_NONE;
FILE* HttpTestManager::test_out = nullptr ;
int DetectionEngine::queue_event(unsigned int, unsigned int, Actions::Type) { return 0; }
void Field::print(_IO_FILE*, char const*) const {}

TEST_GROUP(http2_scan_test)
{
    Http2FlowDataTest* session_data = nullptr;
    uint32_t flush_offset = 0;

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

TEST(http2_scan_test, basic_with_header)
{
    session_data->set_preface(false, SRC_CLIENT);
    const StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"\x00\x00\x0A\x02\x00\x00\x00\x00\x00" "0123456789ABCDEFG",
        26, &flush_offset, SRC_CLIENT);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 19);
    CHECK(session_data->get_header_coming(SRC_CLIENT));
}

TEST(http2_scan_test, basic_with_header_s2c)
{
    const StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"\x00\x00\x0A\x02\x00\x00\x00\x00\x00" "0123456789ABCDEFG",
        26, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 19);
    CHECK(session_data->get_header_coming(SRC_SERVER));
}

TEST(http2_scan_test, header_without_data)
{
    session_data->set_preface(false, SRC_CLIENT);
    const StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"\x00\x00\x0A\x02\x00\x00\x00\x00\x00",
        9, &flush_offset, SRC_CLIENT);
    CHECK(result == StreamSplitter::SEARCH);
    CHECK(flush_offset == 0);
    CHECK(session_data->get_header_coming(SRC_CLIENT));
}

TEST(http2_scan_test, preface_and_more)
{
    const StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nABCDEFGHIJKLMNOPQRSTUVWXYZ",
        50, &flush_offset, SRC_CLIENT);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 24);
    CHECK(!session_data->get_header_coming(SRC_CLIENT));
}

TEST(http2_scan_test, preface_exactly)
{
    const StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        24, &flush_offset, SRC_CLIENT);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 24);
    CHECK(!session_data->get_header_coming(SRC_CLIENT));
}

TEST(http2_scan_test, short_input)
{
    session_data->set_preface(false, SRC_SERVER);
    StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"\x00\x00\x10",
        3, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::SEARCH);
    result = implement_scan(session_data, (const uint8_t*)"\x04\x05\x06", 3, &flush_offset,
        SRC_SERVER);
    CHECK(result == StreamSplitter::SEARCH);
    result = implement_scan(session_data, (const uint8_t*)"\x07\x08\x09" "0123456789ABCDEF", 19, &flush_offset,
        SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 19);
    CHECK(session_data->get_header_coming(SRC_SERVER));
    CHECK(memcmp(session_data->get_currently_processing_frame_header(SRC_SERVER),
        "\x00\x00\x10\x04\x05\x06\x07\x08\x09", 9) == 0);
}

TEST(http2_scan_test, oversize_non_data_frame)
{
    session_data->set_preface(false, SRC_CLIENT);
    const StreamSplitter::Status result = implement_scan(session_data,
        (const uint8_t*)"\x00\xF9\x1C\x01" "12345678901234567",
        21, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::ABORT);
}

TEST(http2_scan_test, maximum_frame)
{
    uint8_t data[63870] = { 'A' };
    memcpy(data,"\x00\xF9\x1B\x04", 4);
    const StreamSplitter::Status result = implement_scan(session_data,
        data, 63780, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 63780);
    CHECK(session_data->get_header_coming(SRC_SERVER));
}

TEST(http2_scan_test, data_sections)
{
    uint8_t data[DATA_SECTION_SIZE+9] ={ 'A' };
    memcpy(data,"\x01\x21\x3C\x00\x00\x00\x00\x00\x00", 9);
    StreamSplitter::Status result = implement_scan(session_data,
        data, DATA_SECTION_SIZE + 9, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == DATA_SECTION_SIZE + 9);
    CHECK(session_data->get_header_coming(SRC_SERVER));
    CHECK(session_data->get_leftover_data(SRC_SERVER) == 0xE13C);
    result = implement_scan(session_data,
        data, DATA_SECTION_SIZE, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == DATA_SECTION_SIZE);
    CHECK(!session_data->get_header_coming(SRC_SERVER));
    result = implement_scan(session_data,
        data, DATA_SECTION_SIZE, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == DATA_SECTION_SIZE);
    CHECK(!session_data->get_header_coming(SRC_SERVER));
    result = implement_scan(session_data,
        data, DATA_SECTION_SIZE, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == DATA_SECTION_SIZE);
    CHECK(!session_data->get_header_coming(SRC_SERVER));
    result = implement_scan(session_data,
        data, 8508, &flush_offset, SRC_SERVER);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(flush_offset == 8508);
    CHECK(!session_data->get_header_coming(SRC_SERVER));
    CHECK(session_data->get_leftover_data(SRC_SERVER) == 0);
}

TEST_GROUP(http2_reassemble_test)
{
    Http2FlowDataTest* session_data = nullptr;

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

TEST(http2_reassemble_test, basic_with_header)
{
    session_data->set_header_coming(true, SRC_CLIENT);
    session_data->set_aggregated_frames (1, SRC_CLIENT);
    implement_reassemble(session_data, 19, 0,
        (const uint8_t*)"\x00\x00\x0A\x02\x00\x00\x00\x00\x00" "0123456789",
        19, PKT_PDU_TAIL, SRC_CLIENT);
    CHECK(session_data->get_frame_data_size(SRC_CLIENT) == 10);
    CHECK(memcmp(session_data->get_frame_data(SRC_CLIENT), "0123456789", 10) == 0);
}

TEST(http2_reassemble_test, basic_with_header_s2c)
{
    session_data->set_header_coming(true, SRC_SERVER);
    session_data->set_aggregated_frames (1, SRC_SERVER);
    implement_reassemble(session_data, 19, 0,
        (const uint8_t*)"\x00\x00\x0A\x02\x00\x00\x00\x00\x00" "0123456789",
        19, PKT_PDU_TAIL, SRC_SERVER);
    CHECK(session_data->get_frame_data_size(SRC_SERVER) == 10);
    CHECK(memcmp(session_data->get_frame_data(SRC_SERVER), "0123456789", 10) == 0);
}

TEST(http2_reassemble_test, basic_without_header)
{
    session_data->set_header_coming(false, SRC_CLIENT);
    implement_reassemble(session_data, 24, 0,
        (const uint8_t*)"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        24, PKT_PDU_TAIL, SRC_CLIENT);
    CHECK(session_data->get_frame_data_size(SRC_CLIENT) == 24);
    CHECK(memcmp(session_data->get_frame_data(SRC_CLIENT), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
}

TEST(http2_reassemble_test, basic_three_pieces)
{
    session_data->set_header_coming(true, SRC_CLIENT);
    session_data->set_aggregated_frames (1, SRC_CLIENT);
    StreamBuffer buffer = implement_reassemble(session_data, 19, 0,
        (const uint8_t*)"\x00\x00\x0A\x02\x00\x00",
        6, 0, SRC_CLIENT);
    CHECK(buffer.length == 0);
    CHECK(session_data->get_frame_data_size(SRC_CLIENT) == 0);
    implement_reassemble(session_data, 19, 6,
        (const uint8_t*)"\x00\x00\x00" "01234",
        8, 0, SRC_CLIENT);
    buffer = implement_reassemble(session_data, 19, 14,
        (const uint8_t*)"56789",
        5, PKT_PDU_TAIL, SRC_CLIENT);
    CHECK(buffer.length == 0);
    CHECK(session_data->get_frame_data_size(SRC_CLIENT) == 10);
    CHECK(memcmp(session_data->get_frame_data(SRC_CLIENT), "0123456789", 10) == 0);
}

TEST(http2_reassemble_test, basic_without_header_two_pieces)
{
    session_data->set_header_coming(false, SRC_CLIENT);
    implement_reassemble(session_data, 24, 0,
        (const uint8_t*)"P",
        1, 0, SRC_CLIENT);
    CHECK(session_data->get_frame_data_size(SRC_CLIENT) == 1);
    CHECK(memcmp(session_data->get_frame_data(SRC_CLIENT), "P", 1) == 0);
     implement_reassemble(session_data, 24, 1,
        (const uint8_t*)"RI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        23, PKT_PDU_TAIL, SRC_CLIENT);
    CHECK(session_data->get_frame_data_size(SRC_CLIENT) == 24);
    CHECK(memcmp(session_data->get_frame_data(SRC_CLIENT), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

