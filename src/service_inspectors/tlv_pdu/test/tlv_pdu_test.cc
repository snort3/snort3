//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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

// tlv_pdu_test.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "stream/flush_bucket.h"
#include "stream/stream.h"

#include "../tlv_pdu.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

const SnortConfig* SnortConfig::get_conf()
{ return nullptr; }

uint16_t FlushBucket::get_size()
{ return 0; }

uint8_t* DetectionEngine::get_next_buffer(unsigned int&)
{ return nullptr; }

Packet* DetectionEngine::get_current_packet()
{ return nullptr; }

StreamSplitter* Stream::get_splitter(Flow*, bool)
{ return nullptr; }

void Stream::flush_client(Packet*)
{ }

void Stream::flush_server(Packet*)
{ }

THREAD_LOCAL PduCounts pdu_counts;

//-------------------------------------------------------------------------
// 4 byte length followed by data, no offset, relative
// check with scan sizes 1, 2, 3, 4, 5
//-------------------------------------------------------------------------

TEST_GROUP(relative_length_only)
{
    // 4 byte length followed by 3 bytes data
    const uint8_t data[7] = { 0, 1, 2, 3, 4, 5, 6 };
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 4, 0, 0, true };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(relative_length_only, n1)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    for ( auto i = 0; i < 3; ++i )
    {
        result = ss->scan(nullptr, data + i, 1, 0, &fp);
        CHECK(result == StreamSplitter::SEARCH);
    }

    result = ss->scan(nullptr, data + 3, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4 - 3 + 0x10203, fp);
}

TEST(relative_length_only, n2)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 2, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 2, 2, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4 - 2 + 0x10203, fp);
}

TEST(relative_length_only, n3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 3, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4 - 3 + 0x10203, fp);
}

TEST(relative_length_only, n4)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4 - 0 + 0x10203, fp);
}

TEST(relative_length_only, n5)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 5, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4 - 0 + 0x10203, fp);
}

//-------------------------------------------------------------------------
// 3 byte offset, 4 byte length, 2 byte skip, relative
// check with scan sizes 1, 2, 3, 4, 7, 8
//-------------------------------------------------------------------------

TEST_GROUP(relative_offset_length)
{
    const uint8_t data[10] = { 9, 8, 7, 0, 1, 2, 3, 4, 5, 6 };
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 4, 3, 2, true };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(relative_offset_length, n1)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    for ( auto i = 0; i < 6; ++i )
    {
        result = ss->scan(nullptr, data + i, 1, 0, &fp);
        CHECK(result == StreamSplitter::SEARCH);
    }

    result = ss->scan(nullptr, data + 6, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3 + 4 + 2 - 6 + 0x10203, fp);
}

TEST(relative_offset_length, n2)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    for ( auto i = 0; i < 6; i+=2 )
    {
        result = ss->scan(nullptr, data + i, 2, 0, &fp);
        CHECK(result == StreamSplitter::SEARCH);
    }

    result = ss->scan(nullptr, data + 6, 2, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3 + 4 + 2 - 6 + 0x10203, fp);
}

TEST(relative_offset_length, n3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 3, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 6, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3 + 4 + 2 - 6 + 0x10203, fp);
}

TEST(relative_offset_length, n4)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 4, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 4, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3 + 4 + 2 - 4 + 0x10203, fp);
}

TEST(relative_offset_length, n7)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3 + 4 + 2 - 0 + 0x10203, fp);
}

TEST(relative_offset_length, n8)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 8, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3 + 4 + 2 - 0 + 0x10203, fp);
}

//-------------------------------------------------------------------------
// various
//-------------------------------------------------------------------------

TEST_GROUP(various)
{
    const uint8_t data[8] = { 9, 8, 0, 1, 2, 3, 4, 5 };
    StreamSplitter* ss = nullptr;

    void teardown() override
    { delete ss; }
};

TEST(various, absolute2)
{
    TlvPduConfig c = { 2, 3, 0, false };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 3, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(-3 + 0x102, fp);
}

TEST(various, absolute3)
{
    TlvPduConfig c = { 3, 2, 0, false };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 3, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(-3 + 0x102, fp);
}

TEST(various, abort)
{
    TlvPduConfig c = { 1, 2, 0, false };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

TEST(various, header_only)
{
    TlvPduConfig c = { 1, 2, 0, true };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(2 + 1 + 0, fp);
}

//-------------------------------------------------------------------------
// multiple PDUs flushed on same flow / direction
//-------------------------------------------------------------------------

TEST_GROUP(multi_flush)
{
// __STRDUMP_DISABLE__
    // 2 byte offset ('O'), 1 byte length, data ('D')
    const uint8_t data[17] = { 'O', 'O', 3, 'D', 'D', 'D', 'O', 'O', 1, 'D', 'O', 'O', 4, 'D', 'D', 'D', 'D' };
// __STRDUMP_ENABLE__
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 1, 2, 0, true };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(multi_flush, pdu3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1
    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);

    // PDU 2
    result = ss->scan(nullptr, data + 6, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4, fp);

    // PDU 3
    result = ss->scan(nullptr, data + 10, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 11, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(7 - 1, fp);
}

TEST(multi_flush, max_pipelined_1)
{
    TlvPduConfig config = { 1, 2, 0, true, 1 };
    TlvPduSplitter limited(true, config);

    uint32_t fp = 0;
    const auto result = limited.scan(nullptr, data, sizeof(data), 0, &fp);

    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);
}

TEST(multi_flush, max_pipelined_2)
{
    TlvPduConfig config = { 1, 2, 0, true, 2 };
    TlvPduSplitter limited(true, config);

    uint32_t fp = 0;
    const auto result = limited.scan(nullptr, data, sizeof(data), 0, &fp);

    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(10, fp);
}

TEST(multi_flush, max_pipelined_3)
{
    TlvPduConfig config = { 1, 2, 0, true, 3 };
    TlvPduSplitter limited(true, config);

    uint32_t fp = 0;
    const auto result = limited.scan(nullptr, data, sizeof(data), 0, &fp);

    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(17, fp);
}

TEST(multi_flush, aggregated_123)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1, 2, 3
    result = ss->scan(nullptr, data + 0, 17, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(17, fp);
}

TEST(multi_flush, aggregated_12_3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1, 2
    result = ss->scan(nullptr, data + 0, 10, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(10, fp);

    // PDU 3
    result = ss->scan(nullptr, data + 10, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(7, fp);
}

TEST(multi_flush, aggregated_1_23)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1
    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);

    // PDU 2, 3
    result = ss->scan(nullptr, data + 6, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(11 - 7, fp);
}

TEST(multi_flush, drill)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1
    result = ss->scan(nullptr, data + 0, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);
    result = ss->scan(nullptr, data + 1, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);
    result = ss->scan(nullptr, data + 2, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6 - 2, fp);

    // PDU 2
    result = ss->scan(nullptr, data + 6, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);
    result = ss->scan(nullptr, data + 7, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);
    result = ss->scan(nullptr, data + 8, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4 - 2, fp);

    // PDU 3
    result = ss->scan(nullptr, data + 10, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);
    result = ss->scan(nullptr, data + 11, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);
    result = ss->scan(nullptr, data + 12, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(7 - 2, fp);
}

TEST(multi_flush, exact_boundary)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // each PDU exactly fills its buffer (fpc == len)
    result = ss->scan(nullptr, data + 0, 6, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);

    result = ss->scan(nullptr, data + 6, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4, fp);

    result = ss->scan(nullptr, data + 10, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(7, fp);
}

TEST(multi_flush, partial_offset_carryover)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1 complete + 1 offset byte of PDU 2
    result = ss->scan(nullptr, data + 0, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);

    // remaining PDU 2 header + data
    result = ss->scan(nullptr, data + 6, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4, fp);

    // PDU 3
    result = ss->scan(nullptr, data + 10, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(7, fp);
}

TEST(multi_flush, partial_header_carryover)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1 complete + full offset of PDU 2 (2 bytes)
    result = ss->scan(nullptr, data + 0, 8, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);

    // full PDU 2, as the leading part repeats
    result = ss->scan(nullptr, data + 6, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(4, fp);

    // PDU 3
    result = ss->scan(nullptr, data + 10, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(7, fp);
}

TEST(multi_flush, carryover_pipeline)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1 complete + 1 offset byte of PDU 2
    result = ss->scan(nullptr, data + 0, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);

    // all of PDU 2 + all of PDU 3 in one buffer
    result = ss->scan(nullptr, data + 6, 11, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(11, fp);
}

//-------------------------------------------------------------------------
// pipeline in absolute mode
//-------------------------------------------------------------------------

TEST_GROUP(pipeline_absolute)
{
    // size=2, offset=0, skip=0, absolute
    // PDU 1: length=0x0005, 5 bytes total
    // PDU 2: length=0x0003, 3 bytes total
// __STRDUMP_DISABLE__
    const uint8_t data[8] = { 0, 5, 'D', 'D', 'D', 0, 3, 'D' };
// __STRDUMP_ENABLE__
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 2, 0, 0, false };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(pipeline_absolute, aggregated)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 8, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(8, fp);
}

TEST(pipeline_absolute, split)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 5, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(5, fp);

    result = ss->scan(nullptr, data + 5, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3, fp);
}

TEST(pipeline_absolute, partial_header)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1 + 1 byte of PDU 2 length field
    result = ss->scan(nullptr, data + 0, 6, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(5, fp);

    // all of PDU 2
    result = ss->scan(nullptr, data + 5, 2, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3, fp);
}

//-------------------------------------------------------------------------
// abort mid-pipeline (absolute mode)
//-------------------------------------------------------------------------

TEST_GROUP(abort_pipeline)
{
    // size=1, offset=2, skip=0, absolute; header=3
    // PDU 1: length=5 (valid, 5 >= header)
    // PDU 2: length=2 (invalid, 2 < header)
    const uint8_t data[8] = { 0, 0, 5, 'D', 'D', 0, 0, 2 };
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 1, 2, 0, false };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(abort_pipeline, mid_buffer)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // valid PDU 1 followed by invalid PDU 2 in one buffer
    result = ss->scan(nullptr, data + 0, 8, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

TEST(abort_pipeline, separate)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1 alone: valid
    result = ss->scan(nullptr, data + 0, 5, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(5, fp);

    // PDU 2 alone: abort
    result = ss->scan(nullptr, data + 5, 3, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

//-------------------------------------------------------------------------
// abort on relative overflow (fpc + header > UINT32_MAX)
//-------------------------------------------------------------------------

TEST_GROUP(abort_relative_overflow)
{
    StreamSplitter* ss = nullptr;

    void teardown() override
    { delete ss; }
};

TEST(abort_relative_overflow, max_length_field)
{
    // length field = 0xFFFFFFFF; fpc + header would overflow
    TlvPduConfig c = { 4, 0, 0, true };
    ss = new TlvPduSplitter(true, c);

    const uint8_t data[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data, 4, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

TEST(abort_relative_overflow, just_over)
{
    // length = UINT32_MAX - header + 1 = 0xFFFFFFFC
    TlvPduConfig c = { 4, 0, 0, true };
    ss = new TlvPduSplitter(true, c);

    const uint8_t data[4] = { 0xFF, 0xFF, 0xFF, 0xFC };

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data, 4, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

TEST(abort_relative_overflow, just_under)
{
    // length = UINT32_MAX - header = 0xFFFFFFFC - 1 = 0xFFFFFFFB
    // fpc + header = 0xFFFFFFFF, does not overflow
    TlvPduConfig c = { 4, 0, 0, true };
    ss = new TlvPduSplitter(true, c);

    const uint8_t data[4] = { 0xFF, 0xFF, 0xFF, 0xFB };

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(0xFFFFFFFF, fp);
}

TEST(abort_relative_overflow, with_offset_and_skip)
{
    // length = 0xFFFF; fpc + header = 0xFFFF + 4 = 0x10003, no overflow
    TlvPduConfig c = { 2, 1, 1, true };
    ss = new TlvPduSplitter(true, c);

    const uint8_t data[3] = { 0, 0xFF, 0xFF };

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(0xFFFF + 4, fp);
}

TEST(abort_relative_overflow, split_header_then_overflow)
{
    // deliver length bytes across two scans, final value overflows
    TlvPduConfig c = { 4, 0, 0, true };
    ss = new TlvPduSplitter(true, c);

    const uint8_t data[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data, 2, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data + 2, 2, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

//-------------------------------------------------------------------------
// pipeline of header-only PDUs (zero data bytes)
//-------------------------------------------------------------------------

TEST_GROUP(pipeline_header_only)
{
    // size=1, offset=0, skip=0, relative; header=1
    // PDUs with length=0: total = 0 + header(1) = 1 byte each
    const uint8_t data[6] = { 0, 0, 0, 2, 'D', 'D' };
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 1, 0, 0, true };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(pipeline_header_only, three_empty)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // three header-only PDUs (length=0, 1 byte each)
    result = ss->scan(nullptr, data + 0, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3, fp);
}

TEST(pipeline_header_only, empty_then_data)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // three header-only PDUs + one PDU with 2 data bytes
    result = ss->scan(nullptr, data + 0, 6, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(6, fp);
}

//-------------------------------------------------------------------------
// pipeline with multi-byte length field
//-------------------------------------------------------------------------

TEST_GROUP(pipeline_multibyte)
{
    // size=2, offset=0, skip=0, relative; header=2
    // PDU 1: length=0x0003, total=3+2=5
    // PDU 2: length=0x0001, total=1+2=3
// __STRDUMP_DISABLE__
    const uint8_t data[8] = { 0, 3, 'D', 'D', 'D', 0, 1, 'D' };
// __STRDUMP_ENABLE__
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 2, 0, 0, true };
        ss = new TlvPduSplitter(true, c);
    }
    void teardown() override
    { delete ss; }
};

TEST(pipeline_multibyte, aggregated)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 8, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(8, fp);
}

TEST(pipeline_multibyte, split)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data + 0, 5, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(5, fp);

    result = ss->scan(nullptr, data + 5, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3, fp);
}

TEST(pipeline_multibyte, split_length_field)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1 + first byte of PDU 2 length field
    result = ss->scan(nullptr, data + 0, 6, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(5, fp);

    // all of PDU 2 repeats and new (second length byte + data)
    result = ss->scan(nullptr, data + 5, 2, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK_EQUAL(3, fp);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
