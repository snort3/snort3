//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
    const uint8_t data[7] = { 0, 1, 2, 3, 4, 5, 6 };  // cppcheck-suppress unreadVariable
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 4, 0, 0, true };
        ss = new TlvPduSplitter(true, c);  // cppcheck-suppress unreadVariable
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
        result = ss->scan(nullptr, data+i, 1, 0, &fp);
        CHECK(result == StreamSplitter::SEARCH);
    }

    result = ss->scan(nullptr, data+3, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 4+0x10203);
}

TEST(relative_length_only, n2)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 2, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+2, 2, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 4+0x10203);
}

TEST(relative_length_only, n3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+3, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 4+0x10203);
}

TEST(relative_length_only, n4)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 4+0x10203);
}

TEST(relative_length_only, n5)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 5, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 4+0x10203);
}

//-------------------------------------------------------------------------
// 3 byte offset, 4 byte length, 2 byte skip, relative
// check with scan sizes 1, 2, 3, 4, 7, 8
//-------------------------------------------------------------------------

TEST_GROUP(relative_offset_length)
{
    const uint8_t data[10] = { 9, 8, 7, 0, 1, 2, 3, 4, 5, 6 };  // cppcheck-suppress unreadVariable
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 4, 3, 2, true };
        ss = new TlvPduSplitter(true, c);  // cppcheck-suppress unreadVariable
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
        result = ss->scan(nullptr, data+i, 1, 0, &fp);
        CHECK(result == StreamSplitter::SEARCH);
    }

    result = ss->scan(nullptr, data+6, 1, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 3+4+2+0x10203);
}

TEST(relative_offset_length, n2)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    for ( auto i = 0; i < 6; i+=2 )
    {
        result = ss->scan(nullptr, data+i, 2, 0, &fp);
        CHECK(result == StreamSplitter::SEARCH);
    }

    result = ss->scan(nullptr, data+6, 2, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 3+4+2+0x10203);
}

TEST(relative_offset_length, n3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+3, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+6, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 3+4+2+0x10203);
}

TEST(relative_offset_length, n4)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 4, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+4, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 3+4+2+0x10203);
}

TEST(relative_offset_length, n7)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 7, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 3+4+2+0x10203);
}

TEST(relative_offset_length, n8)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 8, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 3+4+2+0x10203);
}

//-------------------------------------------------------------------------
// various
//-------------------------------------------------------------------------

TEST_GROUP(various)
{
    const uint8_t data[8] = { 9, 8, 0, 1, 2, 3, 4, 5 };  // cppcheck-suppress unreadVariable
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

    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+3, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 0x102);
}

TEST(various, absolute3)
{
    TlvPduConfig c = { 3, 2, 0, false };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+3, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 0x102);
}

TEST(various, abort)
{
    TlvPduConfig c = { 1, 2, 0, false };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::ABORT);
}

TEST(various, header_only)
{
    TlvPduConfig c = { 1, 2, 0, true };
    ss = new TlvPduSplitter(true, c);

    uint32_t fp = 0;
    StreamSplitter::Status result;

    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 2+1+0);
}

//-------------------------------------------------------------------------
// multiple PDUs flushed on same flow / direction
//-------------------------------------------------------------------------

TEST_GROUP(multi_flush)
{
// __STRDUMP_DISABLE__
    // 2 byte offset ('O'), 1 byte length, data ('D')
    // cppcheck-suppress unreadVariable
    const uint8_t data[17] = { 'O', 'O', 3, 'D', 'D', 'D', 'O', 'O', 1, 'D', 'O', 'O', 4, 'D', 'D', 'D', 'D' };
// __STRDUMP_ENABLE__
    StreamSplitter* ss = nullptr;

    void setup() override
    {
        TlvPduConfig c = { 1, 2, 0, true };
        ss = new TlvPduSplitter(true, c);  // cppcheck-suppress unreadVariable
    }
    void teardown() override
    { delete ss; }
};

TEST(multi_flush, pdu3)
{
    uint32_t fp = 0;
    StreamSplitter::Status result;

    // PDU 1
    result = ss->scan(nullptr, data+0, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 6);

    // PDU 2
    result = ss->scan(nullptr, data+6, 4, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 4);

    // PDU 3
    result = ss->scan(nullptr, data+10, 1, 0, &fp);
    CHECK(result == StreamSplitter::SEARCH);

    result = ss->scan(nullptr, data+11, 3, 0, &fp);
    CHECK(result == StreamSplitter::FLUSH);
    CHECK(fp == 7);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

