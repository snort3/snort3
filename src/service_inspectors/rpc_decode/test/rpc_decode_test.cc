//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <cstring>
#include <vector>

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "main/thread_config.h"
#include "profiler/time_profiler_defs.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace
{
unsigned publish_count;
unsigned published_event_id;
const uint8_t* published_data;
uint16_t published_dsize;
uint64_t published_packet_flags;
FlowData* stored_flow_data;

void reset_publish_state()
{
    publish_count = 0;
    published_event_id = 0;
    published_data = nullptr;
    published_dsize = 0;
    published_packet_flags = 0;
}
}

namespace snort
{
unsigned FlowData::flow_data_id = 0;

FlowData::FlowData(unsigned u) : id(u) {}
FlowData::~FlowData() = default;

unsigned FlowData::create_flow_data_id()
{ return ++flow_data_id; }

FlowDataStore::~FlowDataStore() = default;
FlowData* FlowDataStore::get(unsigned) const { return stored_flow_data; }
void FlowDataStore::set(FlowData* fd) { stored_flow_data = fd; }

Flow::~Flow() = default;

Packet::Packet(bool)
{
}

Packet::~Packet() = default;

bool Packet::test_session_flags(uint32_t)
{ return false; }

Inspector::Inspector() = default;
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned, unsigned, const uint8_t*, unsigned,
    uint32_t, unsigned&)
{ return StreamBuffer(); }

unsigned StreamSplitter::max(Flow*)
{ return 0; }

LogSplitter::LogSplitter(bool b) : StreamSplitter(b)
{ }

StreamSplitter::Status LogSplitter::scan(Packet*, const uint8_t*, uint32_t len, uint32_t,
    uint32_t* fp)
{
    *fp = len;
    return FLUSH;
}

uint32_t Stream::reg_xtra_data_cb(int (*)(Flow*, uint8_t**, uint32_t*, uint32_t*))
{ return 0; }

void Stream::set_extra_data(Flow*, Packet*, uint32_t)
{ }

int DetectionEngine::queue_event(unsigned, unsigned)
{ return 0; }

// cppcheck-suppress constParameterPointer ; signature must match DataBus::publish
void DataBus::publish(unsigned, unsigned event_id, Packet* p, Flow*)
{
    ++publish_count;
    published_event_id = event_id;
    published_data = p->data;
    published_dsize = p->dsize;
    published_packet_flags = p->packet_flags;
}

void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*)
{ }

void DataBus::publish(unsigned, unsigned, const uint8_t*, unsigned, Flow*)
{ }

unsigned DataBus::get_id(const PubKey&)
{ return 1; }

unsigned get_instance_id()
{ return 0; }

THREAD_LOCAL bool TimeProfilerStats::enabled = false;
}

unsigned ThreadConfig::get_instance_max()
{ return 1; }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*)
{ }

void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*)
{ }

#include "service_inspectors/rpc_decode/rpc_decode.cc"

TEST_GROUP(rpc_publish_alt_packet)
{
    Packet packet;
    uint8_t original[8] = {};
    // cppcheck-suppress unreadVariable ; shared fixture state is consumed by test bodies
    uint8_t record[32] = {};

    void setup() override
    {
        reset_publish_state();
        // cppcheck-suppress unreadVariable ; packet state is consumed by test bodies
        packet.data = original;
        // cppcheck-suppress unreadVariable ; packet state is consumed by test bodies
        packet.dsize = sizeof(original);
        // cppcheck-suppress unreadVariable ; packet state is consumed by test bodies
        packet.packet_flags = PKT_REBUILT_STREAM;
    }
};

TEST(rpc_publish_alt_packet, skips_null_empty_and_oversize_records)
{
    RpcPublishAltPacket(&packet, nullptr, 16);
    RpcPublishAltPacket(&packet, record, RPC_FRAG_HDR_SIZE);
    RpcPublishAltPacket(&packet, record, Packet::max_dsize + 1);

    CHECK_EQUAL(0, publish_count);
    POINTERS_EQUAL(original, packet.data);
    CHECK_EQUAL(sizeof(original), packet.dsize);
}

TEST(rpc_publish_alt_packet, publishes_non_empty_record_and_restores_packet_view)
{
    RpcPublishAltPacket(&packet, record, 16);

    CHECK_EQUAL(1, publish_count);
    CHECK_EQUAL(IntrinsicEventIds::ALT_PACKET, published_event_id);
    POINTERS_EQUAL(record, published_data);
    CHECK_EQUAL(16, published_dsize);
    CHECK_EQUAL(PKT_REBUILT_STREAM, published_packet_flags);
    POINTERS_EQUAL(original, packet.data);
    CHECK_EQUAL(sizeof(original), packet.dsize);
}

TEST_GROUP(rpc_prep_frag)
{
    RpcSsnData session;
    DataBuffer alt_buffer;
    uint8_t frag_body[64] = {};

    void setup() override
    {
        if (!alt_buffer.data)
            alt_buffer.allocate_data();
        // cppcheck-suppress unreadVariable ; buffer state is consumed by test bodies
        alt_buffer.len = 0;
        memset(const_cast<uint8_t*>(alt_buffer.data), 0, alt_buffer.decode_blen);
        memset(&session, 0, sizeof(session));

        for (size_t i = 0; i < sizeof(frag_body); ++i)
            frag_body[i] = static_cast<uint8_t>(i + 1);

        CHECK(RpcBufAdd(&session.frag, frag_body, sizeof(frag_body)) == RPC_STATUS__SUCCESS);
    }

    void teardown() override
    {
        RpcBufClean(&session.frag);
    }
};

TEST(rpc_prep_frag, advertises_header_plus_fragment_body)
{
    CHECK(RpcPrepFragBuffer(&session, alt_buffer) == RPC_STATUS__SUCCESS);

    CHECK_EQUAL(RPC_FRAG_HDR_SIZE + sizeof(frag_body), alt_buffer.len);

    uint32_t marker = 0;
    memcpy(&marker, alt_buffer.data, sizeof(marker));
    CHECK_EQUAL(0x80000000 | sizeof(frag_body), ntohl(marker));
    MEMCMP_EQUAL(frag_body, alt_buffer.data + RPC_FRAG_HDR_SIZE, sizeof(frag_body));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
