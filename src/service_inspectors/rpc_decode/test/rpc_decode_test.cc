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


// Pins RpcStatefulInspection post-loop partial flush, RpcChunkAppend packing,
// and growth-quantum behavior that packet tests cannot steer precisely.
// End-to-end attack/regression pcaps live under snort3_test.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <cstring>
#include <vector>

#include "detection/detection_buf.h"
#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "framework/data_bus.h"
#include "main/thread_config.h"
#include "profiler/time_profiler_defs.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "service_inspectors/rpc_decode/rpc_module.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "utils/safec.h"

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
unsigned depth_exceeded_events;

void reset_publish_state()
{
    publish_count = 0;
    published_event_id = 0;
    published_data = nullptr;
    published_dsize = 0;
    published_packet_flags = 0;
}

void write_frag_hdr(uint8_t* dst, uint32_t body_len, bool last)
{
    const uint32_t marker = htonl(body_len | (last ? 0x80000000u : 0u));
    memcpy_s(dst, sizeof(marker), &marker, sizeof(marker));
}

void append_frag_hdr(std::vector<uint8_t>& payload, uint32_t body_len, bool last)
{
    const size_t offset = payload.size();
    payload.resize(offset + sizeof(uint32_t));
    write_frag_hdr(payload.data() + offset, body_len, last);
}

void append_body(std::vector<uint8_t>& payload, uint32_t len, uint8_t fill)
{
    payload.insert(payload.end(), len, fill);
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
void FlowStash::reset() { }

IpsContext::IpsContext(unsigned)
{ }

IpsContext::~IpsContext() = default;

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

int DetectionEngine::queue_event(unsigned gid, unsigned sid)
{
    if (gid == GID_RPC_DECODE && sid == RPC_INSPECT_DEPTH_EXCEEDED)
        ++depth_exceeded_events;

    return 0;
}

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

void show_stats(const PegCount*, const PegInfo*, unsigned, const char*)
{ }

void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*)
{ }

#include "service_inspectors/rpc_decode/rpc_decode.cc"

namespace
{
unsigned count_chunk_nodes(const RpcSsnData* rsdata)
{
    unsigned count = 0;

    for (const RpcChunkNode* node = rsdata->chunks_head; node != nullptr; node = node->next)
        ++count;

    return count;
}
}

TEST_GROUP(rpc_publish_alt_packet)
{
    Packet packet;
    uint8_t original[8] = {};
    uint8_t record[32] = {};

    void setup() override
    {
        reset_publish_state();
        packet.data = original;
        packet.dsize = sizeof(original);
        packet.packet_flags = PKT_REBUILT_STREAM;
    }
};

TEST(rpc_publish_alt_packet, skips_null_empty_and_oversize_records)
{
    // When Snort hands detection a rebuilt RPC record, RpcPublishAltPacket is the gate.
    // This test checks three cases where publishing must NOT happen:
    //   - no record pointer at all (null)
    //   - a record that is only the 4-byte header with zero body bytes
    //   - a record larger than the packet can hold
    // If any of these wrongly published, detection would run on bad data or corrupt the
    // packet view. We also check the original packet pointer and size are unchanged.
    RpcPublishAltPacket(&packet, nullptr, 16);
    RpcPublishAltPacket(&packet, record, RPC_FRAG_HDR_SIZE);
    RpcPublishAltPacket(&packet, record, Packet::max_dsize + 1);

    CHECK_EQUAL(0, publish_count);
    POINTERS_EQUAL(original, packet.data);
    CHECK_EQUAL(sizeof(original), packet.dsize);
}

TEST(rpc_publish_alt_packet, publishes_non_empty_record_and_restores_packet_view)
{
    // When a valid RPC record slice is ready, Snort publishes an ALT_PACKET event so
    // nested rules can inspect just that record. This test feeds a normal 16-byte
    // record and checks:
    //   - publish happened exactly once
    //   - the event type is ALT_PACKET
    //   - detection saw the record bytes, not the original packet buffer
    // After publishing, the packet must be put back the way it was (same data pointer
    // and size) so the rest of the pipeline is not confused.
    RpcPublishAltPacket(&packet, record, 16);

    CHECK_EQUAL(1, publish_count);
    CHECK_EQUAL(IntrinsicEventIds::ALT_PACKET, published_event_id);
    POINTERS_EQUAL(record, published_data);
    CHECK_EQUAL(16, published_dsize);
    CHECK_EQUAL(PKT_REBUILT_STREAM, published_packet_flags);
    POINTERS_EQUAL(original, packet.data);
    CHECK_EQUAL(sizeof(original), packet.dsize);
}

TEST_GROUP(rpc_prep_chunk)
{
    RpcSsnData session = {};
    DataBuffer alt_buffer;
    uint8_t frag_body[64] = {};

    void setup() override
    {
        if (!alt_buffer.data)
            alt_buffer.allocate_data();
        alt_buffer.len = 0;
        memset(const_cast<uint8_t*>(alt_buffer.data), 0, alt_buffer.decode_blen);
        memset(&session, 0, sizeof(session));

        for (size_t i = 0; i < sizeof(frag_body); ++i)
            frag_body[i] = static_cast<uint8_t>(i + 1);

        CHECK(RpcChunkAppend(&session, frag_body, sizeof(frag_body)) == RPC_STATUS__SUCCESS);
    }

    void teardown() override
    {
        RpcChunksClear(&session);
    }
};

TEST(rpc_prep_chunk, advertises_header_plus_fragment_body)
{
    // RpcPrepChunkBuffer builds the alt buffer for partial RPC inspection. It must
    // write a proper SunRPC fragment header (4 bytes) followed by the body bytes
    // collected in the chunk list. This test checks:
    //   - total length is header size plus 64 body bytes
    //   - the header marks this as the last fragment and encodes length 64
    //   - the body bytes match what was appended earlier
    // Wrong layout here would make content rules match the wrong bytes.
    CHECK(RpcPrepChunkBuffer(&session, alt_buffer, true) == RPC_STATUS__SUCCESS);

    CHECK_EQUAL(RPC_FRAG_HDR_SIZE + sizeof(frag_body), alt_buffer.len);

    uint32_t marker = 0;
    memcpy_s(&marker, sizeof(marker), alt_buffer.data, sizeof(marker));
    CHECK_EQUAL(0x80000000 | sizeof(frag_body), ntohl(marker));
    MEMCMP_EQUAL(frag_body, alt_buffer.data + RPC_FRAG_HDR_SIZE, sizeof(frag_body));
}

TEST_GROUP(rpc_chunks_clear)
{
    RpcSsnData session = {};

    void setup() override
    {
        memset(&session, 0, sizeof(session));
    }

    void teardown() override
    {
        RpcChunksClear(&session);
    }
};

TEST(rpc_chunks_clear, resets_partial_serialized)
{
    // When buffered RPC body data is thrown away, all bookkeeping must reset too.
    // RpcChunksClear is called after a full flush or when tearing down a session.
    // If partial_serialized or body_buffered were left stale, the next partial flush
    // could fire too early or too late. This test seeds fake counts, clears, and
    // checks everything goes back to zero and the chunk list is empty.
    session.body_buffered = 300;
    session.partial_serialized = 256;
    RpcChunksClear(&session);

    CHECK_EQUAL(0, session.body_buffered);
    CHECK_EQUAL(0, session.partial_serialized);
    CHECK(session.chunks_head == nullptr);
}

TEST_GROUP(rpc_chunk_append)
{
    RpcSsnData session = {};

    void setup() override
    {
        memset(&session, 0, sizeof(session));
    }

    void teardown() override
    {
        RpcChunksClear(&session);
    }
};

TEST(rpc_chunk_append, fills_tail_node_before_allocating_another)
{
    // Body bytes are stored in a linked list of fixed-size nodes (80 bytes each).
    // This test checks we pack bytes into the current node before allocating another.
    // Append 80 one-byte chunks: should use exactly one node.
    // Append one more byte: should create a second node.
    // If we allocated a new node on every byte, memory and CPU would explode on
    // tiny TCP segments (the attack this rewrite fixes).
    const uint8_t byte = 0x01;

    for (unsigned i = 0; i < NODE_SIZE; ++i)
        CHECK(RpcChunkAppend(&session, &byte, 1) == RPC_STATUS__SUCCESS);

    CHECK_EQUAL(1, count_chunk_nodes(&session));
    CHECK_EQUAL(NODE_SIZE, session.body_buffered);

    CHECK(RpcChunkAppend(&session, &byte, 1) == RPC_STATUS__SUCCESS);

    CHECK_EQUAL(2, count_chunk_nodes(&session));
    CHECK_EQUAL(NODE_SIZE + 1, session.body_buffered);
}

TEST_GROUP(rpc_stateful_post_loop)
{
    Packet packet;
    IpsContext context;
    RpcSsnData session = {};
    std::vector<uint8_t> payload;

    void setup() override
    {
        reset_publish_state();
        depth_exceeded_events = 0;
        memset(&session, 0, sizeof(session));
        session.active = 1;
        memset(&rdstats, 0, sizeof(rdstats));

        packet.context = &context;
        packet.packet_flags = PKT_REBUILT_STREAM;

        if (!context.alt_data.data)
            context.alt_data.allocate_data();

        context.alt_data.len = 0;
        payload.clear();
    }

    void teardown() override
    {
        RpcChunksClear(&session);
    }

    void seed_stale_alt()
    {
        static const char tag[] = "STALE";
        memcpy_s(const_cast<uint8_t*>(context.alt_data.data), context.alt_data.decode_blen,
            tag, sizeof(tag) - 1);
        context.alt_data.len = sizeof(tag) - 1;
    }

    void run_inspection()
    {
        packet.data = payload.data();
        packet.dsize = (uint16_t)payload.size();
        CHECK(RpcStatefulInspection(&session, &packet) == RPC_STATUS__SUCCESS);
    }

    void begin_last_fragment(uint32_t body_len)
    {
        payload.clear();
        append_frag_hdr(payload, body_len, true);
        run_inspection();
    }

    void run_one_body_byte(uint8_t fill = 0x01)
    {
        payload.assign(1, fill);
        run_inspection();
    }
};

TEST(rpc_stateful_post_loop, partial_flush_at_quantum_without_prior_sync_publish)
{
    // A large RPC record may arrive over many TCP segments. Snort re-serializes buffered
    // body bytes into the alt buffer every 256 new bytes (the "quantum") so rules can
    // inspect progress before the full record arrives. This test sends one segment with
    // a header plus exactly 256 body bytes (no complete small record before it).
    // Expect: alt buffer is filled for detection, partial_flushes peg is 1, and no
    // full ALT_PACKET publish yet because the record is not finished.
    append_frag_hdr(payload, 300, true);
    append_body(payload, RPC_PARTIAL_FLUSH_QUANTUM, 0x55);

    run_inspection();

    CHECK_EQUAL(0, publish_count);
    CHECK_EQUAL(RPC_FRAG_HDR_SIZE + RPC_PARTIAL_FLUSH_QUANTUM, context.alt_data.len);
    CHECK_EQUAL(1, rdstats.partial_flushes);
}

TEST(rpc_stateful_post_loop, partial_flush_after_sync_publish_keeps_alt_for_next_record)
{
    // One packet can contain multiple RPC records. Record A (8 bytes) completes and
    // gets a full ALT_PACKET publish. Record B starts in the same packet and already
    // has 256 body bytes buffered. This test checks that after A is published, B still
    // gets a partial alt prep at the quantum boundary — detection is not skipped for
    // the second record just because the first one already published.
    append_frag_hdr(payload, 8, true);
    append_body(payload, 8, 0x41);
    append_frag_hdr(payload, 300, true);
    append_body(payload, RPC_PARTIAL_FLUSH_QUANTUM, 0x42);

    run_inspection();

    CHECK_EQUAL(1, publish_count);
    CHECK_EQUAL(RPC_FRAG_HDR_SIZE + RPC_PARTIAL_FLUSH_QUANTUM, context.alt_data.len);
    CHECK_EQUAL(RPC_PARTIAL_FLUSH_QUANTUM, session.partial_serialized);
    CHECK_EQUAL(1, rdstats.partial_flushes);
}

TEST(rpc_stateful_post_loop, skip_record_clears_alt)
{
    // When a record exceeds the 16 KB inspection cap, rpc_decode sets skip_record and
    // stops buffering further body data. Any leftover alt buffer from earlier work must
    // be cleared so stale bytes are not matched by rules. This test simulates that
    // state: skip_record is on, a stale alt buffer is seeded, and a tiny header-only
    // segment arrives. Expect alt_data.len becomes 0.
    session.skip_record = true;
    session.cur_frag_len = 4;
    session.cur_frag_received = 0;
    seed_stale_alt();

    payload.assign(RPC_FRAG_HDR_SIZE, 0x00);
    run_inspection();

    CHECK_EQUAL(0, context.alt_data.len);
}

TEST(rpc_stateful_post_loop, sub_quantum_body_without_sync_publish_defers_partial_flush)
{
    // Partial inspection only runs after 256 new body bytes accumulate. If fewer than
    // 256 bytes have arrived and no full record was published yet, Snort should hold
    // the bytes in the chunk list and NOT fill the alt buffer. This test sends 200
    // body bytes (below the quantum). Expect: no publish, no alt buffer, no partial
    // flush peg increment, but chunks still hold the 200 bytes for later.
    append_frag_hdr(payload, 300, true);
    append_body(payload, 200, 0x44);

    run_inspection();

    CHECK_EQUAL(0, publish_count);
    CHECK_EQUAL(0, context.alt_data.len);
    CHECK_EQUAL(0, rdstats.partial_flushes);
    CHECK(session.chunks_head != nullptr);
    CHECK_EQUAL(200, session.body_buffered);
}

TEST(rpc_stateful_post_loop, whole_packet_record_uses_fast_path_without_alt)
{
    // When a single small RPC record fits entirely in one TCP segment and is the only
    // thing in the packet, rpc_decode uses a fast path: rules can inspect the raw
    // packet data directly. No chunk list, no alt buffer, no partial flush work.
    // This test sends an 8-byte record as the whole payload. Expect zero publishes,
    // zero alt usage, and zero partial_flushes — the cheap path for normal traffic.
    append_frag_hdr(payload, 8, true);
    append_body(payload, 8, 0x45);

    run_inspection();

    CHECK_EQUAL(0, publish_count);
    CHECK_EQUAL(0, context.alt_data.len);
    CHECK_EQUAL(0, rdstats.partial_flushes);
}

TEST(rpc_stateful_post_loop, three_hundred_one_byte_appends_limit_partial_flushes)
{
    // An old bug flushed partial data on every tiny segment, causing O(N^2) work. The
    // fix only flushes when 256 *new* body bytes have arrived since the last partial
    // flush — not once per TCP segment. This test opens a 1000-byte fragment, then
    // sends 300 one-byte segments. Expect only 1 partial flush (at 256 bytes), not
    // 300. Sending 212 more bytes (total 512) should trigger a second flush at 512.
    begin_last_fragment(1000);

    for (unsigned i = 0; i < 300; ++i)
        run_one_body_byte(0x01);

    CHECK_EQUAL(300, session.body_buffered);
    CHECK_EQUAL(1, rdstats.partial_flushes);
    CHECK_EQUAL(RPC_PARTIAL_FLUSH_QUANTUM, session.partial_serialized);

    for (unsigned i = 0; i < 212; ++i)
        run_one_body_byte(0x02);

    CHECK_EQUAL(512, session.body_buffered);
    CHECK_EQUAL(2, rdstats.partial_flushes);
    CHECK_EQUAL(RPC_PARTIAL_FLUSH_QUANTUM * 2, session.partial_serialized);
}

TEST(rpc_stateful_post_loop, monolithic_body_triggers_one_partial_flush_per_segment)
{
    // One large TCP segment can deliver 1024 body bytes at once. The post-loop runs
    // once per inspect call and performs at most one partial prep, even if those bytes
    // span several 256-byte quanta internally. The fragment header declares 2048 bytes
    // so the record stays incomplete after this segment. Expect exactly 1 partial flush
    // and 1024 bytes still buffered in chunks — not 4 flushes from floor(1024/256).
    static constexpr unsigned k_body = RPC_PARTIAL_FLUSH_QUANTUM * 4;
    static constexpr unsigned k_declared = k_body * 2;

    append_frag_hdr(payload, k_declared, true);
    append_body(payload, k_body, 0x11);
    run_inspection();

    CHECK_EQUAL(1, rdstats.partial_flushes);
    CHECK(session.chunks_head != nullptr);
    CHECK_EQUAL(k_body, session.body_buffered);
}

TEST(rpc_stateful_post_loop, one_byte_segments_match_quantum_partial_flush_count)
{
    // Same 1024 body bytes as the monolithic test, but delivered as 1024 separate
    // one-byte TCP segments. Because each segment triggers its own post-loop, partial
    // flushes accumulate at every 256-byte boundary: 256, 512, 768, 1024 → 4 total.
    // The fragment is declared as 2048 bytes so the record does not complete early
    // on the last byte (which would clear chunks and skip the 4th post-loop flush).
    static constexpr unsigned k_body = RPC_PARTIAL_FLUSH_QUANTUM * 4;
    static constexpr unsigned k_declared = k_body * 2;

    begin_last_fragment(k_declared);

    for (unsigned i = 0; i < k_body; ++i)
        run_one_body_byte(0x22);

    CHECK_EQUAL(k_body / RPC_PARTIAL_FLUSH_QUANTUM, rdstats.partial_flushes);
}

TEST(rpc_stateful_post_loop, header_only_segments_do_not_increment_partial_flushes)
{
    // Attackers could send many packets that contain only RPC headers and no body
    // bytes ("zero-growth" flood). If partial flush ran on every such packet even
    // when no new body bytes arrived, CPU would still spike. This test first buffers
    // 512 body bytes and marks partial work as caught up (partial_serialized equals
    // body_buffered). Then it sends 100 header-only non-last fragments. Expect the
    // partial_flushes peg does not increase — no work when since_partial is zero.
    static constexpr unsigned k_body = RPC_PARTIAL_FLUSH_QUANTUM * 2;
    const uint8_t byte = 0x33;

    for (unsigned i = 0; i < k_body; ++i)
        CHECK(RpcChunkAppend(&session, &byte, 1) == RPC_STATUS__SUCCESS);

    session.partial_serialized = session.body_buffered;
    const PegCount flushes_before = rdstats.partial_flushes;

    for (unsigned i = 0; i < 100; ++i)
    {
        payload.clear();
        append_frag_hdr(payload, 0, false);
        run_inspection();
    }

    CHECK_EQUAL(flushes_before, rdstats.partial_flushes);
    CHECK_EQUAL(k_body, session.body_buffered);
}

TEST(rpc_stateful_post_loop, multi_small_fragments_do_not_trip_depth_exceeded)
{
    // A real SunRPC record can be split into hundreds of small fragments (~8 KB total).
    // That is normal traffic, not an attack. The 16 KB cap and 106:6 alert must NOT
    // fire on it. This test builds one packet with 200 fragments of 40 bytes each,
    // then runs inspection once. Expect: no skip_record, no 106:6 event queued, and
    // oversized_records peg stays at zero.
    static constexpr unsigned k_frags = 200;
    static constexpr unsigned k_frag_body = 40;

    for (unsigned i = 0; i < k_frags - 1; ++i)
    {
        append_frag_hdr(payload, k_frag_body, false);
        append_body(payload, k_frag_body, 0xAB);
    }

    append_frag_hdr(payload, k_frag_body, true);
    append_body(payload, k_frag_body, 0xAB);

    run_inspection();

    CHECK(!session.skip_record);
    CHECK_EQUAL(0, depth_exceeded_events);
    CHECK_EQUAL(0, rdstats.oversized_records);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
