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

// tcp_overlap_resolver_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "normalize/normalize.h"
#include "stream/tcp/tcp_module.h"
#include "stream/tcp/tcp_overlap_resolver.h"
#include "stream/tcp/tcp_reassembler.h"
#include "stream/tcp/tcp_reassembly_segments.h"
#include "stream/tcp/tcp_segment_descriptor.h"
#include "stream/tcp/tcp_segment_node.h"
#include "stream/tcp/tcp_stream_tracker.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------

THREAD_LOCAL TcpStats tcpStats;
THREAD_LOCAL PegCount norm_stats[PC_MAX][NORM_MODE_MAX];

NormMode Normalize_GetMode(NormFlags) { return NORM_MODE_TEST; }

namespace snort
{
void DetectionEngine::disable_content(Packet*) { }
void FlowDataStore::call_handlers(Packet*, FlowDataStore::FlowDataHandlerType) const { }
}

void TcpSegmentDescriptor::set_retransmit_flag() { }

TcpReassemblySegments::~TcpReassemblySegments() = default;
void TcpReassemblySegments::add_reassembly_segment(
    TcpSegmentDescriptor&, uint16_t, uint32_t, uint32_t, uint32_t, TcpSegmentNode*) { }
int TcpReassemblySegments::delete_reassembly_segment(TcpSegmentNode*) { return 0; }

bool TcpSegmentNode::is_retransmit(const uint8_t*, uint16_t, uint32_t, uint16_t, bool*)
{ return false; }

TcpStreamTracker::TcpStreamTracker(bool client) :
    client_tracker(client), tcp_state(client ? TCP_STATE_NONE : TCP_LISTEN), held_packet()
{ }
TcpStreamTracker::~TcpStreamTracker() = default;

TcpReassemblerIgnore::TcpReassemblerIgnore(bool) { }
uint32_t TcpReassemblerIgnore::perform_partial_flush(Flow*, Packet*&) { return 0; }

//--------------------------------------------------------------------------
// helpers
//--------------------------------------------------------------------------

// TcpSegmentNode uses the struct hack, so give it a tail to own.
struct SegStore
{
    TcpSegmentNode node;
    uint8_t tail[2048];
};

static TcpSegmentNode& make_segment(
    SegStore& store, uint32_t seq, uint16_t offset, uint16_t length, uint16_t cursor)
{
    store = SegStore();
    store.node.seq = seq;
    store.node.offset = offset;
    store.node.length = length;
    store.node.cursor = cursor;
    store.node.size = sizeof(store.tail);
    return store.node;
}

static SegStore dup_store;

// Like the real split: the copy starts where left does, keeps its cursor and follows left.
void TcpReassemblySegments::dup_reassembly_segment(TcpSegmentNode* left, TcpSegmentNode** retSeg)
{
    TcpSegmentNode& tsn =
        make_segment(dup_store, left->start_seq(), 0, left->length, left->cursor);
    insert(left, &tsn);
    *retSeg = &tsn;
}

// Reaches the protected overlap handlers without an inspection policy.
class ResolverPeer : public TcpOverlapResolver
{
public:
    using TcpOverlapResolver::left_overlap_keep_last;
    using TcpOverlapResolver::left_overlap_trim_first;
    using TcpOverlapResolver::right_overlap_truncate_existing;

private:
    void insert_left_overlap(TcpOverlapState&) override { }
    void insert_right_overlap(TcpOverlapState&) override { }
    void insert_full_overlap(TcpOverlapState&) override { }
};

TEST_GROUP(tcp_overlap_resolver_cursor)
{
};

// Regression for an out-of-bounds read when a right overlap truncates the
// front of a segment the scan cursor has already entered.
TEST(tcp_overlap_resolver_cursor, right_overlap_truncate_existing_rebases_cursor)
{
    TcpReassemblySegments seglist;
    TcpOverlapState tos(seglist);
    ResolverPeer peer;
    SegStore store;

    TcpSegmentNode& right = make_segment(store, 1000, 0, 1000, 900);

    tos.right = &right;
    tos.seq = 1500;
    tos.seq_end = 1950;
    tos.len = 450;
    tos.slide = 0;
    tos.overlap = 950;

    peer.right_overlap_truncate_existing(tos);

    CHECK_EQUAL(950, right.offset);
    CHECK_EQUAL(50, right.length);
    // cursor is relative to offset, which advanced by the whole overlap.
    CHECK_EQUAL(0, right.cursor);
    CHECK_EQUAL(50, right.unscanned());
}

TEST(tcp_overlap_resolver_cursor, right_overlap_truncate_existing_keeps_scanned_progress)
{
    TcpReassemblySegments seglist;
    TcpOverlapState tos(seglist);
    ResolverPeer peer;
    SegStore store;

    TcpSegmentNode& right = make_segment(store, 1000, 0, 1000, 900);

    tos.right = &right;
    tos.seq = 1100;
    tos.seq_end = 1200;
    tos.len = 100;
    tos.slide = 0;
    tos.overlap = 200;

    peer.right_overlap_truncate_existing(tos);

    CHECK_EQUAL(200, right.offset);
    CHECK_EQUAL(800, right.length);
    CHECK_EQUAL(700, right.cursor);
    CHECK_EQUAL(100, right.unscanned());
}

TEST(tcp_overlap_resolver_cursor, right_overlap_truncate_existing_slides_on_equal_start)
{
    TcpReassemblySegments seglist;
    TcpOverlapState tos(seglist);
    ResolverPeer peer;
    SegStore store;

    TcpSegmentNode& right = make_segment(store, 1000, 0, 1000, 900);

    tos.right = &right;
    tos.seq = 1000;
    tos.seq_end = 1400;
    tos.len = 400;
    tos.slide = 0;
    tos.overlap = 400;

    peer.right_overlap_truncate_existing(tos);

    CHECK_EQUAL(400, tos.slide);
    CHECK_EQUAL(0, right.offset);
    CHECK_EQUAL(1000, right.length);
    CHECK_EQUAL(900, right.cursor);
}

TEST(tcp_overlap_resolver_cursor, left_overlap_trim_first_clamps_cursor)
{
    TcpReassemblySegments seglist;
    TcpOverlapState tos(seglist);
    ResolverPeer peer;
    SegStore store;

    TcpSegmentNode& left = make_segment(store, 1000, 0, 1000, 900);

    tos.left = &left;
    tos.seq = 1400;
    tos.seq_end = 2200;
    tos.len = 800;

    peer.left_overlap_trim_first(tos);

    CHECK_EQUAL(400, left.length);
    CHECK_EQUAL(400, left.cursor);
    CHECK_EQUAL(0, left.unscanned());
}

// A truncation wider than int16_t must still shrink the segment.
TEST(tcp_overlap_resolver_cursor, right_overlap_truncate_existing_handles_wide_overlap)
{
    TcpReassemblySegments seglist;
    TcpOverlapState tos(seglist);
    ResolverPeer peer;
    SegStore store;

    TcpSegmentNode& right = make_segment(store, 1000, 0, 40000, 100);

    tos.right = &right;
    tos.seq = 900;
    tos.seq_end = 40000;
    tos.len = 39100;
    tos.slide = 0;
    tos.overlap = 39000;

    peer.right_overlap_truncate_existing(tos);

    CHECK_EQUAL(39000, right.offset);
    CHECK_EQUAL(1000, right.length);
    CHECK_EQUAL(0, right.cursor);
}

// The clamp is reached only by a node whose cursor already overran its length.
TEST(tcp_overlap_resolver_cursor, trim_front_clamps_overrun_cursor)
{
    SegStore store;
    TcpSegmentNode& seg = make_segment(store, 1000, 950, 50, 900);

    seg.trim_front(10);

    CHECK_EQUAL(960, seg.offset);
    CHECK_EQUAL(40, seg.length);
    CHECK_EQUAL(40, seg.cursor);
    CHECK_EQUAL(0, seg.unscanned());
}

// A split trims both halves, so each keeps its cursor inside its own data.
TEST(tcp_overlap_resolver_cursor, left_overlap_keep_last_split_rebases_both_cursors)
{
    TcpReassemblerIgnore reassembler(false);
    TcpStreamTracker tracker(false);
    tracker.reassembler = &reassembler;

    TcpReassemblySegments seglist;
    seglist.tracker = &tracker;
    TcpOverlapState tos(seglist);
    ResolverPeer peer;
    SegStore store;

    TcpSegmentNode& left = make_segment(store, 900, 100, 1000, 900);

    tos.left = &left;
    tos.seq = 1200;
    tos.seq_end = 1400;
    tos.len = 200;

    peer.left_overlap_keep_last(tos);

    CHECK_EQUAL(200, left.length);
    CHECK_EQUAL(200, left.cursor);
    POINTERS_EQUAL(&dup_store.node, tos.right);
    CHECK_EQUAL(1400, tos.right->start_seq());
    CHECK_EQUAL(600, tos.right->length);
    CHECK_EQUAL(500, tos.right->cursor);
    CHECK_EQUAL(100, tos.right->unscanned());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
