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
// user_session_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream/user/user_session.h"

#include <cstdlib>

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/flow_control.h"
#include "framework/pig_pen.h"
#include "main/snort_config.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "stream/flush_bucket.h"
#include "stream/paf.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "stream/user/stream_user.h"
#include "stream/user/user_module.h"
#include "trace/trace_api.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------

THREAD_LOCAL const Trace* stream_user_trace = nullptr;

static Packet s_rebuilt(false);
static uint8_t s_pdu_buf[Packet::max_dsize];
static const int32_t* s_paf_results = nullptr;
static unsigned s_paf_result_count = 0;
static unsigned s_paf_calls = 0;
static uint32_t s_paf_lens[4] = { };
static uint32_t s_paf_totals[4] = { };

namespace snort
{
THREAD_LOCAL SnortConfig* snort_conf = nullptr;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

Flow::Flow() = default;
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;
void FlowStash::reset() { }
void Flow::set_direction(Packet*) { }
void Flow::set_expire(const Packet*, uint64_t) { }
void Flow::set_ttl(Packet*, bool) { }
void Flow::swap_roles() { }
void Flow::restart(bool) { }
void Flow::restart(Packet&, bool) { }

void TraceApi::filter(const Packet&) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }

void trace_vprintf(
    const char*, TraceLevel, const char*, const Packet*, const char*, va_list)
{ }

THREAD_LOCAL bool TimeProfilerStats::enabled = false;

Packet::Packet(bool) { }
Packet::~Packet() = default;

Packet* DetectionEngine::set_next_packet(const Packet*, Flow*)
{ return &s_rebuilt; }

Packet* DetectionEngine::get_current_packet()
{ return &s_rebuilt; }

uint8_t* DetectionEngine::get_next_buffer(unsigned& max)
{
    max = sizeof(s_pdu_buf);
    return s_pdu_buf;
}

bool PigPen::inspect_rebuilt(Packet*) { return true; }

StreamSplitter* Stream::get_splitter(Flow*, bool)
{ return nullptr; }

void Stream::flush_client(Packet*) { }
void Stream::flush_server(Packet*) { }
bool Stream::expired_flow(Flow*, Packet*) { return false; }
bool Stream::blocked_flow(Packet*) { return false; }
bool Stream::ignored_flow(Flow*, Packet*) { return false; }

void* snort_alloc(size_t n) { return std::calloc(1, n); }
void snort_free(void* p) { std::free(p); }
}

uint16_t FlushBucket::get_size()
{ return 1; }

bool FlowControl::apply_flow_state(Flow*, Packet*, bool)
{ return true; }

StreamUserConfig* get_user_cfg(Inspector*)
{ return nullptr; }

void paf_setup(PAF_State*) { }
void paf_reset(PAF_State*) { }
void paf_clear(PAF_State*) { }

int32_t paf_check(
    StreamSplitter*, PAF_State*, Packet*, const uint8_t*, uint32_t len,
    uint32_t total, uint32_t, uint32_t* flags)
{
    const unsigned call = s_paf_calls++;

    if ( call < 4 )
    {
        s_paf_lens[call] = len;
        s_paf_totals[call] = total;
    }

    if ( call >= s_paf_result_count )
        return -1;

    const int32_t result = s_paf_results[call];
    if ( result >= 0 )
        *flags |= PKT_PDU_HEAD | PKT_PDU_TAIL;

    return result;
}

//--------------------------------------------------------------------------
// test splitter
//--------------------------------------------------------------------------

// reports back only what the front segment can legally supply; the base
// splitter reports the whole request, which is what underflows the length

struct FlushRecord
{
    unsigned offset = 0;
    unsigned len = 0;
    uint32_t flags = 0;
};

class RecordingSplitter : public StreamSplitter
{
public:
    static const unsigned max_calls = 4;

    RecordingSplitter(const unsigned* seg_lens, unsigned seg_count) :
        StreamSplitter(true), lens(seg_lens), count(seg_count) { }

    Status scan(Packet*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override
    { return StreamSplitter::SEARCH; }

    const StreamBuffer reassemble(
        Flow*, unsigned, unsigned offset, const uint8_t*,
        unsigned len, uint32_t flags, unsigned& copied) override
    {
        if ( calls < max_calls )
        {
            rec[calls].offset = offset;
            rec[calls].len = len;
            rec[calls].flags = flags;
        }
        // past the loaded segments there is no legal supply to report, so take
        // the whole request and let the call count assertion report it
        copied = ( calls < count and len > lens[calls] ) ? lens[calls] : len;
        ++calls;
        return { nullptr, 0 };
    }

    // the tracker owns its splitter; these instances are stack allocated
    void go_away() override { }
    bool is_paf() override { return true; }

    FlushRecord rec[max_calls];
    unsigned calls = 0;

private:
    const unsigned* lens;
    const unsigned count;
};

static void load(UserTracker& ut, const unsigned* lens, unsigned count)
{
    static const uint8_t payload[8192] = { };

    for ( unsigned i = 0; i < count; ++i )
    {
        ut.seg_list.push_back(UserSegment::init(payload, lens[i]));
        ut.total += lens[i];
    }
}

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

TEST_GROUP(user_tracker_flush)
{
    void setup() override
    {
        s_paf_results = nullptr;
        s_paf_result_count = 0;
        s_paf_calls = 0;
    }

    void teardown() override
    {
        s_paf_results = nullptr;
        s_paf_result_count = 0;
    }
};

// Regression for an out-of-bounds write via UserSegment::len underflow
TEST(user_tracker_flush, flush_across_two_segments_ending_on_the_boundary)
{
    const unsigned lens[] = { 1652, 2056 };
    const unsigned amount = lens[0] + lens[1];

    RecordingSplitter ss(lens, 2);
    UserTracker ut;
    ut.splitter = &ss;
    load(ut, lens, 2);

    Packet p(false);
    p.flow = nullptr;
    ut.flush(&p, amount, PKT_PDU_HEAD | PKT_PDU_TAIL);

    CHECK_EQUAL(2, ss.calls);

    CHECK_EQUAL(0, ss.rec[0].offset);
    CHECK_EQUAL(lens[0], ss.rec[0].len);
    CHECK_EQUAL(0u, ss.rec[0].flags & PKT_PDU_TAIL);

    CHECK_EQUAL(lens[0], ss.rec[1].offset);
    CHECK_EQUAL(lens[1], ss.rec[1].len);
    CHECK(ss.rec[1].flags & PKT_PDU_TAIL);

    CHECK_EQUAL(0, ut.total);
    CHECK(ut.seg_list.empty());

    ut.splitter = nullptr;
}

TEST(user_tracker_flush, partial_flush_across_two_segments)
{
    const unsigned lens[] = { 1652, 2056 };
    const unsigned amount = lens[0] + 1000;

    RecordingSplitter ss(lens, 2);
    UserTracker ut;
    ut.splitter = &ss;
    load(ut, lens, 2);

    Packet p(false);
    p.flow = nullptr;
    ut.flush(&p, amount, PKT_PDU_HEAD | PKT_PDU_TAIL);

    CHECK_EQUAL(2, ss.calls);
    CHECK_EQUAL(lens[0], ss.rec[1].offset);
    CHECK_EQUAL(1000, ss.rec[1].len);

    // the tail segment keeps the bytes the flush did not take
    CHECK_EQUAL(1, ut.seg_list.size());
    CHECK_EQUAL(lens[1] - 1000, ut.seg_list.front()->get_len());
    CHECK_EQUAL(lens[0] + lens[1] - amount, ut.total);

    ut.splitter = nullptr;
}

TEST(user_tracker_flush, single_segment_flush)
{
    const unsigned lens[] = { 1400 };

    RecordingSplitter ss(lens, 1);
    UserTracker ut;
    ut.splitter = &ss;
    load(ut, lens, 1);

    Packet p(false);
    p.flow = nullptr;
    ut.flush(&p, lens[0], PKT_PDU_HEAD | PKT_PDU_TAIL);

    CHECK_EQUAL(1, ss.calls);
    CHECK_EQUAL(0, ss.rec[0].offset);
    CHECK_EQUAL(lens[0], ss.rec[0].len);
    CHECK(ss.rec[0].flags & PKT_PDU_TAIL);
    CHECK_EQUAL(0, ut.total);
    CHECK(ut.seg_list.empty());

    ut.splitter = nullptr;
}

TEST(user_tracker_flush, split_packet_uses_running_scan_total)
{
    RecordingSplitter ss(nullptr, 0);
    UserTracker ut;
    ut.splitter = &ss;

    Packet p(false);
    p.flow = nullptr;
    p.packet_flags = PKT_FROM_CLIENT;
    p.data = s_pdu_buf;
    p.dsize = 1000;
    ut.add_data(&p);

    // Fill the remaining 3064 bytes in the first bucket and put the final
    // 936 bytes in a second segment.
    p.dsize = 4000;
    ut.add_data(&p);

    CHECK_EQUAL(3, s_paf_calls);
    CHECK_EQUAL(1000, s_paf_lens[0]);
    CHECK_EQUAL(1000, s_paf_totals[0]);
    CHECK_EQUAL(3064, s_paf_lens[1]);
    CHECK_EQUAL(4064, s_paf_totals[1]);
    CHECK_EQUAL(936, s_paf_lens[2]);
    CHECK_EQUAL(5000, s_paf_totals[2]);
    CHECK_EQUAL(2, ut.seg_list.size());
    CHECK_EQUAL(5000, ut.total);

    ut.splitter = nullptr;
}

TEST(user_tracker_flush, partial_flush_rescans_retained_tail)
{
    // Fill one bucket, then flush 936 bytes of the next segment.  Its retained
    // 1120-byte tail must be presented to PAF again.
    const unsigned copy_lens[] = { 4064, 936, 1120 };
    const int32_t paf_results[] = { -1, 5000, 1120 };

    s_paf_results = paf_results;
    s_paf_result_count = 3;

    RecordingSplitter ss(copy_lens, 3);
    UserTracker ut;
    ut.splitter = &ss;

    Packet p(false);
    p.flow = nullptr;
    p.packet_flags = PKT_FROM_CLIENT;
    p.data = s_pdu_buf;
    p.dsize = 4064;
    ut.add_data(&p);

    p.dsize = 2056;
    ut.add_data(&p);

    CHECK_EQUAL(3, s_paf_calls);
    CHECK_EQUAL(4064, s_paf_lens[0]);
    CHECK_EQUAL(4064, s_paf_totals[0]);
    CHECK_EQUAL(2056, s_paf_lens[1]);
    CHECK_EQUAL(6120, s_paf_totals[1]);
    CHECK_EQUAL(1120, s_paf_lens[2]);
    CHECK_EQUAL(1120, s_paf_totals[2]);

    CHECK_EQUAL(3, ss.calls);
    CHECK_EQUAL(4064, ss.rec[0].len);
    CHECK_EQUAL(936, ss.rec[1].len);
    CHECK_EQUAL(1120, ss.rec[2].len);
    CHECK_EQUAL(0, ut.total);
    CHECK(ut.seg_list.empty());

    ut.splitter = nullptr;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
