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

// dce_smb2_lru_test.cc author Karthik Subramanian <ksubram6@cisco.com>

// Victim selection policy for SMB2 file tracker eviction, which packet-level tests cannot pin
// down. The ftracker_memcap regression pcaps cover the end-to-end behaviour.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../dce_smb2.h"
#include "../dce_smb2_utils.h"

#include "detection/detection_engine.h"
#include "file_api/file_service.h"
#include "flow/flow.h"
#include "utils/util.h"

#include "catch/catch.hpp"

#include <cstdarg>
#include <iterator>
#include <vector>

using namespace snort;

namespace
{
FlowKey test_key {};
Flow test_flow;
Packet test_packet;

// A memcap admitting exactly n file trackers on top of one session and one tree tracker.
size_t memcap_for(unsigned n)
{
    return sizeof(DCE2_Smb2SessionTracker) + sizeof(DCE2_Smb2TreeTracker)
        + (n * SMB2_FTRACKER_CACHE_COST);
}

// One session with a single disk tree. Teardown repeats the order dce2_smb_tterm uses.
class Fixture
{
public:
    explicit Fixture(unsigned capacity)
    {
        dce2_smb_stats = { };
        test_key = {};
        test_flow.key = &test_key;
        test_packet.flow = &test_flow;
        DCE2_Smb2FtrackerLruInit();
        DCE2_SmbSessionCacheInit(memcap_for(capacity));
        str = new DCE2_Smb2SessionTracker(1);
        ttr = new DCE2_Smb2TreeTracker(1, SMB2_SHARE_TYPE_DISK);
        str->insertTtracker(1, ttr);
        baseline = smb2_session_cache->current_size;
    }

    ~Fixture()
    {
        // ~str reads from the channels, so it must die while they are still alive.
        delete str;
        for ( auto* ssd : channels )
            delete ssd;
        channels.clear();
        delete smb2_session_cache;
        smb2_session_cache = nullptr;
        DCE2_Smb2FtrackerLruTerm();
    }

    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    // Look up without disturbing recency, unlike findFtracker which splices to the front.
    DCE2_Smb2FileTracker* peek(uint64_t file_id) const
    { return ttr->file_trackers.Find(file_id); }

    // Fill until the cap forces the first eviction, without hard-coding how many that took.
    unsigned fill_to_cap()
    {
        while (!dce2_smb_stats.v2_ftracker_evicted)
        {
            REQUIRE(next_id < 10000);   // a cap that never bites would otherwise spin
            REQUIRE(DCE2_Smb2CreateFileTracker(next_id++, ttr, str) != nullptr);
        }
        return smb2_ftracker_lru->size();
    }

    void churn(unsigned rounds)
    {
        for ( unsigned i = 0; i < rounds; ++i )
            REQUIRE(DCE2_Smb2CreateFileTracker(next_id++, ttr, str) != nullptr);
    }

    // Register a synthetic TCP channel. test_key is mutated so each gets a distinct flow_key.
    DCE2_Smb2SsnData* add_channel()
    {
        ++test_key.port_l;
        auto* ssd = new DCE2_Smb2SsnData();
        str->insertConnectionTracker(ssd->flow_key, ssd);
        channels.push_back(ssd);
        return ssd;
    }

    DCE2_Smb2SessionTracker* str = nullptr;
    DCE2_Smb2TreeTracker* ttr = nullptr;
    size_t baseline = 0;
    uint64_t next_id = 1;
    std::vector<DCE2_Smb2SsnData*> channels;
};

void mark_all_with_learned_state()
{
    for ( auto* ftr : *smb2_ftracker_lru )
        ftr->file_name_hash = 0xabcd;
}
}

THREAD_LOCAL dce2SmbStats dce2_smb_stats;
THREAD_LOCAL const snort::Trace* dce_smb_trace = nullptr;

namespace snort
{
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;

Packet::Packet(bool)
{
}

Packet::~Packet()
{
}

void Packet::reset()
{
}

Packet* DetectionEngine::get_current_packet()
{
    return &test_packet;
}

int DetectionEngine::queue_event(unsigned, unsigned)
{
    return 0;
}

int64_t FileService::get_max_file_depth(FileConfig*)
{
    return 0;
}

void WarningMessage(const char*, ...) { }

uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }

void trace_vprintf(const char*, unsigned char, const char*, const Packet*, const char*, va_list) { }
}

void DCE2_CoCleanTracker(DCE2_CoTracker*)
{
}

void DCE2_Smb2Setup(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint64_t, const uint8_t*,
    const uint8_t*)
{
}

void DCE2_Smb2TreeConnect(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    DCE2_Smb2SessionTracker*, uint32_t)
{
}

void DCE2_Smb2TreeDisconnect(DCE2_Smb2SsnData*, const uint8_t*, const uint8_t*)
{
}

void DCE2_Smb2Create(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    uint64_t, uint64_t, uint32_t)
{
}

void DCE2_Smb2Read(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    DCE2_Smb2SessionTracker*, DCE2_Smb2TreeTracker*, uint64_t)
{
}

void DCE2_Smb2Write(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    DCE2_Smb2SessionTracker*, DCE2_Smb2TreeTracker*, uint64_t)
{
}

void DCE2_Smb2SetInfo(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    DCE2_Smb2TreeTracker*)
{
}

bool DCE2_Smb2ProcessFileData(DCE2_Smb2SsnData*, const uint8_t*, uint32_t)
{
    return false;
}

void DCE2_Smb2CloseCmd(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    DCE2_Smb2TreeTracker*, DCE2_Smb2SessionTracker*, uint64_t)
{
}

void DCE2_Smb2Logoff(DCE2_Smb2SsnData*, const uint8_t*, const uint64_t)
{
}

void DCE2_Smb2IoctlCommand(DCE2_Smb2SsnData*, const Smb2Hdr*, const uint8_t*, const uint8_t*,
    DCE2_Smb2SessionTracker*, DCE2_Smb2TreeTracker*, uint64_t)
{
}

// cppcheck-suppress syntaxError
TEST_CASE("file trackers stay within the smb memcap", "[dce_smb2_lru]")
{
    Fixture f(40);
    const unsigned live = f.fill_to_cap();

    f.churn(500);

    // One in, one out, so the population stays flat however many distinct fileIds arrive.
    CHECK(smb2_ftracker_lru->size() == live);
    CHECK(smb2_session_cache->current_size <= smb2_session_cache->max_size);
    CHECK(dce2_smb_stats.v2_ftracker_evicted >= 500);
    CHECK(dce2_smb_stats.v2_max_file_trackers == live);
}

TEST_CASE("eviction prefers a pristine tracker over one carrying learned state",
    "[dce_smb2_lru]")
{
    Fixture f(40);
    const unsigned live = f.fill_to_cap();
    REQUIRE(live > 4);

    mark_all_with_learned_state();

    // Reset one node in from the tail so the oldest is no longer the cheapest to lose.
    auto it = smb2_ftracker_lru->rbegin();
    std::advance(it, 3);
    const uint64_t pristine = (*it)->file_id;
    (*it)->file_name_hash = 0;

    const uint64_t oldest = smb2_ftracker_lru->back()->file_id;
    REQUIRE(pristine != oldest);

    f.churn(1);

    // Age loses to inspection value: the older tracker survives because a name was learned.
    CHECK(f.peek(pristine) == nullptr);
    CHECK(f.peek(oldest) != nullptr);
    CHECK(dce2_smb_stats.v2_ftracker_evict_live == 0);
}

TEST_CASE("eviction spares reassembly state until nothing else is available",
    "[dce_smb2_lru]")
{
    Fixture f(40);
    f.fill_to_cap();

    // The scan skips any candidate holding DCE/RPC reassembly state.
    for ( auto* ftr : *smb2_ftracker_lru )
        ftr->co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));

    const uint64_t oldest = smb2_ftracker_lru->back()->file_id;
    const PegCount live_before = dce2_smb_stats.v2_ftracker_evict_live;

    f.churn(1);

    // Nothing acceptable in the window, so eviction fell back to plain LRU.
    CHECK(f.peek(oldest) == nullptr);
    CHECK(dce2_smb_stats.v2_ftracker_evict_live == live_before + 1);
}

TEST_CASE("a lookup renews a tracker so it escapes the tail", "[dce_smb2_lru]")
{
    Fixture f(40);
    const unsigned live = f.fill_to_cap();
    REQUIRE(live > 1);

    // Start from the worst case: the tracker about to be evicted next.
    const uint64_t hot = smb2_ftracker_lru->back()->file_id;
    REQUIRE(f.ttr->findFtracker(hot) != nullptr);
    CHECK(smb2_ftracker_lru->front()->file_id == hot);

    for ( unsigned i = 0; i < 500; ++i )
    {
        f.churn(1);
        REQUIRE(f.ttr->findFtracker(hot) != nullptr);
    }

    // A tracker that keeps being used keeps being spliced forward, so it never reaches the tail.
    CHECK(f.peek(hot) != nullptr);
}

TEST_CASE("a lone tracker is kept rather than evicted for its own successor",
    "[dce_smb2_lru]")
{
    // Only reachable by misconfiguration, but with one node the scan would have no choice.
    Fixture f(1);

    REQUIRE(DCE2_Smb2CreateFileTracker(1, f.ttr, f.str) != nullptr);
    REQUIRE(smb2_ftracker_lru->size() == 1);

    REQUIRE(DCE2_Smb2CreateFileTracker(2, f.ttr, f.str) != nullptr);

    // Both survive, overshooting the cap by one. Bounded: once the list holds two the
    // guard no longer applies.
    CHECK(dce2_smb_stats.v2_ftracker_evicted == 0);
    CHECK(f.peek(1) != nullptr);
    CHECK(f.peek(2) != nullptr);
    CHECK(smb2_session_cache->current_size
        <= smb2_session_cache->max_size + SMB2_FTRACKER_CACHE_COST);

    // The third creation finds two candidates, so the guard steps aside and the oldest goes.
    REQUIRE(DCE2_Smb2CreateFileTracker(3, f.ttr, f.str) != nullptr);
    CHECK(dce2_smb_stats.v2_ftracker_evicted == 1);
    CHECK(f.peek(1) == nullptr);
    CHECK(smb2_ftracker_lru->size() == 2);
}

TEST_CASE("the victim scan is bounded so eviction cannot be made expensive",
    "[dce_smb2_lru]")
{
    Fixture f(SMB2_FTRACKER_EVICT_SCAN * 2);
    const unsigned live = f.fill_to_cap();
    REQUIRE(live > SMB2_FTRACKER_EVICT_SCAN + 1);

    // co_tracker candidates are skipped without consuming the active-test budget, so arming
    // the tail-most SMB2_FTRACKER_EVICT_SCAN of them isolates the scan bound.
    unsigned armed = 0;
    for (auto it = smb2_ftracker_lru->rbegin();
        it != smb2_ftracker_lru->rend() and armed < SMB2_FTRACKER_EVICT_SCAN; ++it, ++armed)
    {
        (*it)->co_tracker = (DCE2_CoTracker*)snort_calloc(sizeof(DCE2_CoTracker));
    }
    REQUIRE(armed == SMB2_FTRACKER_EVICT_SCAN);

    // The node just outside the bound is a pristine victim an unbounded scan would find.
    auto target_it = smb2_ftracker_lru->rbegin();
    std::advance(target_it, SMB2_FTRACKER_EVICT_SCAN);
    const uint64_t pristine_id = (*target_it)->file_id;
    REQUIRE((*target_it)->co_tracker == nullptr);
    REQUIRE((*target_it)->max_offset == 0);
    REQUIRE((*target_it)->file_name_hash == 0);

    const uint64_t oldest = smb2_ftracker_lru->back()->file_id;
    const PegCount live_before = dce2_smb_stats.v2_ftracker_evict_live;

    f.churn(1);

    CHECK(f.peek(pristine_id) != nullptr);
    CHECK(f.peek(oldest) == nullptr);
    CHECK(dce2_smb_stats.v2_ftracker_evict_live == live_before + 1);
}

TEST_CASE("file tracker accounting returns to its baseline", "[dce_smb2_lru]")
{
    Fixture f(40);
    const unsigned count = 20;

    for ( uint64_t id = 1; id <= count; ++id )
        REQUIRE(DCE2_Smb2CreateFileTracker(id, f.ttr, f.str) != nullptr);

    REQUIRE(dce2_smb_stats.v2_ftracker_evicted == 0);
    CHECK(smb2_session_cache->current_size
        == f.baseline + (count * SMB2_FTRACKER_CACHE_COST));

    for ( uint64_t id = 1; id <= count; ++id )
        f.ttr->removeFtracker(id);

    // Asymmetry between the charge and the refund would drift into a cap that can never be met.
    CHECK(smb2_session_cache->current_size == f.baseline);
    CHECK(smb2_ftracker_lru->empty());
}

TEST_CASE("eviction spares a tracker that is an active transfer", "[dce_smb2_lru]")
{
    Fixture f(40);
    const unsigned live = f.fill_to_cap();
    REQUIRE(live > 4);

    mark_all_with_learned_state();

    // Point a channel at the tail, the one plain LRU would take.
    DCE2_Smb2SsnData* ch = f.add_channel();
    DCE2_Smb2FileTracker* tail = smb2_ftracker_lru->back();
    const uint64_t active_id = tail->file_id;
    ch->ftracker_tcp = tail;

    const PegCount live_before = dce2_smb_stats.v2_ftracker_evict_live;
    f.churn(1);

    // The active tracker survived; something else was taken instead.
    CHECK(f.peek(active_id) != nullptr);
    CHECK(dce2_smb_stats.v2_ftracker_evict_live == live_before);
    CHECK(dce2_smb_stats.v2_ftracker_evicted > 0);
}

TEST_CASE("eviction nulls the back-pointer preventing UAF", "[dce_smb2_lru]")
{
    Fixture f(40);

    REQUIRE(DCE2_Smb2CreateFileTracker(1, f.ttr, f.str) != nullptr);
    DCE2_Smb2FileTracker* ftr = f.peek(1);
    REQUIRE(ftr != nullptr);

    DCE2_Smb2SsnData* ch = f.add_channel();
    ch->ftracker_tcp = ftr;

    // ~DCE2_Smb2FileTracker must null any pointer to itself. This is what makes eviction UAF-safe.
    f.ttr->removeFtracker(1);

    CHECK(ch->ftracker_tcp == nullptr);
}

TEST_CASE("the active-test budget forces a safe live eviction", "[dce_smb2_lru]")
{
    // Past SMB2_FTRACKER_ACTIVE_TESTS the scan breaks out and falls through to the tail.
    Fixture f(40);
    const unsigned live = f.fill_to_cap();
    REQUIRE(live > SMB2_FTRACKER_ACTIVE_TESTS + 2);

    mark_all_with_learned_state();

    // Clear co_tracker so the scan reaches is_ftracker_active instead of skipping.
    for ( auto* ftr : *smb2_ftracker_lru )
        ftr->co_tracker = nullptr;

    // Wire each tracker inward from the tail to a separate channel, so every one tests active.
    std::vector<DCE2_Smb2SsnData*> active_channels;
    auto it = smb2_ftracker_lru->rbegin();
    for ( unsigned i = 0; i < SMB2_FTRACKER_ACTIVE_TESTS + 2 and
        it != smb2_ftracker_lru->rend(); ++i, ++it )
    {
        DCE2_Smb2SsnData* ch = f.add_channel();
        ch->ftracker_tcp = *it;
        active_channels.push_back(ch);
    }

    const DCE2_Smb2FileTracker* tail = smb2_ftracker_lru->back();
    const uint64_t tail_id = tail->file_id;
    const DCE2_Smb2SsnData* tail_channel = active_channels[0];
    REQUIRE(tail_channel->ftracker_tcp == tail);

    const PegCount live_before = dce2_smb_stats.v2_ftracker_evict_live;
    f.churn(1);

    // Budget exhausted, so the fallback takes the tail and must null the channel's pointer.
    CHECK(dce2_smb_stats.v2_ftracker_evict_live == live_before + 1);
    CHECK(f.peek(tail_id) == nullptr);
    CHECK(tail_channel->ftracker_tcp == nullptr);
}
