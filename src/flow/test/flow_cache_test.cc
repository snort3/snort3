//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Cisco and/or its affiliates. All rights reserved.
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

// flow_cache_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_common.h>
#include <set>

#include "flow/flow_control.h"

#include "control/control.h"
#include "detection/detection_engine.h"
#include "flow/dump_flows.h"
#include "flow/dump_flows_serializer.h"
#include "flow/expect_cache.h"
#include "flow/flow_cache.h"
#include "flow/ha.h"
#include "flow/session.h"
#include "helpers/policy_switcher.h"
#include "main/analyzer.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "stream/base/stream_module.h"
#include "utils/util.h"
#include "trace/trace_api.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "flow_stubs.h"

using namespace snort;

THREAD_LOCAL const Trace* stream_trace = nullptr;
THREAD_LOCAL FlowControl* flow_con = nullptr;
THREAD_LOCAL BaseStats stream_base_stats = {};

Analyzer* Analyzer::get_local_analyzer() { return nullptr; }
void Analyzer::resume(uint64_t) { }

void Active::drop_packet(snort::Packet const*, bool) { }
void Active::suspend(ActiveSuspendReason) { }
void Active::resume() { }
void Active::set_drop_reason(char const*) { }

DetectionEngine::DetectionEngine() = default;
DetectionEngine::~DetectionEngine() = default;
void DetectionEngine::disable_all(Packet*) { }

const SnortConfig* SnortConfig::get_conf() { return nullptr; }
unsigned SnortConfig::get_reload_id() { return 0; }

Flow* HighAvailabilityManager::import(Packet&, FlowKey&) { return nullptr; }

// Test-only controllable stub. Callers add a Flow* to force in_standby()
// to return true for that flow. Each TEST_GROUP that uses this must
// clear the set in setup()/teardown() (see flow_cache_move_on_excess)
// so a prior test's leaked pointer cannot alias a later allocation.
static std::set<const Flow*> ha_standby_flows;
static void set_standby(const Flow* f, bool on)
{ if ( on ) ha_standby_flows.insert(f); else ha_standby_flows.erase(f); }
// cppcheck-suppress constParameterPointer
bool HighAvailabilityManager::in_standby(Flow* f)
{ return ha_standby_flows.count(f) != 0; }

uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) {}

// Mock counter for preemptive_kick calls
static unsigned preemptive_kick_count = 0;

void ThreadConfig::preemptive_kick() { preemptive_kick_count++; }
unsigned ThreadConfig::get_instance_max() { return 1; }

// Helper function to reset and get kick count
unsigned get_preemptive_kick_count() { return preemptive_kick_count; }
void reset_preemptive_kick_count() { preemptive_kick_count = 0; }

SfIpRet SfIp::set(void const*, int) { return SFIP_SUCCESS; }
SfIpRet SfIp::set(void const*) { return SFIP_SUCCESS; }
SfIpRet SfIp::pton(const int, const char* ) { return SFIP_SUCCESS; }

const char* SfIp::ntop(char* buf, int) const
{ buf[0] = 0; return buf; }

const char* SfIp::ntop(SfIpString buf) const
{ buf[0] = 0; return buf; }

bool ControlConn::respond(const char*, ...) { return true; }

class TcpStreamTracker;
const char* stream_tcp_state_to_str(const TcpStreamTracker&) { return "error"; }

void LogMessage(const char*, ...) { }

PolicySwitcher::PolicySwitcher(snort::Flow*) { }
PolicySwitcher::~PolicySwitcher() { }

namespace snort
{
Flow::Flow() { }
Flow::~Flow() = default;
void Flow::init(PktType) { }
void Flow::flush(bool) { }

// the real reset() reaches Flow::restart() through Session::cleanup(), which
// makes a still-blocked flow a candidate again; set this to model that
FlowCache* test_reset_relink_cache = nullptr;

void Flow::reset(bool)
{
    if ( test_reset_relink_cache and was_blocked() )
        test_reset_relink_cache->relink_uni(this);
}

void Flow::trust() { }
void Flow::free_flow_data() { }
void Flow::set_block_flags(uint32_t drop_flags) { ssn_state.session_flags |= drop_flags; }
void Flow::set_client_initiate(Packet*) { }
void Flow::set_direction(Packet*) { }
void Flow::set_mpls_layer_per_dir(const Packet*) { }
void FlowStash::reset() { }
FlowDataStore::~FlowDataStore() = default;

IpsContext::IpsContext(unsigned) { }
IpsContext::~IpsContext() = default;

void IpsContextChain::push_back(IpsContext* c)
{
    if ( !_front )
        _front = c;
    _back = c;
}

void packet_gettimeofday(struct timeval* ) { }
SO_PUBLIC void ts_print(const struct timeval*, char*, bool) { }

void Stream::disable_reassembly(Flow*) { }

time_t packet_time() { return 0; }

void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}

unsigned get_instance_id() { return 0; }
unsigned get_relative_instance_number() { return 1; }

namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
bool Stream::midstream_allowed(Packet const*, bool)
{ return false; }
}

ExpectCache::ExpectCache(uint32_t) { }
ExpectCache::~ExpectCache() = default;

bool ExpectCache::check(Packet*, Flow*) { return true; }

int ExpectCache::add_flow(const Packet*, PktType, IpProtocol, const SfIp*, uint16_t,
    const SfIp*, uint16_t, char, FlowData*, SnortProtocolId, bool, bool, bool, bool)
{
    return 1;
}
unsigned int get_random_seed()
{ return 3193; }

class DumpFlowsTest : public DumpFlows
{
    public:
        DumpFlowsTest(ControlConn* conn, DumpFlowsFilter* dff) 
        : DumpFlows(conn, dff) 
        { }

        ~DumpFlowsTest() override= default;

        bool execute(FlowCache*);

    void set_protocol_list(PktType proto_id)
    {
        protocols.clear();
        protocols.push_back(static_cast<LRUType>(proto_id));
    }

    void set_filter_criteria(const snort::SfIp& src_ip, const snort::SfIp& dst_ip,
        const snort::SfIp& src_subnet, const snort::SfIp& dst_subnet,
        const uint16_t src_port, const uint16_t dst_port)
    {
        dff.portA = src_port;
        dff.portB = dst_port;
        dff.ipA = src_ip;
        dff.ipB = dst_ip;
        dff.ipA_subnet = src_subnet;
        dff.ipB_subnet = dst_subnet;

        // Fast path: check if all filter fields are empty to avoid expensive filter_flows calls
        dff.filter_none = ( !dff.ipA.is_set() and
            !dff.ipB.is_set() and
             dff.portA == 0 and
             dff.portB == 0 );
    }
};

// cppcheck-suppress constParameterPointer ; signature overrides the control test interface
bool DumpFlowsTest::execute(FlowCache* cache)
{
    DumpFlowsControl& dfc = dump_flows_control[0];

    if ( !dfc.flow_table )
    {
        if ( open_file(dfc) )
            tinit(dfc, cache->get_flow_table());
        else
        {
            CHECK(false);
            return false;
        }
    }
    
    dfc.next = 1;
    dfc.has_more_flows = false;
    for( unsigned idx = 0; idx < protocols.size(); idx++ )
        dump_flows(dfc, idx);

    return !dfc.has_more_flows;
}

class DumpFlowsSummaryTest : public DumpFlowsSummary
{ 
    public:DumpFlowsSummaryTest(ControlConn* conn, DumpFlowsFilter* dff)
    : DumpFlowsSummary(conn, dff)
    { }

    ~DumpFlowsSummaryTest() override = default;

    bool execute(FlowCache*);

    FlowsSummary& get_flows_summary() { return flows_summaries[0]; }

    void set_protocol_list(PktType proto_id)
    {
        protocols.clear();
        protocols.push_back(static_cast<LRUType>(proto_id));
    }

    void set_filter_criteria(const snort::SfIp& src_ip, const snort::SfIp& dst_ip,
        const snort::SfIp& src_subnet, const snort::SfIp& dst_subnet,
        const uint16_t src_port, const uint16_t dst_port)
    {
        dff.portA = src_port;
        dff.portB = dst_port;
        dff.ipA = src_ip;
        dff.ipB = dst_ip;
        dff.ipA_subnet = src_subnet;
        dff.ipB_subnet = dst_subnet;

        // Fast path: check if all filter fields are empty to avoid expensive filter_flows calls
        dff.filter_none = ( !dff.ipA.is_set() and
            !dff.ipB.is_set() and
             dff.portA == 0 and
             dff.portB == 0 );
    }
};

// cppcheck-suppress constParameterPointer ; signature overrides the control test interface
bool DumpFlowsSummaryTest::execute(FlowCache* cache)
{
    DumpFlowsControl& dfc = dump_flows_control[0];

    if ( !dfc.flow_table )
        tinit(dfc, cache->get_flow_table());
        
    for( unsigned idx = 0; idx < protocols.size(); idx++ )
        dump_flows_summary(dfc, idx, flows_summaries[0]);

    return true;
}

TEST_GROUP(tunnel_key) { };

// An inner 5-tuple decapsulated from a tunnel is named by the packet
// payload rather than by the connection the DAQ keyed on
TEST(tunnel_key, tunneled_inner_tuple_does_not_match_bare_flow)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 2;
    FlowCache* cache = new FlowCache(fcg);

    FlowKey bare_key;
    memset(&bare_key, 0, sizeof(FlowKey));
    bare_key.pkt_type = PktType::TCP;
    bare_key.port_l = 18080;
    bare_key.port_h = 52669;

    // the same 5-tuple, but reached by decapsulating a tunnel
    FlowKey tunneled_key = bare_key;
    tunneled_key.flags.tunnel_encapsulated = true;

    CHECK(!FlowKey::is_equal(&bare_key, &tunneled_key));

    const Flow* bare_flow = cache->allocate(&bare_key);
    CHECK(bare_flow != nullptr);
    CHECK(cache->get_count() == 1);

    // the tunneled key must not find the bare Flow
    CHECK(cache->find(&tunneled_key) == nullptr);

    // and gets a Flow of its own, leaving the bare Flow intact
    const Flow* tunneled_flow = cache->allocate(&tunneled_key);
    CHECK(tunneled_flow != nullptr);
    CHECK(tunneled_flow != bare_flow);
    CHECK(cache->get_count() == 2);
    CHECK(cache->find(&bare_key) == bare_flow);

    cache->purge();
    delete cache;
}

// Ensure that the tunnel_encapsulated bit has an effect in the hash calculation
TEST(tunnel_key, tunnel_bit_participates_in_hash)
{
    FlowKey bare_key;
    memset(&bare_key, 0, sizeof(FlowKey));
    bare_key.pkt_type = PktType::TCP;
    bare_key.port_l = 18080;
    bare_key.port_h = 52669;

    FlowKey tunneled_key = bare_key;
    tunneled_key.flags.tunnel_encapsulated = true;

    FlowHashKeyOps hash_ops(1024);
    const unsigned bare_hash =
        hash_ops.do_hash(reinterpret_cast<const unsigned char*>(&bare_key), sizeof(FlowKey));
    const unsigned tunneled_hash =
        hash_ops.do_hash(reinterpret_cast<const unsigned char*>(&tunneled_key), sizeof(FlowKey));

    CHECK(bare_hash != tunneled_hash);
}

TEST(tunnel_key, tuple_lookup_retries_tunneled_key)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 1;
    FlowControl flow_control(fcg);

    FlowKey bare_key = {};
    bare_key.pkt_type = PktType::TCP;
    bare_key.port_l = 18080;
    bare_key.port_h = 52669;

    FlowKey tunneled_key = bare_key;
    tunneled_key.flags.tunnel_encapsulated = true;
    const Flow* tunneled_flow = flow_control.new_flow(&tunneled_key);

    CHECK(tunneled_flow != nullptr);
    CHECK(flow_control.find_flow_either_tunnel_state(bare_key) == tunneled_flow);
    CHECK_FALSE(bare_key.flags.tunnel_encapsulated);

    flow_control.purge_flows();
}

TEST(tunnel_key, tuple_lookup_prefers_bare_key)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 2;
    FlowControl flow_control(fcg);

    FlowKey bare_key = {};
    bare_key.pkt_type = PktType::TCP;
    bare_key.port_l = 18080;
    bare_key.port_h = 52669;

    FlowKey tunneled_key = bare_key;
    tunneled_key.flags.tunnel_encapsulated = true;
    const Flow* bare_flow = flow_control.new_flow(&bare_key);
    const Flow* tunneled_flow = flow_control.new_flow(&tunneled_key);

    CHECK(bare_flow != nullptr);
    CHECK(tunneled_flow != nullptr);
    CHECK(flow_control.find_flow_either_tunnel_state(bare_key) == bare_flow);

    flow_control.purge_flows();
}

TEST_GROUP(flow_prune) { };

// No flows in the flow cache, pruning should not happen
TEST(flow_prune, empty_cache_prune_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    FlowCache *cache = new FlowCache(fcg);

    CHECK(cache->get_count() == 0);
    CHECK(cache->delete_flows(1) == 0);
    CHECK(cache->get_count() == 0);
    delete cache;
}

// Do not delete blocked flow
TEST(flow_prune, blocked_flow_prune_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 2;
    FlowCache *cache = new FlowCache(fcg);

    int first_port = 1;
    int second_port = 2;

    // Add two flows in the flow cache
    FlowKey flow_key;
    memset(&flow_key, 0, sizeof(FlowKey));
    flow_key.pkt_type = PktType::TCP;

    flow_key.port_l = first_port;
    cache->allocate(&flow_key);

    flow_key.port_l = second_port;
    Flow* flow = cache->allocate(&flow_key);

    CHECK(cache->get_count() == fcg.max_flows);

    // block the second flow
    flow->block();

    // Access the first flow
    // This will move it to the MRU
    flow_key.port_l = first_port;
    CHECK(cache->find(&flow_key) != nullptr);

    // Prune one flow. This should delete the MRU flow, since
    // LRU flow is blocked
    CHECK(cache->delete_flows(1) == 1);

    // Blocked Flow should still be there
    flow_key.port_l = second_port;
    CHECK(cache->find(&flow_key) != nullptr);
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// Add 3 flows in flow cache and delete one
TEST(flow_prune, prune_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    FlowCache *cache = new FlowCache(fcg);
    int port = 1;

    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        cache->allocate(&flow_key);
    }

    CHECK(cache->get_count() == fcg.max_flows);
    CHECK(cache->delete_flows(1) == 1);
    CHECK(cache->get_count() == fcg.max_flows-1);
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}


// Add 3 flows in flow cache, delete all
TEST(flow_prune, prune_all_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    FlowCache *cache = new FlowCache(fcg);
    int port = 1;

    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        cache->allocate(&flow_key);
    }

    CHECK(cache->get_count() == fcg.max_flows);
    CHECK(cache->delete_flows(3) == 3);
    CHECK(cache->get_count() == 0);
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// Add 3 flows, all blocked, in flow cache, delete all
TEST(flow_prune, prune_all_blocked_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    FlowCache *cache = new FlowCache(fcg);
    int port = 1;

    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        flow->block();
    }

    CHECK(cache->get_count() == fcg.max_flows);
    CHECK(cache->delete_flows(3) == 3);
    CHECK(cache->get_count() == 0);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}


static FlowKey make_key(PktType pkt_type, uint16_t port)
{
    FlowKey flow_key;
    memset(&flow_key, 0, sizeof(FlowKey));
    flow_key.pkt_type = pkt_type;
    flow_key.port_l = port;
    return flow_key;
}

static FlowKey make_tcp_key(uint16_t port)
{ return make_key(PktType::TCP, port); }

// prune_unis() drops a candidate blocked without the funnel running, instead of
// stepping over it on every later allocation
TEST(flow_prune, uni_prune_unlinks_blocked_candidates)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 8;
    FlowCache* cache = new FlowCache(fcg);

    Flow* flows[8];
    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        flows[i] = cache->allocate(&flow_key);
    }

    CHECK_EQUAL(8u, cache->get_count());
    CHECK_EQUAL(8u, cache->uni_flows_size());

    // allocate() prepends, so flows[0] is oldest; block more than max_uni = 3
    for ( unsigned i = 0; i < 4; i++ )
        flows[i]->block();

    FlowKey trigger_key = make_tcp_key(2000);
    cache->allocate(&trigger_key);

    CHECK_EQUAL(1u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::EXCESS));

    CHECK_EQUAL(4u, cache->uni_flows_size());

    CHECK_EQUAL(8u, cache->get_count());
    CHECK_EQUAL(8u, cache->count_flows_in_lru(to_utype(PktType::TCP)));

    for ( unsigned i = 0; i < 4; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        CHECK(cache->find(&flow_key) != nullptr);
    }

    FlowKey pruned_key = make_tcp_key(1004);
    CHECK(cache->find(&pruned_key) == nullptr);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// a flow that stops being blocked is a candidate again, and relinking is idempotent
TEST(flow_prune, relink_uni_restores_candidacy_once)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 8;
    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key = make_tcp_key(1000);
    Flow* flow = cache->allocate(&flow_key);

    CHECK_EQUAL(1u, cache->uni_flows_size());

    cache->unlink_uni(flow);
    CHECK_EQUAL(0u, cache->uni_flows_size());

    cache->relink_uni(flow);
    CHECK_EQUAL(1u, cache->uni_flows_size());

    cache->relink_uni(flow);
    CHECK_EQUAL(1u, cache->uni_flows_size());

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// delete_active_flows() frees the flow itself, so the reset() that relinks it
// must happen before the final unlink, not after
TEST(flow_prune, delete_flows_unlinks_a_candidate_restored_by_reset)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 2;
    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key = make_tcp_key(1000);
    Flow* flow = cache->allocate(&flow_key);

    flow->block();
    // the stubbed set_block_flags() above only sets the flags
    cache->unlink_uni(flow);
    CHECK_EQUAL(0u, cache->uni_flows_size());

    test_reset_relink_cache = cache;
    CHECK_EQUAL(1u, cache->delete_flows(1));
    test_reset_relink_cache = nullptr;

    CHECK_EQUAL(0u, cache->uni_flows_size());
    CHECK_EQUAL(0u, cache->get_count());

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// with every candidate blocked, prune_unis() prunes nothing and prune_excess()
// must still terminate and hand the excess to prune_multiple()
TEST(flow_prune, uni_prune_all_blocked_falls_through_to_excess)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 8;
    fcg.prune_flows = 2;
    FlowCache* cache = new FlowCache(fcg);

    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        cache->allocate(&flow_key)->block();
    }

    FlowKey trigger_key = make_tcp_key(2000);
    cache->allocate(&trigger_key);

    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(2u, cache->get_prunes(PruneReason::EXCESS));

    // max_uni = 3 candidates left, the two excess prunes come from the old end of
    // the LRU, which prune_unis() already unlinked, then the new flow is linked
    CHECK_EQUAL(4u, cache->uni_flows_size());
    CHECK_EQUAL(7u, cache->get_count());

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// a blocked run of any length is rotated past, so prune_excess() prunes the
// eligible flow behind it rather than handing the blocked heads to prune_multiple()
TEST(flow_prune, excess_prune_rotates_past_blocked_run)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 8;
    fcg.prune_flows = 2;
    FlowCache* cache = new FlowCache(fcg);

    Flow* flows[8];
    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        flows[i] = cache->allocate(&flow_key);
        // keep prune_unis() out of it; this is about the protocol LRU
        cache->unlink_uni(flows[i]);
    }

    for ( unsigned i = 0; i < 5; i++ )
        flows[i]->block();

    FlowKey trigger_key = make_tcp_key(2000);
    cache->allocate(&trigger_key);

    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(1u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(8u, cache->get_count());

    for ( unsigned i = 0; i < 5; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        CHECK(cache->find(&flow_key) != nullptr);
    }

    FlowKey pruned_key = make_tcp_key(1005);
    CHECK(cache->find(&pruned_key) == nullptr);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// an offloaded head is rotated past like a blocked one, so detection in flight is
// not discarded while a prunable flow is still available behind it
TEST(flow_prune, excess_prune_rotates_past_suspended_run)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 8;
    fcg.prune_flows = 2;
    FlowCache* cache = new FlowCache(fcg);

    Flow* flows[8];
    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        flows[i] = cache->allocate(&flow_key);
        // keep prune_unis() out of it; this is about the protocol LRU
        cache->unlink_uni(flows[i]);
    }

    // the pointer just has to be non-null for is_suspended()
    IpsContext suspending_context(1);
    for ( unsigned i = 0; i < 5; i++ )
        flows[i]->context_chain.push_back(&suspending_context);

    FlowKey trigger_key = make_tcp_key(2000);
    cache->allocate(&trigger_key);

    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(1u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(8u, cache->get_count());

    for ( unsigned i = 0; i < 5; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        CHECK(cache->find(&flow_key) != nullptr);
    }

    FlowKey pruned_key = make_tcp_key(1005);
    CHECK(cache->find(&pruned_key) == nullptr);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// max_blocked_unlink_per_prune caps what one call drains, not the drain itself:
// each unlink is permanent, so a backlog larger than the cap converges over
// successive allocations instead of being stepped over again on each one
TEST(flow_prune, uni_prune_drains_large_blocked_backlog_across_allocations)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 1024;
    FlowCache* cache = new FlowCache(fcg);

    // more than max_blocked_unlink_per_prune, and max_uni = 257 stays below the
    // candidate count throughout, so the drain is what ends each walk
    const unsigned blocked_count = 300;

    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        Flow* flow = cache->allocate(&flow_key);
        if ( i < blocked_count )
            flow->block();
    }

    CHECK_EQUAL(1024u, cache->uni_flows_size());
    CHECK_EQUAL(1024u, cache->get_count());

    FlowKey first_key = make_tcp_key(3000);
    cache->allocate(&first_key);

    // the drain cap ends the walk before any candidate is reached, and the excess walk
    // finds only blocked heads.  prune_flows is left unset to isolate the drain: with a
    // configured value prune_multiple() would make the room and reclaim, which
    // excess_fallback_blocked_cost_is_bounded_per_episode covers.  Unset, the cache goes
    // one over max_flows, which keeps every later allocation pruning and so lets the
    // drain converge.
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(769u, cache->uni_flows_size());
    CHECK_EQUAL(1025u, cache->get_count());

    FlowKey second_key = make_tcp_key(3001);
    cache->allocate(&second_key);

    // the remaining 44 unlink, then the first candidate behind them is pruned
    CHECK_EQUAL(1u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(725u, cache->uni_flows_size());
    CHECK_EQUAL(1025u, cache->get_count());

    FlowKey third_key = make_tcp_key(3002);
    cache->allocate(&third_key);

    // converged: nothing left to step over, one candidate pruned per allocation
    CHECK_EQUAL(2u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(725u, cache->uni_flows_size());
    CHECK_EQUAL(1025u, cache->get_count());

    // with the fallback out of reach the drain only unlinks and the walk only steps
    // over, so nothing blocked is released here
    unsigned blocked_found = 0;
    for ( unsigned i = 0; i < blocked_count; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        if ( cache->find(&flow_key) )
            blocked_found++;
    }
    CHECK_EQUAL(blocked_count, blocked_found);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// the round robin visits every LRU, so an LRU with nothing prunable cannot starve
// the others: the eligible flow deeper in a larger LRU is still reached and preferred
// over a blocked head that the fallbacks would have taken
TEST(flow_prune, excess_prune_leaves_exhausted_lru_to_reach_eligible_flow)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 8;
    fcg.prune_flows = 2;
    FlowCache* cache = new FlowCache(fcg);

    Flow* tcp_flows[2];
    for ( unsigned i = 0; i < 2; i++ )
    {
        FlowKey flow_key = make_key(PktType::TCP, 1000 + i);
        tcp_flows[i] = cache->allocate(&flow_key);
        cache->unlink_uni(tcp_flows[i]);
        tcp_flows[i]->block();
    }

    Flow* udp_flows[6];
    for ( unsigned i = 0; i < 6; i++ )
    {
        FlowKey flow_key = make_key(PktType::UDP, 2000 + i);
        udp_flows[i] = cache->allocate(&flow_key);
        cache->unlink_uni(udp_flows[i]);
    }

    // the whole TCP LRU is unprunable; the one eligible flow is the newest UDP one
    for ( unsigned i = 0; i < 5; i++ )
        udp_flows[i]->block();

    FlowKey trigger_key = make_key(PktType::TCP, 3000);
    cache->allocate(&trigger_key);

    // one prune, and it is the eligible flow rather than a blocked LRU head taken
    // by the prune_multiple() fallback
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::UNI));
    CHECK_EQUAL(1u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(8u, cache->get_count());

    for ( unsigned i = 0; i < 2; i++ )
    {
        FlowKey flow_key = make_key(PktType::TCP, 1000 + i);
        CHECK(cache->find(&flow_key) != nullptr);
    }

    for ( unsigned i = 0; i < 5; i++ )
    {
        FlowKey flow_key = make_key(PktType::UDP, 2000 + i);
        CHECK(cache->find(&flow_key) != nullptr);
    }

    FlowKey pruned_key = make_key(PktType::UDP, 2005);
    CHECK(cache->find(&pruned_key) == nullptr);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

// an all-blocked cache of the given size, forcing prune_excess() to walk without
// finding anything it can freely take; returns what that one allocation examined
static unsigned all_blocked_excess_examined(unsigned size)
{
    FlowCacheConfig fcg;
    fcg.max_flows = size;
    fcg.prune_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    for ( unsigned i = 0; i < size; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
        flow->block();
    }

    FlowKey trigger_key = make_tcp_key(60000);
    cache->allocate(&trigger_key);

    // the walk found nothing free to take, so prune_multiple() made the room and it
    // takes blocked heads, up to prune_flows of them
    CHECK_EQUAL(fcg.prune_flows, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(size - fcg.prune_flows + 1, cache->get_count());

    const unsigned examined = cache->get_last_excess_examined();

    cache->purge();
    delete cache;

    return examined;
}

// max_excess_examined_per_prune bounds what one allocation pays to walk past heads it
// cannot take, so that cost does not scale with the cache: doubling the size examines
// no more before prune_multiple() makes the room
TEST(flow_prune, excess_prune_work_does_not_scale_with_cache_size)
{
    const unsigned small = all_blocked_excess_examined(300);
    const unsigned large = all_blocked_excess_examined(600);

    CHECK(small > 0);
    CHECK(small < 300);
    CHECK_EQUAL(small, large);
}

// only a head the walk actually reads spends budget. with one protocol in the cache
// every other LRU it rotates through is empty, and if those cost budget the walk gives
// up long before reaching a flow it could have taken.
TEST(flow_prune, excess_prune_budget_not_diluted_by_empty_lrus)
{
    const unsigned blocked_count = 100;

    FlowCacheConfig fcg;
    fcg.max_flows = blocked_count + 1;
    fcg.prune_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    // oldest, so the walk meets all of them before anything else
    for ( unsigned i = 0; i < blocked_count; i++ )
    {
        FlowKey blocked_key = make_tcp_key(1000 + i);
        Flow* blocked = cache->allocate(&blocked_key);
        cache->unlink_uni(blocked);
        blocked->block();
    }

    FlowKey free_key = make_tcp_key(2000);
    cache->unlink_uni(cache->allocate(&free_key));

    FlowKey trigger_key = make_tcp_key(60000);
    cache->allocate(&trigger_key);

    // each blocked head is rotated to MRU, so the free flow reaches the tail and is
    // taken on the next read -- in preference to any blocked flow
    CHECK_EQUAL(1u, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(blocked_count + 1, cache->get_last_excess_examined());
    CHECK(nullptr == cache->find(&free_key));

    FlowKey survivor_key = make_tcp_key(1000);
    CHECK(nullptr != cache->find(&survivor_key));

    cache->purge();
    delete cache;
}

static FlowCache* make_blocked_backlog_cache(FlowCacheConfig& fcg, unsigned blocked_count,
    const FlowKey& free_key)
{
    fcg.max_flows = blocked_count + 1;
    FlowCache* cache = new FlowCache(fcg);

    for ( unsigned i = 0; i < blocked_count; i++ )
    {
        FlowKey blocked_key = make_tcp_key(1000 + i);
        Flow* blocked = cache->allocate(&blocked_key);
        cache->unlink_uni(blocked);
        blocked->block();
    }

    cache->unlink_uni(cache->allocate(&free_key));
    return cache;
}

TEST(flow_prune, excess_fallback_takes_blocked_above_budget)
{
    const unsigned blocked_count = 300;

    FlowCacheConfig fcg;
    fcg.prune_flows = 10;
    FlowKey free_key = make_tcp_key(2000);
    FlowCache* cache = make_blocked_backlog_cache(fcg, blocked_count, free_key);

    FlowKey trigger_key = make_tcp_key(60000);
    cache->allocate(&trigger_key);

    // the budget stops the walk short of the eligible flow, so nothing the walk
    // examined was reclaimable and every reclaim came from the fallback
    CHECK_EQUAL(1u, cache->get_excess_walk_calls());
    CHECK(cache->get_last_excess_examined() < blocked_count);
    CHECK_EQUAL(fcg.prune_flows, cache->get_prunes(PruneReason::EXCESS));

    // the fallback checks neither block state nor depth, so it takes blocked flows
    // and leaves the eligible one -- the reverse of what happens under the budget
    CHECK(nullptr != cache->find(&free_key));

    unsigned blocked_alive = 0;
    for ( unsigned i = 0; i < blocked_count; i++ )
    {
        FlowKey blocked_key = make_tcp_key(1000 + i);
        if ( cache->find(&blocked_key) )
            blocked_alive++;
    }
    CHECK_EQUAL(blocked_count - fcg.prune_flows, blocked_alive);

    cache->purge();
    delete cache;
}

// with every flow blocked the walk can reclaim nothing at all, so the fallback is the
// only path to the cap; prune_one() takes blocked flows, so max_flows still holds
TEST(flow_prune, excess_holds_cap_when_every_flow_is_blocked)
{
    const unsigned over_cap = 50;

    FlowCacheConfig fcg;
    fcg.max_flows = 100;
    fcg.prune_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    for ( unsigned i = 0; i < fcg.max_flows + over_cap; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
        flow->block();
    }

    // one reclaim for every allocation that found the cache at the cap
    CHECK_EQUAL(over_cap, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(fcg.max_flows, cache->get_count());

    cache->purge();
    delete cache;
}

// at the configured default the fallback is reachable, so the blocked run is paid for
// once per over-cap episode and the walk then converges onto eligible flows
TEST(flow_prune, excess_fallback_blocked_cost_is_bounded_per_episode)
{
    const unsigned blocked_count = 300;
    const unsigned allocations = 40;

    FlowCacheConfig fcg;
    fcg.max_flows = 1024;
    fcg.prune_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    // the oldest flows are the blocked run; unlinking every flow leaves prune_unis()
    // with nothing to reclaim, so each allocation over the cap reaches prune_excess()
    for ( unsigned i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
        if ( i < blocked_count )
            flow->block();
    }

    for ( unsigned i = 0; i < allocations; i++ )
    {
        FlowKey flow_key = make_tcp_key(60000 + i);
        cache->allocate(&flow_key);
    }

    unsigned blocked_alive = 0;
    for ( unsigned i = 0; i < blocked_count; i++ )
    {
        FlowKey flow_key = make_tcp_key(1000 + i);
        if ( cache->find(&flow_key) )
            blocked_alive++;
    }

    // the fallback ran once and took prune_flows blocked flows; the rest of the run
    // was walked past rather than reclaimed, so the cost does not scale with the
    // allocations that follow
    CHECK_EQUAL(fcg.prune_flows, blocked_count - blocked_alive);

    // every allocation over the cap made room, so the cap holds
    CHECK_EQUAL(allocations, cache->get_prunes(PruneReason::EXCESS));
    CHECK_EQUAL(fcg.max_flows, cache->get_count());

    // reclaiming prune_flows at once leaves cleanup_flows short of the cap, so the
    // allocations that fill the gap back in do not walk at all
    CHECK(cache->get_excess_walk_calls() < allocations);

    cache->purge();
    delete cache;
}

TEST(flow_prune, excess_walk_advances_across_allocations)
{
    const unsigned blocked_count = 300;

    FlowCacheConfig fcg;
    // prune_flows = 1 leaves no headroom, so the next allocation reaches prune_excess()
    // again; a larger value would skip it and leave last_excess_examined stale
    fcg.prune_flows = 1;
    FlowKey free_key = make_tcp_key(2000);
    FlowCache* cache = make_blocked_backlog_cache(fcg, blocked_count, free_key);

    // no find() between the two passes: find() touches the flow it returns to MRU
    // and would reorder the very LRU under test
    FlowKey first_key = make_tcp_key(60000);
    cache->allocate(&first_key);
    const unsigned first_examined = cache->get_last_excess_examined();

    FlowKey second_key = make_tcp_key(60001);
    cache->allocate(&second_key);
    const unsigned second_examined = cache->get_last_excess_examined();

    // both allocations walked, so the two counts are from different calls
    CHECK_EQUAL(2u, cache->get_excess_walk_calls());

    // a head the walk declines is rotated to MRU, so the next call resumes past it
    // rather than re-reading the same run
    CHECK(second_examined < first_examined);

    // and having advanced, the walk reaches the eligible flow and prefers it
    CHECK(nullptr == cache->find(&free_key));

    cache->purge();
    delete cache;
}

TEST_GROUP(flow_timeout)
{
    void setup() override    { ha_standby_flows.clear(); }
    void teardown() override { ha_standby_flows.clear(); }
};

TEST(flow_timeout, expired_head_is_retired)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key = make_tcp_key(1000);
    cache->allocate(&flow_key)->last_data_seen = 1;

    CHECK_EQUAL(1u, cache->timeout(5, 1000000));

    cache->purge();
    delete cache;
}

// a head timeout() cannot release must leave the walk able to finish. before, the
// standby check neither advanced the cursor nor retired the LRU, so the call could
// not reach its exit condition and never returned.
TEST(flow_timeout, standby_head_does_not_stall_the_walk)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key = make_tcp_key(1000);
    Flow* standby = cache->allocate(&flow_key);
    standby->last_data_seen = 1;
    set_standby(standby, true);

    CHECK_EQUAL(0u, cache->timeout(5, 1000000));

    cache->purge();
    delete cache;
}

// and it must not cost another protocol its timeout
TEST(flow_timeout, standby_head_does_not_hide_another_proto)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    FlowCache* cache = new FlowCache(fcg);

    FlowKey tcp_key = make_tcp_key(1000);
    Flow* standby = cache->allocate(&tcp_key);
    standby->last_data_seen = 1;
    set_standby(standby, true);

    FlowKey udp_key = make_key(PktType::UDP, 2000);
    cache->allocate(&udp_key)->last_data_seen = 1;

    CHECK_EQUAL(1u, cache->timeout(5, 1000000));
    CHECK(nullptr == cache->find(&udp_key));
    CHECK(nullptr != cache->find(&tcp_key));

    cache->purge();
    delete cache;
}

// prune base on the proto type of the flow
TEST(flow_prune, prune_proto)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 5;
    fcg.prune_flows = 3;

    for(uint8_t i = to_utype(PktType::NONE); i < to_utype(PktType::MAX); i++)
        fcg.proto[i].nominal_timeout = 5;

    FlowCache *cache = new FlowCache(fcg);
    int port = 1;

    for ( unsigned i = 0; i < 2; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;
        cache->allocate(&flow_key);
    }

    CHECK (cache->get_count() == 2);

    //pruning should not happen for all other proto except UDP
    for(uint8_t i = 0; i < to_utype(PktType::MAX) - 1; i++)
    {
        if (i == to_utype(PktType::UDP))
            continue;
        CHECK(cache->prune_one(PruneReason::NONE, true, i) == false);
    }

    //pruning should happen for UDP
    CHECK(cache->prune_one(PruneReason::NONE, true, to_utype(PktType::UDP)) == true);

    FlowKey flow_key2;
    flow_key2.port_l = port++;
    flow_key2.pkt_type = PktType::ICMP;
    cache->allocate(&flow_key2);

    CHECK (cache->get_count() == 2);

    //target flow is ICMP
    CHECK(cache->prune_multiple(PruneReason::NONE, true) == 1);

    //adding UDP flow it will become LRU
    for ( unsigned i = 0; i < 2; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;
        Flow* flow = cache->allocate(&flow_key);
        flow->last_data_seen = 2+i;
    }

    //adding TCP flow it will become MRU and put UDP flow to LRU
    for ( unsigned i = 0; i < 3; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        flow->last_data_seen = 4+i; //this will force to timeout later than UDP
    }

    //timeout should happen for 2 UDP and 1 TCP flow
    CHECK( 3 == cache->timeout(5,9));

    //target flow UDP flow and it will fail because no UDP flow is present
    CHECK(cache->prune_one(PruneReason::NONE, true, to_utype(PktType::UDP)) == false);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

TEST(flow_prune, prune_counts)
{
    PruneStats stats;

    // Simulate a few prunes for different reasons and protocol types
    stats.update(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP);
    stats.update(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::TCP);
    stats.update(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::UDP);
    stats.update(PruneReason::MEMCAP, PktType::ICMP);
    stats.update(PruneReason::MEMCAP, PktType::USER);

    // Check the total prunes
    CHECK_EQUAL(5, stats.get_total());

    // Check individual protocol prunes
    CHECK_EQUAL(1, stats.get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::TCP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::UDP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PruneReason::MEMCAP, PktType::ICMP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PruneReason::MEMCAP, PktType::USER));

    // Check prunes for a specific protocol across all reasons
    CHECK_EQUAL(1, stats.get_proto_prune_count(PktType::IP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PktType::TCP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PktType::UDP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PktType::ICMP));
    CHECK_EQUAL(1, stats.get_proto_prune_count(PktType::USER));

    // Reset the counts
    stats = PruneStats();

    // Ensure that the counts have been reset
    CHECK_EQUAL(0, stats.get_total());
    CHECK_EQUAL(0, stats.get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP));
    CHECK_EQUAL(0, stats.get_proto_prune_count(PruneReason::MEMCAP, PktType::TCP));

     // Update the same protocol and reason multiple times
    stats.update(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP);
    stats.update(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP);
    stats.update(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP);

    CHECK_EQUAL(3, stats.get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP));
}

TEST_GROUP(allowlist_test) { };

TEST(allowlist_test, move_to_allowlist)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 5;
    FlowCache* cache = new FlowCache(fcg);
    int port = 1;

    // Adding two UDP flows and moving them to allow list
    for (unsigned i = 0; i < 2; ++i) {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;

        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow) == true);  // Move flow to allow list

        const Flow* found_flow = cache->find(&flow_key);
        CHECK(found_flow == flow);  // Verify flow is found
        CHECK(found_flow->flags.in_allowlist == 1);  // Verify it's in allowlist
    }

    CHECK_EQUAL(2, cache->get_count());  // Check two flows in cache
    CHECK_EQUAL(2, cache->get_lru_flow_count(allowlist_lru_index));  // Check 2 allow list flows

    cache->purge();
    delete cache;
}


TEST(allowlist_test, allowlist_timeout_prune_fail)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 5;
    FlowCache* cache = new FlowCache(fcg);
    int port = 1;

    for (unsigned i = 0; i < 2; ++i)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;

        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow) == true);
    }

    CHECK_EQUAL(2, cache->get_count());
    CHECK_EQUAL(2, cache->get_lru_flow_count(allowlist_lru_index));

    // Ensure pruning doesn't occur because all flows are allow listed
    for (uint8_t i = 0; i < total_lru_count; ++i)
        CHECK(cache->prune_one(PruneReason::IDLE_PROTOCOL_TIMEOUT, true, i) == false);

    CHECK_EQUAL(2, cache->get_count());
    CHECK_EQUAL(2, cache->get_lru_flow_count(allowlist_lru_index));

    cache->purge();
    delete cache;
}

TEST(allowlist_test, allowlist_memcap_prune_pass)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    FlowCache* cache = new FlowCache(fcg);
    int port = 1;

    for (unsigned i = 0; i < 10; ++i)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;

        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow) == true);
    }

    CHECK_EQUAL(10, cache->get_count());  // Check 10 flows in cache
    CHECK_EQUAL(10, cache->get_lru_flow_count(allowlist_lru_index));  // Check 2 allow listed flows

    CHECK_EQUAL(5, cache->prune_multiple(PruneReason::MEMCAP, true));
    CHECK_EQUAL(5, cache->get_count());
    CHECK_EQUAL(5, cache->get_proto_prune_count(PruneReason::MEMCAP, (PktType)allowlist_lru_index));
    CHECK_EQUAL(5, cache->get_lru_flow_count(allowlist_lru_index));

    cache->purge();
    delete cache;
}


TEST(allowlist_test, allowlist_timeout_with_other_protos)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 10;

    for (uint8_t i = to_utype(PktType::NONE); i < to_utype(PktType::MAX); ++i)
        fcg.proto[i].nominal_timeout = 5;

    FlowCache* cache = new FlowCache(fcg);
    int port = 1;

    for (unsigned i = 0; i < 2; ++i)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;

        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow) == true);  // Move flow to allow list

        const Flow* found_flow = cache->find(&flow_key);
        CHECK(found_flow == flow);
        CHECK(found_flow->flags.in_allowlist == 1);
    }

    CHECK_EQUAL(2, cache->get_count());

    // Ensure pruning doesn't occur because all flows are allow listed
    for (uint8_t i = 0; i < to_utype(PktType::MAX) - 1; ++i)
        CHECK(cache->prune_one(PruneReason::NONE, true, i) == false);

    CHECK_EQUAL(2, cache->get_count());  // Ensure no flows were pruned

    // Add a new ICMP flow
    FlowKey flow_key_icmp;
    flow_key_icmp.port_l = port++;
    flow_key_icmp.pkt_type = PktType::ICMP;
    cache->allocate(&flow_key_icmp);

    CHECK_EQUAL(3, cache->get_count());
    CHECK_EQUAL(2, cache->get_lru_flow_count(allowlist_lru_index));

    // Prune Reason::NONE will not be able to prune allow listed flow, only 1 UDP
    CHECK_EQUAL(1, cache->prune_multiple(PruneReason::NONE, true));

    // we can't prune to 0 so 1 flow will be pruned
    CHECK_EQUAL(1, cache->prune_multiple(PruneReason::MEMCAP, true));

    CHECK_EQUAL(1, cache->get_count());
    CHECK_EQUAL(1, cache->get_lru_flow_count(allowlist_lru_index));

    // Adding five UDP flows, these will become the LRU flows
    for (unsigned i = 0; i < 5; ++i)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;

        Flow* flow = cache->allocate(&flow_key);
        flow->last_data_seen = 2 + i;
    }

    CHECK_EQUAL(6, cache->get_count());

    // Adding three TCP flows, move two to allow list, making them MRU
    for (unsigned i = 0; i < 3; ++i)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;

        Flow* flow = cache->allocate(&flow_key);
        flow->last_data_seen = 4 + i;  // Set TCP flows to have later timeout

        if (i > 0)
        {
            CHECK(cache->move_to_allowlist(flow) == true);

            const Flow* found_flow = cache->find(&flow_key);
            CHECK(found_flow == flow);
            CHECK(found_flow->flags.in_allowlist == 1);
        }
    }

    CHECK_EQUAL(5, cache->get_lru_flow_count(to_utype(PktType::UDP)));
    CHECK_EQUAL(1, cache->get_lru_flow_count(to_utype(PktType::TCP)));
    CHECK_EQUAL(3, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(9, cache->get_count());  // Verify total flows (5 UDP + 1 TCP + 3 allow list)
    CHECK_EQUAL(3, cache->get_lru_flow_count(allowlist_lru_index));  // Verify 3 allow listed flows

    // Timeout 4 flows, 3 UDP and 1 TCP
    CHECK_EQUAL(4, cache->timeout(5, 9));
    CHECK_EQUAL(5, cache->get_count());  // Ensure 4 flows remain (2 UDP + 3 allow listed TCP)
    CHECK_EQUAL(3, cache->count_flows_in_lru(allowlist_lru_index));
    CHECK_EQUAL(0, cache->count_flows_in_lru(to_utype(PktType::TCP)));
    CHECK_EQUAL(2, cache->count_flows_in_lru(to_utype(PktType::UDP)));

    //try multiple prune 2 UDP flow should be pruned as other flows are allow listed
    CHECK_EQUAL(2, cache->prune_multiple(PruneReason::NONE, true));

    //memcap prune can prune all the flows
    CHECK_EQUAL(2, cache->prune_multiple(PruneReason::MEMCAP, true));

    CHECK_EQUAL(1, cache->get_count());
    CHECK_EQUAL(1, cache->get_lru_flow_count(allowlist_lru_index));

    // Clean up
    cache->purge();
    delete cache;
}
TEST(allowlist_test, excess_prune)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 5;
    fcg.prune_flows = 2;
    FlowCache* cache = new FlowCache(fcg);
    int port = 1;

    for (unsigned i = 0; i < 6; ++i)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;

        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow) == true);
    }

    // allocating 6 flows and moving all to allowlist
    // max_flows is 5 one flow should be pruned
    CHECK_EQUAL(5, cache->get_count());
    CHECK_EQUAL(5, cache->get_lru_flow_count(allowlist_lru_index));

    // Prune 3 flows, expect 2 flows pruned
    CHECK_EQUAL(2, cache->prune_multiple(PruneReason::EXCESS, true));
    CHECK_EQUAL(3, cache->get_count());
    CHECK_EQUAL(3, cache->get_lru_flow_count(allowlist_lru_index));

    cache->purge();
    delete cache;
}

TEST_GROUP(dump_flows)
 {
    FlowCacheConfig fcg;
    FlowCache* cache;
    DumpFlowsTest* df;

    void setup() override
    {
        fcg.max_flows = 500;
        cache = new FlowCache(fcg);
        DumpFlowsFilter* dff = new DumpFlowsFilterAnd(false);
        dff->file_name = "dump_flows_test";
        df = new DumpFlowsTest(nullptr, dff);
    }

    void teardown() override
    {
        delete cache;
        delete df;
    }    
};

TEST(dump_flows, dump_flows_with_all_empty_caches)
{
    CHECK(df->execute(cache) == true);
    CHECK(cache->get_flows_allocated() == 0);
}

TEST(dump_flows, dump_flows_with_one_tcp_flow)
{
    FlowKey flow_key;
    flow_key.port_l = 1;
    flow_key.pkt_type = PktType::TCP;
    cache->allocate(&flow_key);

    CHECK(df->execute(cache) == true);
    CHECK (cache->get_count() == 1);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}

TEST(dump_flows, dump_flows_with_102_tcp_flows)
{
    int port = 1;

    for ( unsigned i = 0; i < 102; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        cache->allocate(&flow_key);
    }
    CHECK (cache->get_count() == 102);

    //since we only dump 100 flows at a time. The first call will return false
    //second time when it is called , it dumps the remaining 2 flows and returns true
    CHECK(df->execute(cache) == false);
    CHECK(df->execute(cache) == true);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK (cache->get_count() == 0);
}

TEST(dump_flows, dump_flows_with_102_tcp_flows_and_202_udp_flows)
{
    int port = 1;

    for ( unsigned i = 0; i < 102; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        cache->allocate(&flow_key);
    }

    for ( unsigned i = 0; i < 202; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;
        cache->allocate(&flow_key);
    }

    CHECK (cache->get_count() == 304);

    //since we only dump 100 flows at a time. The first 2 calls will return false
    //third time when it is called , it dumps the remaining 2 UDP flows and returns true
    CHECK(df->execute(cache) == false);
    CHECK(df->execute(cache) == false);
    CHECK(df->execute(cache) == true);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK (cache->get_count() == 0);
}

TEST(dump_flows, dump_flows_with_allowlist)
{
    int port = 1;
    FlowKey flow_key[10];

    // Add TCP flows and mark some as allow listed
    for (unsigned i = 0; i < 10; ++i)
    {
        flow_key[i].port_l = port++;
        flow_key[i].pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key[i]);
        // Mark the first 5 flows as allow listed
        if (i < 5)
        {
            CHECK(cache->move_to_allowlist(flow) == true);
        }
    }

    CHECK(cache->get_count() == 10);

    //check flows are properly moved to allow list
    CHECK(cache->count_flows_in_lru(to_utype(PktType::TCP)) == 5);  // Check 5 TCP flows
    CHECK(cache->count_flows_in_lru(allowlist_lru_index) == 5);  // Check 5 allow listed flows

    // Check that the first dump call works (with allow listed and non-allow listed flows)
    CHECK(df->execute(cache) == true);
 
    // Verify that allow listed flows exist and are correctly handled
    for (unsigned i = 0; i < 5; ++i)
    {
        flow_key[i].port_l = i + 1;  // allow listed flow ports
        flow_key[i].pkt_type = PktType::TCP;
        const Flow* flow = cache->find(&flow_key[i]);
        CHECK(flow != nullptr);  // Ensure the flow is found
        CHECK(flow->flags.in_allowlist == 1);  // Ensure the flow is allow listed
    }

    // Ensure cache cleanup and correct flow counts
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK(cache->get_count() == 0);
}

TEST(dump_flows, dump_flows_no_flows_to_dump)
{
    CHECK(df->execute(cache) == true);
}

TEST(dump_flows, serializer_captures_current_and_peak_mem)
{
    FlowKey flow_key;
    flow_key.port_l = 1;
    flow_key.pkt_type = PktType::UDP;
    Flow* flow = cache->allocate(&flow_key);

    // raise the high-water peak, then drop current below it, so the wire
    // record must carry the current usage and the higher peak independently
    flow->add_mem(256);
    flow->add_mem(512);
    flow->sub_mem(512);
    CHECK(flow->get_peak_mem_usage() > flow->get_mem_usage());

    DumpFlowsSerializer serializer;
    const struct timeval now = { 0, 0 };
    serializer.initialize(*flow, now);

    const DumpFlowsBinaryDescriptor& bin = serializer.get_binary();
    UNSIGNED_LONGS_EQUAL(flow->get_mem_usage(), bin.flow_mem);
    UNSIGNED_LONGS_EQUAL(flow->get_peak_mem_usage(), bin.peak_flow_mem);

    cache->purge();
}

TEST_GROUP(dump_flows_summary)
{
    FlowCacheConfig fcg;
    FlowCache* cache;
    DumpFlowsSummaryTest* dfs;
    std::vector<PktType> types = {PktType::IP, PktType::ICMP, PktType::TCP, PktType::UDP};

    void setup() override
    {
        fcg.max_flows = 500;
        cache = new FlowCache(fcg);
        DumpFlowsFilter* dff = new DumpFlowsFilterAnd(false);
        dfs = new DumpFlowsSummaryTest(nullptr, dff);
    }

    void teardown() override
    {
        delete cache;
        delete dfs;
    }    
};

TEST(dump_flows_summary, dump_flows_summary_with_all_empty_caches)
{
    CHECK(dfs->execute(cache) == true);
    CHECK(cache->get_flows_allocated() == 0);

    FlowsTypeSummary expected_type{};
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    CHECK(expected_state == dfs->get_flows_summary().state_summary);
}


TEST(dump_flows_summary, dump_flows_summary_with_one_tcp_flow)
{
    FlowKey flow_key;
    flow_key.port_l = 1;
    flow_key.pkt_type = PktType::TCP;
    cache->allocate(&flow_key);

    CHECK(dfs->execute(cache) == true);
    CHECK(cache->get_count() == 1);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = 1;
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 1;
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}

TEST(dump_flows_summary, dump_flows_summary_with_5_of_each_flow)
{
    int port = 1;

    for (const auto& type : types)
    {
        for (unsigned i = 0; i < 5; i++)
        {
            FlowKey flow_key;
            flow_key.port_l = port++;
            flow_key.pkt_type = type;
            cache->allocate(&flow_key);
        }
    }
    CHECK (cache->get_count() == 5 * types.size());
    CHECK(dfs->execute(cache) == true);

    FlowsTypeSummary expected_type{};
    for (const auto& type : types)
        expected_type[to_utype(type)] = 5;
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 5 * types.size();
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK (cache->get_count() == 0);
}

TEST(dump_flows_summary, dump_flows_summary_with_different_flow_states)
{
    int port = 1;
    unsigned flows_number = 5;

    std::vector<snort::Flow::FlowState> types = {snort::Flow::FlowState::BLOCK, snort::Flow::FlowState::ALLOW, snort::Flow::FlowState::SETUP};

    for (const auto& type : types)
    {
        for (unsigned i = 0; i < 5; i++)
        {
            FlowKey flow_key;
            flow_key.port_l = port++;
            flow_key.pkt_type = PktType::TCP;
            cache->allocate(&flow_key);
            Flow* flow = cache->find(&flow_key);
            flow->flow_state = type;
        }
    }

    CHECK(dfs->execute(cache) == true);

    CHECK(cache->get_count() == flows_number * types.size());

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = flows_number * types.size();
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    for (const auto& type : types)
    {
        expected_state[to_utype(type)] = flows_number;
    }
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}

TEST(dump_flows_summary, dump_flows_summary_with_allowlist)
{
    int port = 1;
    FlowKey flow_key[10];

    // Add TCP flows and mark some as allow listed
    for (unsigned i = 0; i < 10; ++i)
    {
        flow_key[i].port_l = port++;
        flow_key[i].pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key[i]);
        // Mark the first 5 flows as allow listed
        if (i < 5)
        {
            CHECK(cache->move_to_allowlist(flow) == true);
        }
    }

    CHECK(cache->get_count() == 10);

    //check flows are properly moved to allow list
    CHECK(cache->count_flows_in_lru(to_utype(PktType::TCP)) == 5);  // Check 5 TCP flows
    CHECK(cache->count_flows_in_lru(allowlist_lru_index) == 5);  // Check 5 allow listed flows

    CHECK(dfs->execute(cache) == true);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = 10;
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 10;
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    // Verify that allow listed flows exist and are correctly handled
    for (unsigned i = 0; i < 5; ++i)
    {
        flow_key[i].port_l = i + 1;  // allow listed flow ports
        flow_key[i].pkt_type = PktType::TCP;
        const Flow* flow = cache->find(&flow_key[i]);
        CHECK(flow != nullptr);  // Ensure the flow is found
        CHECK(flow->flags.in_allowlist == 1);  // Ensure the flow is allow listed
    }

    // Ensure cache cleanup and correct flow counts
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK(cache->get_count() == 0);
}

TEST(dump_flows_summary, dump_flows_summary_with_protocol_filter)
{
    unsigned flows_number = 5;

    for (const auto& type : types)
    {
        int port = 1;
        for (unsigned i = 0; i < 5; i++)
        {
            FlowKey flow_key;
            flow_key.port_l = port++;
            flow_key.port_h = 80;
            flow_key.pkt_type = type;
            cache->allocate(&flow_key);

            Flow* flow = cache->find(&flow_key);
            flow->pkt_type = type;
        }
    }
    CHECK(cache->get_count() == flows_number * types.size());

    // check proto filter
    dfs->set_protocol_list(PktType::TCP);
    CHECK(dfs->execute(cache) == true);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = flows_number;
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = flows_number;
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}

TEST(dump_flows_summary, dump_flows_summary_with_port_filter)
{
    unsigned flows_number = 5;

    for (const auto& type : types)
    {
        int port = 1;
        for (unsigned i = 0; i < 5; i++)
        {
            FlowKey flow_key;
            flow_key.port_l = port++;
            flow_key.port_h = 80;
            flow_key.pkt_type = type;
            cache->allocate(&flow_key);

            Flow* flow = cache->find(&flow_key);
            flow->pkt_type = type;
        }
    }
    CHECK(cache->get_count() == flows_number * types.size());

    //check port filter
    SfIp src_ip, src_subnet, dst_ip, dst_subnet;
    dfs->set_filter_criteria(src_ip, dst_ip, src_subnet, dst_subnet, 1, 0);
    CHECK(dfs->execute(cache) == true);

    FlowsTypeSummary expected_type{};
    for (const auto& type : types)
        expected_type[to_utype(type)] = 1;

    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = types.size();
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}

TEST(dump_flows_summary, dump_flows_summary_with_multiple_filter)
{
    unsigned flows_number = 5;

    for (const auto& type : types)
    {
        int port = 1;
        for (unsigned i = 0; i < 5; i++)
        {
            FlowKey flow_key;
            flow_key.port_l = port++;
            flow_key.port_h = 80;
            flow_key.pkt_type = type;
            cache->allocate(&flow_key);

            Flow* flow = cache->find(&flow_key);
            flow->pkt_type = type;
        }
    }
    CHECK(cache->get_count() == flows_number * types.size());

    dfs->set_protocol_list(PktType::UDP);

    //check with multiple filter criteria
    SfIp src_ip, src_subnet, dst_ip, dst_subnet;
    dfs->set_filter_criteria(src_ip, dst_ip, src_subnet, dst_subnet, 1, 80);
    CHECK(dfs->execute(cache) == true);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::UDP)] = 1;
    CHECK(expected_type == dfs->get_flows_summary().type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 1;
    CHECK(expected_state == dfs->get_flows_summary().state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}
TEST(dump_flows_summary, watchdog_kick_functionality)
{
    int port = 1;

    // Reset kick counter before test
    reset_preemptive_kick_count();

    // Add flows that will trigger watchdog kicks
    // watch dog mask = 7, so kick happens every 8 flows (when count & 7 == 0)
    // Add 64 flows to trigger multiple kicks
    for (unsigned i = 0; i < 64; i++)
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        cache->allocate(&flow_key);
    }

    CHECK(cache->get_count() == 64);

    // execute dump_flows_summary which should trigger watchdog kicks
    CHECK(dfs->execute(cache) == true);

    // Check that watchdog was kicked the expected number of times
    // With 64 flows and watch dog mask = 7, kicks should happen at:
    // flow 8 (8 & 7 = 0), flow 16 (16 & 7 = 0), flow 24, 32, 40, 48, 56, 64
    // That's 8 kicks total
    unsigned kick_count = get_preemptive_kick_count();
    CHECK_EQUAL(8, kick_count);

    // Verify all flows were processed correctly
    CHECK_EQUAL(64, dfs->get_flows_summary().type_summary[to_utype(PktType::TCP)]);
    CHECK_EQUAL(64, dfs->get_flows_summary().state_summary[to_utype(snort::Flow::FlowState::SETUP)]);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
}

TEST_GROUP(flow_cache_lrus)
{
    FlowCacheConfig fcg;
    FlowCache* cache;

    void setup() override
    {
        fcg.max_flows = 20;
        cache = new FlowCache(fcg);
    }

    void teardown() override
    {
        cache->purge();
        delete cache;
    }
};

TEST(flow_cache_lrus, count_flows_in_lru_test)
{
    FlowKey flow_keys[10];
    memset(flow_keys, 0, sizeof(flow_keys));

    flow_keys[0].pkt_type = PktType::TCP;
    flow_keys[1].pkt_type = PktType::UDP;
    flow_keys[2].pkt_type = PktType::USER;
    flow_keys[3].pkt_type = PktType::FILE;
    flow_keys[4].pkt_type = PktType::TCP;
    flow_keys[5].pkt_type = PktType::TCP;
    flow_keys[6].pkt_type = PktType::PDU;
    flow_keys[7].pkt_type = PktType::ICMP;
    flow_keys[8].pkt_type = PktType::TCP;
    flow_keys[9].pkt_type = PktType::ICMP;

    //flow count 4 TCP, 1 UDP, 1 USER, 1 FILE, 1 PDU, 2 ICMP = 10
    // Add the flows to the hash_table
    for (int i = 0; i < 10; ++i)
    {
        flow_keys[i].port_l = i;
        const Flow* flow = cache->allocate(&flow_keys[i]);
        CHECK(flow != nullptr);
    }

    CHECK_EQUAL(10, cache->get_count());  // Verify 10 flows in
    CHECK_EQUAL(4, cache->count_flows_in_lru(to_utype(PktType::TCP)));  // 4 TCP flows
    CHECK_EQUAL(1, cache->count_flows_in_lru(to_utype(PktType::UDP)));  // 1 UDP flow
    CHECK_EQUAL(1, cache->count_flows_in_lru(to_utype(PktType::USER)));  // 1 USER flow
    CHECK_EQUAL(1, cache->count_flows_in_lru(to_utype(PktType::FILE)));  // 1 FILE flow
    CHECK_EQUAL(1, cache->count_flows_in_lru(to_utype(PktType::PDU)));  // 1 PDU flow
    CHECK_EQUAL(2, cache->count_flows_in_lru(to_utype(PktType::ICMP)));  // 2 ICMP flow

    Flow* flow1 = cache->find(&flow_keys[0]);
    Flow* flow2 = cache->find(&flow_keys[1]);
    Flow* flow3 = cache->find(&flow_keys[6]);
    CHECK(cache->move_to_allowlist(flow1));
    CHECK(cache->move_to_allowlist(flow2));
    CHECK(cache->move_to_allowlist(flow3));

    CHECK_EQUAL(10, cache->get_count());
    CHECK_EQUAL(3, cache->count_flows_in_lru(to_utype(PktType::TCP)));  // 3 TCP flows
    CHECK_EQUAL(0, cache->count_flows_in_lru(to_utype(PktType::UDP)));  // 0 UDP flows
    CHECK_EQUAL(1, cache->count_flows_in_lru(to_utype(PktType::USER)));  // 1 USER flow
    CHECK_EQUAL(1, cache->count_flows_in_lru(to_utype(PktType::FILE)));  // 1 FILE flow
    CHECK_EQUAL(0, cache->count_flows_in_lru(to_utype(PktType::PDU)));  // 0 PDU flows
    CHECK_EQUAL(2, cache->count_flows_in_lru(to_utype(PktType::ICMP)));  // 2 ICMP flow
    // Check the allow listed flows
    CHECK_EQUAL(3, cache->count_flows_in_lru(allowlist_lru_index));  // 3 allowlist flows

}

TEST_GROUP(flow_cache_allowlist_pruning) { };

TEST(flow_cache_allowlist_pruning, allowlist_on_excess_true)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 1;

    FlowCache* cache = new FlowCache(fcg);

    // Add flows until we trigger excess pruning
    for (int i = 0; i < 4; i++) {
        FlowKey flow_key;
        flow_key.port_l = 1000 + i;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
    }

    CHECK(cache->get_count() <= fcg.max_flows);
    CHECK(cache->get_lru_flow_count(allowlist_lru_index) > 0);
    CHECK(cache->get_excess_to_allowlist_count() > 0);

    cache->purge();
    delete cache;
}

TEST(flow_cache_allowlist_pruning, allowlist_on_excess_false_no_allowlist)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    fcg.allowlist_cache = false; // Disable allowlist_cache
    fcg.move_to_allowlist_on_excess = true;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 4; i++) {
        FlowKey flow_key;
        flow_key.port_l = 1000 + i;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
    }
    
    // Should prune normally, no allowlist flows
    CHECK_EQUAL(3, cache->get_count());
    CHECK_EQUAL(0, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

// Test that allowlist_on_excess behavior when move_to_allowlist_on_excess is disabled
TEST(flow_cache_allowlist_pruning, allowlist_on_excess_false_no_move_on_excess)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 3;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = false; // Disable move_to_allowlist_on_excess

    FlowCache* cache = new FlowCache(fcg);

    // Add flows until we trigger excess pruning
    for (int i = 0; i < 4; i++) {
        FlowKey flow_key;
        flow_key.port_l = 1000 + i;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
    }
    
    // Should prune normally, no allowlist flows from excess
    CHECK_EQUAL(3, cache->get_count());
    CHECK_EQUAL(0, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

// Test how prune_one handles allowed flows with EXCESS reason
TEST(flow_cache_allowlist_pruning, prune_one_excess_in_allowlist)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;

    FlowCache* cache = new FlowCache(fcg);
    // Create a test flow
    FlowKey flow_key;
    flow_key.port_l = 1234;
    flow_key.pkt_type = PktType::TCP;
    Flow* flow = cache->allocate(&flow_key);

    // Set the flow as allowed
    CHECK(cache->move_to_allowlist(flow));
    CHECK(flow->flags.in_allowlist == 1);

    // move_to_allowlist_on_excess is true, so Prune Reason::EXCESS on allowed flow should not succeed
    CHECK(cache->prune_one(PruneReason::EXCESS, true, allowlist_lru_index) == false);

    // cache still have the allowed flow
    CHECK_EQUAL(1, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(1, cache->get_count()); 

    cache->purge();
    delete cache;
}

// Test how prune_one handles allowed flows with timeout reasons
TEST(flow_cache_allowlist_pruning, prune_one_timeout_in_allowlist)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.allowlist_cache = true;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key;
    flow_key.port_l = 1234;
    flow_key.pkt_type = PktType::TCP;
    Flow* flow = cache->allocate(&flow_key);

    CHECK(cache->move_to_allowlist(flow));
    CHECK(flow->flags.in_allowlist == 1);

    CHECK_FALSE(cache->prune_one(PruneReason::IDLE_PROTOCOL_TIMEOUT, true, allowlist_lru_index));

    CHECK_EQUAL(1, cache->get_count());

    cache->purge();
    delete cache;
}

// Test that prune_one with MEMCAP reason evicts an allowlist LRU entry
TEST(flow_cache_allowlist_pruning, prune_one_memcap_in_allowlist)
{
    FlowCacheConfig fcg;
    fcg.allowlist_cache = true;
    fcg.max_flows = 10;

    FlowCache* cache = new FlowCache(fcg);

    // Populate the allowlist LRU directly with legitimate trust decisions.
    for (int i = 0; i < 6; i++)
    {
        FlowKey flow_key;
        flow_key.port_l = 1000 + i;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
        CHECK(cache->move_to_allowlist(flow));
    }

    CHECK_EQUAL(6, cache->get_count());
    CHECK_EQUAL(6, cache->get_lru_flow_count(allowlist_lru_index));

    // MEMCAP pruning must evict from the allowlist LRU.
    CHECK(cache->prune_one(PruneReason::MEMCAP, true, allowlist_lru_index));

    CHECK_EQUAL(5, cache->get_count());
    CHECK_EQUAL(5, cache->get_lru_flow_count(allowlist_lru_index));

    cache->purge();
    delete cache;
}

// EXCESS pruning of a proto LRU hard-prunes; admission to the allowlist is
// proactive (allocate() -> allowlist_on_excess_check), never at prune time.
TEST(flow_cache_allowlist_pruning, prune_one_excess_regular_flow_hard_prunes)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 6;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key;
    flow_key.port_l = 1234;
    flow_key.pkt_type = PktType::TCP;
    Flow* flow = cache->allocate(&flow_key);
    cache->unlink_uni(flow);

    FlowKey flow_key2;
    flow_key2.port_l = 5678;
    flow_key2.pkt_type = PktType::TCP;
    flow = cache->allocate(&flow_key2);
    cache->unlink_uni(flow);

    CHECK(cache->prune_one(PruneReason::EXCESS, true, to_utype(PktType::TCP)));

    // The oldest TCP flow is released (not moved to the allowlist).
    CHECK_EQUAL(1, cache->get_count());
    CHECK_EQUAL(0, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(1, cache->get_lru_flow_count(to_utype(PktType::TCP)));
    CHECK_EQUAL(0, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

// A non-TCP/UDP flow under EXCESS is hard-pruned, never allowlisted.
TEST(flow_cache_allowlist_pruning, prune_one_excess_icmp_not_allowlisted)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 6;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey flow_key;
    flow_key.port_l = 1234;
    flow_key.pkt_type = PktType::ICMP;
    Flow* flow = cache->allocate(&flow_key);
    cache->unlink_uni(flow);

    FlowKey flow_key2;
    flow_key2.port_l = 5678;
    flow_key2.pkt_type = PktType::ICMP;
    flow = cache->allocate(&flow_key2);
    cache->unlink_uni(flow);

    CHECK(cache->prune_one(PruneReason::EXCESS, true, to_utype(PktType::ICMP)));

    CHECK_EQUAL(1, cache->get_count());
    CHECK_EQUAL(0, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}


TEST(flow_cache_allowlist_pruning, prune_multiple_allowlist_pruning)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 5; i++)
    {
        FlowKey flow_key;
        flow_key.port_l = 1000 + i;
        flow_key.pkt_type = PktType::TCP;
        Flow* flow = cache->allocate(&flow_key);
        cache->unlink_uni(flow);
    }

    for (int i = 0; i < 5; i++)
    {
        FlowKey flow_key;
        flow_key.port_l = 2000 + i;
        flow_key.pkt_type = PktType::UDP;
        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow));
    }

    CHECK_EQUAL(10, cache->get_count());
    CHECK_EQUAL(5, cache->get_lru_flow_count(to_utype(PktType::TCP)));
    CHECK_EQUAL(5, cache->get_lru_flow_count(allowlist_lru_index));

    // Using MEMCAP reason should first prune from allowlist LRU
    CHECK_EQUAL(5, cache->prune_multiple(PruneReason::MEMCAP, true));

    // Check that we now have only TCP flows, allowlist was pruned first
    CHECK_EQUAL(5, cache->get_count());
    CHECK_EQUAL(5, cache->get_lru_flow_count(to_utype(PktType::TCP)));
    CHECK_EQUAL(0, cache->get_lru_flow_count(allowlist_lru_index));

    cache->purge();
    delete cache;
}


#ifdef ALLOWLIST_MOVE_ON_EXCESS
TEST_GROUP(flow_cache_move_on_excess)
{
    // Guard against Flow-pointer reuse across tests: any prior test that
    // aborted mid-run could leave a dangling pointer in the standby set,
    // and a new allocation may land at the same address.
    void setup() override    { ha_standby_flows.clear(); }
    void teardown() override { ha_standby_flows.clear(); }
};

TEST(flow_cache_move_on_excess, admission_trigger_below_threshold_no_move)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(6u, cache->get_count());
    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, admission_trigger_at_threshold_moves_oldest)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 7; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    FlowKey k;
    k.port_l = 2000;
    k.pkt_type = PktType::TCP;
    Flow* f = cache->allocate(&k);
    cache->unlink_uni(f);

    CHECK_EQUAL(1u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(1u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(8u, cache->get_count());

    cache->purge();
    delete cache;
}

// Positive contract: the admitted flow is the oldest eligible one and carries
// the full excess-move state (in_allowlist, allowed_on_excess, WHITELIST verdict).
TEST(flow_cache_move_on_excess, admitted_flow_carries_whitelist_state)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey oldest_key;
    oldest_key.port_l = 1000;
    oldest_key.pkt_type = PktType::TCP;
    Flow* oldest = cache->allocate(&oldest_key);
    cache->unlink_uni(oldest);

    for (int i = 1; i < 8; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(1u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(1u, cache->get_lru_flow_count(allowlist_lru_index));

    // The oldest flow is the one moved, and it carries the full move state.
    const Flow* moved = cache->find(&oldest_key);
    CHECK(moved == oldest);
    CHECK_EQUAL(1u, moved->flags.in_allowlist);
    CHECK_EQUAL(1u, moved->flags.allowed_on_excess);
    CHECK(moved->last_verdict == DAQ_VERDICT_WHITELIST);

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, total_stays_bounded_by_max_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 100; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
        CHECK(cache->get_count() <= fcg.max_flows);
    }

    CHECK_EQUAL(10u, cache->get_count());
    CHECK_EQUAL(3u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(93u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(90u, cache->get_prunes(PruneReason::EXCESS));

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, disabled_when_max_excess_zero)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 0;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 20; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());
    CHECK(cache->get_count() <= fcg.max_flows);

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, disabled_when_max_excess_equals_max_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 10;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 20; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());
    CHECK(cache->get_count() <= fcg.max_flows);

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, disabled_when_max_excess_exceeds_max_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 20;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 20; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());
    CHECK(cache->get_count() <= fcg.max_flows);

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, disabled_when_move_on_excess_false)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = false;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 20; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}


TEST(flow_cache_move_on_excess, blocked_prefix_rotates_and_admits_eligible)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 20;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 10;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 8; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
        f->block();
    }

    FlowKey ek;
    ek.port_l = 2000;
    ek.pkt_type = PktType::TCP;
    Flow* eligible = cache->allocate(&ek);
    cache->unlink_uni(eligible);

    unsigned before = cache->get_excess_to_allowlist_count();
    CHECK_EQUAL(0u, before);

    for (int i = 0; i < 20; i++)
    {
        FlowKey k;
        k.port_l = 3000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(20u, cache->get_count());
    CHECK_EQUAL(5u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(14u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(9u, cache->get_prunes(PruneReason::EXCESS));

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, scan_cap_exhausted_all_blocked)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 20;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 5;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 8; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
        f->block();
    }
    for (int i = 0; i < 7; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    FlowKey trigger_key;
    trigger_key.port_l = 3000;
    trigger_key.pkt_type = PktType::TCP;
    Flow* f = cache->allocate(&trigger_key);
    cache->unlink_uni(f);

    CHECK_EQUAL(16u, cache->get_count());
    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(0u, cache->get_prunes(PruneReason::EXCESS));

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, mixed_tcp_udp_both_admitted)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 20;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 5;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 40; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = (i % 2 == 0) ? PktType::TCP : PktType::UDP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK(cache->get_count() <= fcg.max_flows);
    CHECK(cache->get_excess_to_allowlist_count() > 0);

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, expired_reclaimable_defers_admission_across_protocols)
{
    // Reclaimable expired TCP head + eligible UDP head → defer entirely.
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey k_tcp;
    k_tcp.port_l = 1000;
    k_tcp.pkt_type = PktType::TCP;
    Flow* tcp_head = cache->allocate(&k_tcp);
    cache->unlink_uni(tcp_head);
    tcp_head->set_hard_expiration();
    tcp_head->expire_time = 1;

    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::UDP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, expired_standby_head_does_not_defer_admission)
{
    // Expired but HA-standby TCP head → timeout() will not reclaim it,
    // so admission must NOT defer. UDP LRU head must be admitted, and
    // the standby TCP must remain untouched (still in TCP LRU, not in
    // allowlist).
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey k_tcp;
    k_tcp.port_l = 1000;
    k_tcp.pkt_type = PktType::TCP;
    Flow* tcp_head = cache->allocate(&k_tcp);
    cache->unlink_uni(tcp_head);
    tcp_head->set_hard_expiration();
    tcp_head->expire_time = 1;
    set_standby(tcp_head, true);

    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::UDP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(1u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(1u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(0u, tcp_head->flags.in_allowlist);

    set_standby(tcp_head, false);
    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, expired_nonstandby_defers_even_with_standby_present)
{
    // Expired non-standby TCP at LRU head + unexpired standby TCP behind
    // it + eligible UDP. Two invariants pinned:
    //   (a) admission defers across all protocols (expired non-standby
    //       signals imminent capacity)
    //   (b) even without the defer, the unexpired standby TCP would not
    //       be admitted
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey k1;
    k1.port_l = 1000;
    k1.pkt_type = PktType::TCP;
    Flow* expired_tcp = cache->allocate(&k1);
    cache->unlink_uni(expired_tcp);
    expired_tcp->set_hard_expiration();
    expired_tcp->expire_time = 1;

    FlowKey k2;
    k2.port_l = 1001;
    k2.pkt_type = PktType::TCP;
    Flow* standby_tcp = cache->allocate(&k2);
    cache->unlink_uni(standby_tcp);
    set_standby(standby_tcp, true);

    for (int i = 0; i < 5; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::UDP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(0u, standby_tcp->flags.in_allowlist);

    set_standby(standby_tcp, false);
    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, all_standby_head_no_admission)
{
    // Threshold reached, every scanned candidate is HA-standby. Assert
    // no admission and no state mutation on any standby flow.
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    std::vector<Flow*> standby_flows;
    for (int i = 0; i < 7; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = (i % 2 == 0) ? PktType::TCP : PktType::UDP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
        set_standby(f, true);
        standby_flows.push_back(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());
    for ( const Flow* f : standby_flows )
    {
        CHECK_EQUAL(0u, f->flags.in_allowlist);
        CHECK_EQUAL(0u, f->flags.allowed_on_excess);
    }

    for ( const Flow* f : standby_flows )
        set_standby(f, false);
    cache->purge();
    delete cache;
}

// The oldest candidate is blocked (SSNFLAG_BLOCK): it must not be admitted,
// and admission falls through to the next eligible flow.
TEST(flow_cache_move_on_excess, blocked_head_not_admitted)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey k1;
    k1.port_l = 1000;
    k1.pkt_type = PktType::TCP;
    Flow* blocked_tcp = cache->allocate(&k1);
    cache->unlink_uni(blocked_tcp);
    blocked_tcp->set_state(Flow::FlowState::BLOCK);
    blocked_tcp->block();

    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, blocked_tcp->flags.in_allowlist);
    CHECK(blocked_tcp->last_verdict != DAQ_VERDICT_WHITELIST);
    // A younger eligible flow is admitted instead of the blocked head.
    CHECK_EQUAL(1u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

// A flow in FlowState::RESET without SSNFLAG_BLOCK is still not admitted;
// was_blocked() alone would miss it.
TEST(flow_cache_move_on_excess, reset_head_not_admitted)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey k1;
    k1.port_l = 1000;
    k1.pkt_type = PktType::TCP;
    Flow* reset_tcp = cache->allocate(&k1);
    cache->unlink_uni(reset_tcp);
    reset_tcp->set_state(Flow::FlowState::RESET);

    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, reset_tcp->flags.in_allowlist);
    CHECK(reset_tcp->flow_state == Flow::FlowState::RESET);
    CHECK_EQUAL(1u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

// A flow with an active deferred-trust decision must not be trusted/admitted.
TEST(flow_cache_move_on_excess, deferred_trust_head_not_admitted)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    FlowKey k1;
    k1.port_l = 1000;
    k1.pkt_type = PktType::TCP;
    Flow* deferred_tcp = cache->allocate(&k1);
    cache->unlink_uni(deferred_tcp);
    deferred_tcp->set_deferred_trust(1, true);
    CHECK(deferred_tcp->cannot_trust());

    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, deferred_tcp->flags.in_allowlist);
    CHECK(deferred_tcp->flow_state != Flow::FlowState::ALLOW);
    CHECK_EQUAL(1u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, legit_trust_flow_prunable_under_excess)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 3; i++)
    {
        FlowKey k;
        k.port_l = 9000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
        CHECK(cache->move_to_allowlist(f));
    }

    unsigned allowlist_before = cache->get_lru_flow_count(allowlist_lru_index);
    CHECK_EQUAL(3u, allowlist_before);

    for (int i = 0; i < 30; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    CHECK_EQUAL(10u, cache->get_count());
    CHECK_EQUAL(6u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(26u, cache->get_excess_to_allowlist_count());
    CHECK_EQUAL(23u, cache->get_prunes(PruneReason::EXCESS));

    cache->purge();
    delete cache;
}

TEST(flow_cache_move_on_excess, reload_threshold_change_no_active_drain)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 20;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 10;

    FlowCache* cache = new FlowCache(fcg);

    for (int i = 0; i < 30; i++)
    {
        FlowKey k;
        k.port_l = 1000 + i;
        k.pkt_type = PktType::TCP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    unsigned allowlist_before = cache->get_lru_flow_count(allowlist_lru_index);
    CHECK(allowlist_before > 0);

    FlowCacheConfig new_cfg = fcg;
    new_cfg.allowlist_max_excess_flows = 2;
    cache->set_flow_cache_config(new_cfg);

    CHECK_EQUAL(allowlist_before, cache->get_lru_flow_count(allowlist_lru_index));

    cache->purge();
    delete cache;
}
TEST(flow_cache_move_on_excess, pruning_timeout_eligible_defers_admission)
{
    // A flow whose idle_timeout has not expired but whose last_data_seen
    // falls outside config.pruning_timeout is reclaimable by prune_idle().
    // Admission must defer rather than trust that flow.
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    fcg.allowlist_cache = true;
    fcg.move_to_allowlist_on_excess = true;
    fcg.allowlist_max_excess_flows = 3;
    fcg.pruning_timeout = 100;   // prune_idle reclaims flows older than 100s

    FlowCache* cache = new FlowCache(fcg);

    // TCP LRU head: last seen at t=1, idle_timeout=9999 (not per-flow expired),
    // but last_data_seen + pruning_timeout = 101 < now=1000 → prune_idle eligible.
    FlowKey k_tcp;
    k_tcp.port_l = 1000;
    k_tcp.pkt_type = PktType::TCP;
    Flow* tcp_head = cache->allocate(&k_tcp);
    cache->unlink_uni(tcp_head);
    tcp_head->last_data_seen = 1;
    tcp_head->set_idle_timeout(9999);

    // Fill enough UDP flows to push past the allowlist admission threshold.
    for (int i = 0; i < 6; i++)
    {
        FlowKey k;
        k.port_l = 2000 + i;
        k.pkt_type = PktType::UDP;
        Flow* f = cache->allocate(&k);
        cache->unlink_uni(f);
    }

    // now=1000: tcp_head->last_data_seen(1) + pruning_timeout(100) = 101 < 1000
    // → prune_idle would reclaim it → admission must defer.
    cache->allowlist_on_excess_check(1000);

    CHECK_EQUAL(0u, cache->get_lru_flow_count(allowlist_lru_index));
    CHECK_EQUAL(0u, cache->get_excess_to_allowlist_count());

    cache->purge();
    delete cache;
}

#endif // ALLOWLIST_MOVE_ON_EXCESS

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
