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
void Flow::reset(bool) { }
void Flow::trust() { }
void Flow::free_flow_data() { }
void Flow::set_client_initiate(Packet*) { }
void Flow::set_direction(Packet*) { }
void Flow::set_mpls_layer_per_dir(const Packet*) { }
void FlowStash::reset() { }
FlowDataStore::~FlowDataStore() = default;
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

// An inner 5-tuple decapsulated from a UDP tunnel is named by the packet
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

    // the same 5-tuple, but reached by decapsulating a UDP tunnel
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
