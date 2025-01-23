//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow_control.h"

#include "control/control.h"
#include "detection/detection_engine.h"
#include "flow/expect_cache.h"
#include "flow/flow_cache.h"
#include "flow/ha.h"
#include "flow/session.h"
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
#include "utils/util.h"
#include "trace/trace_api.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "flow_stubs.h"

using namespace snort;

THREAD_LOCAL const Trace* stream_trace = nullptr;
THREAD_LOCAL FlowControl* flow_con = nullptr;

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

Flow* HighAvailabilityManager::import(Packet&, FlowKey&) { return nullptr; }
bool HighAvailabilityManager::in_standby(Flow*) { return false; }

uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) {}

void ThreadConfig::preemptive_kick() {}
unsigned ThreadConfig::get_instance_max() { return 0; }

SfIpRet SfIp::set(void const*, int) { return SFIP_SUCCESS; }
SfIpRet SfIp::set(void const*) { return SFIP_SUCCESS; }
SfIpRet SfIp::pton(const int, const char* ) { return SFIP_SUCCESS; }

const char* SfIp::ntop(char* buf, int) const
{ buf[0] = 0; return buf; }

bool ControlConn::respond(const char*, ...) { return true; }

class TcpStreamTracker;
const char* stream_tcp_state_to_str(const TcpStreamTracker&) { return "error"; }

void LogMessage(const char*, ...) { }

namespace snort
{
Flow::~Flow() = default;
void Flow::init(PktType) { }
void Flow::flush(bool) { }
void Flow::reset(bool) { }
void Flow::free_flow_data() { }
void Flow::set_client_initiate(Packet*) { }
void Flow::set_direction(Packet*) { }
void Flow::set_mpls_layer_per_dir(Packet*) { }
void packet_gettimeofday(struct timeval* ) { }

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

class DummyCache : public FlowCache
{
    public:
        DummyCache(const FlowCacheConfig& cfg) : FlowCache(cfg) {}
        ~DummyCache() = default;
        void output_flow(std::fstream& stream, const Flow& flow, const struct timeval& now) const override { (void)stream, (void)flow, (void)now; };
        bool filter_flows(const Flow& flow, const FilterFlowCriteria& ffc) const override { (void)flow; (void)ffc; return true; };
};

class DummyCacheWithFilter : public FlowCache
{
    public:
        DummyCacheWithFilter(const FlowCacheConfig& cfg) : FlowCache(cfg) {}
        ~DummyCacheWithFilter() = default;
        void output_flow(std::fstream& stream, const Flow& flow, const struct timeval& now) const override { (void)stream, (void)flow, (void)now; };
};

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

    for(uint8_t i = to_utype(PktType::NONE); i <= to_utype(PktType::MAX); i++)
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
    DummyCache* cache = new DummyCache(fcg);
    int port = 1;

    // Adding two UDP flows and moving them to allow list
    for (unsigned i = 0; i < 2; ++i) {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::UDP;
        
        Flow* flow = cache->allocate(&flow_key);
        CHECK(cache->move_to_allowlist(flow) == true);  // Move flow to allow list

        Flow* found_flow = cache->find(&flow_key);
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
    DummyCache* cache = new DummyCache(fcg);
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
    PruneStats stats;
    FlowCacheConfig fcg;
    fcg.max_flows = 10;
    fcg.prune_flows = 5;
    DummyCache* cache = new DummyCache(fcg);
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

    for (uint8_t i = to_utype(PktType::NONE); i <= to_utype(PktType::MAX); ++i) 
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

        Flow* found_flow = cache->find(&flow_key);
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

            Flow* found_flow = cache->find(&flow_key);
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
    DummyCache* cache = new DummyCache(fcg);
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

TEST_GROUP(dump_flows) { };

TEST(dump_flows, dump_flows_with_all_empty_caches)
{
    FlowCacheConfig fcg;
    FilterFlowCriteria ffc;
    std::fstream dump_stream;
    DummyCache *cache = new DummyCache(fcg);
    CHECK(cache->dump_flows(dump_stream, 100, ffc, true, 1 ) == true);
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

TEST(dump_flows, dump_flows_with_one_tcp_flow)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 5;
    FilterFlowCriteria ffc;
    std::fstream dump_stream;
    DummyCache *cache = new DummyCache(fcg);

    FlowKey flow_key;
    flow_key.port_l = 1;
    flow_key.pkt_type = PktType::TCP;
    cache->allocate(&flow_key);
    CHECK(cache->dump_flows(dump_stream, 100, ffc, true, 1 ) == true);
    CHECK (cache->get_count() == 1);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

TEST(dump_flows, dump_flows_with_102_tcp_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 500;
    FilterFlowCriteria ffc;
    std::fstream dump_stream;
    DummyCache *cache = new DummyCache(fcg);
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
    CHECK(cache->dump_flows(dump_stream, 100, ffc, true, 1 ) == false);
    CHECK(cache->dump_flows(dump_stream, 100, ffc, false, 1 ) == true);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK (cache->get_count() == 0);
    delete cache;
}

TEST(dump_flows, dump_flows_with_102_tcp_flows_and_202_udp_flows)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 500;
    FilterFlowCriteria ffc;
    std::fstream dump_stream;
    DummyCache *cache = new DummyCache(fcg);
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
    CHECK(cache->dump_flows(dump_stream, 100, ffc, true, 1 ) == false);
    CHECK(cache->dump_flows(dump_stream, 100, ffc, false, 1 ) == false);
    CHECK(cache->dump_flows(dump_stream, 100, ffc, false, 1 ) == true);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK (cache->get_count() == 0);
    delete cache;
}

TEST(dump_flows, dump_flows_with_allowlist)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 500;
    FilterFlowCriteria ffc;
    std::fstream dump_stream;
    DummyCache* cache = new DummyCache(fcg);
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
    CHECK(cache->dump_flows(dump_stream, 10, ffc, true, 1) == true);


    // Verify that allow listed flows exist and are correctly handled
    for (unsigned i = 0; i < 5; ++i)
    {
        flow_key[i].port_l = i + 1;  // allow listed flow ports
        flow_key[i].pkt_type = PktType::TCP;
        Flow* flow = cache->find(&flow_key[i]);
        CHECK(flow != nullptr);  // Ensure the flow is found
        CHECK(flow->flags.in_allowlist == 1);  // Ensure the flow is allow listed
    }

    // Ensure cache cleanup and correct flow counts
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK(cache->get_count() == 0);
    delete cache;
}

TEST(dump_flows, dump_flows_no_flows_to_dump)
{
    FlowCacheConfig fcg;
    FilterFlowCriteria ffc;
    fcg.max_flows = 10;
    std::fstream dump_stream;

    DummyCache* cache = new DummyCache(fcg);
    CHECK(cache->dump_flows(dump_stream, 100, ffc, true, 1) == true);

    delete cache;   
}

TEST_GROUP(dump_flows_summary) { };

TEST(dump_flows_summary, dump_flows_summary_with_all_empty_caches)
{
    FlowCacheConfig fcg;
    FilterFlowCriteria ffc;
    FlowsSummary flows_summary;
    DummyCache *cache = new DummyCache(fcg);
    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);
    CHECK(cache->get_flows_allocated() == 0);

    FlowsTypeSummary expected_type{};
    CHECK(expected_type == flows_summary.type_summary);

    FlowsStateSummary expected_state{};
    CHECK(expected_state == flows_summary.state_summary);

    delete cache;
}

TEST(dump_flows_summary, dump_flows_summary_with_one_tcp_flow)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 5;
    FilterFlowCriteria ffc;
    FlowsSummary flows_summary;
    DummyCache *cache = new DummyCache(fcg);

    FlowKey flow_key;
    flow_key.port_l = 1;
    flow_key.pkt_type = PktType::TCP;
    cache->allocate(&flow_key);
    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);
    CHECK(cache->get_count() == 1);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = 1;
    CHECK(expected_type == flows_summary.type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 1;
    CHECK(expected_state == flows_summary.state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}


TEST(dump_flows_summary, dump_flows_summary_with_5_of_each_flow)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 50;
    FilterFlowCriteria ffc;
    FlowsSummary flows_summary;
    DummyCache *cache = new DummyCache(fcg);
    int port = 1;

    std::vector<PktType> types = {PktType::IP, PktType::ICMP, PktType::TCP, PktType::UDP};

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
    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);

    FlowsTypeSummary expected_type{};
    for (const auto& type : types) 
        expected_type[to_utype(type)] = 5;
    CHECK(expected_type == flows_summary.type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 5 * types.size();
    CHECK(expected_state == flows_summary.state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK (cache->get_count() == 0);
    delete cache;
}

TEST(dump_flows_summary, dump_flows_summary_with_different_flow_states)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 50;
    FilterFlowCriteria ffc;
    FlowsSummary flows_summary;
    DummyCache *cache = new DummyCache(fcg);
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

    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);
    CHECK(cache->get_count() == flows_number * types.size());

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = flows_number * types.size();
    CHECK(expected_type == flows_summary.type_summary);

    FlowsStateSummary expected_state{};
    for (const auto& type : types) 
    {
        expected_state[to_utype(type)] = flows_number;
    }
    CHECK(expected_state == flows_summary.state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}

TEST(dump_flows_summary, dump_flows_summary_with_allowlist)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 50;
    FilterFlowCriteria ffc;
    FlowsSummary flows_summary{};
    DummyCache* cache = new DummyCache(fcg);
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

    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = 10;
    CHECK(expected_type == flows_summary.type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 10;
    CHECK(expected_state == flows_summary.state_summary);

    // Verify that allow listed flows exist and are correctly handled
    for (unsigned i = 0; i < 5; ++i)
    {
        flow_key[i].port_l = i + 1;  // allow listed flow ports
        flow_key[i].pkt_type = PktType::TCP;
        Flow* flow = cache->find(&flow_key[i]);
        CHECK(flow != nullptr);  // Ensure the flow is found
        CHECK(flow->flags.in_allowlist == 1);  // Ensure the flow is allow listed
    }

    // Ensure cache cleanup and correct flow counts
    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    CHECK(cache->get_count() == 0);
    delete cache;
}

TEST(dump_flows_summary, dump_flows_summary_with_filter)
{
    FlowCacheConfig fcg;
    fcg.max_flows = 50;
    FilterFlowCriteria ffc;
    FlowsSummary flows_summary;
    DummyCacheWithFilter *cache = new DummyCacheWithFilter(fcg);
    unsigned flows_number = 5;

    std::vector<PktType> types = {PktType::IP, PktType::ICMP, PktType::TCP, PktType::UDP};

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
    ffc.pkt_type = PktType::TCP;
    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);

    FlowsTypeSummary expected_type{};
    expected_type[to_utype(PktType::TCP)] = flows_number;
    CHECK(expected_type == flows_summary.type_summary);

    FlowsStateSummary expected_state{};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = flows_number;
    CHECK(expected_state == flows_summary.state_summary);

    //check port filter
    ffc.pkt_type = PktType::NONE;
    ffc.source_port = 1;
    flows_summary = {};
    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);

    expected_type = {};
    for (const auto& type : types) 
        expected_type[to_utype(type)] = 1;
    CHECK(expected_type == flows_summary.type_summary);

    expected_state = {};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = types.size();
    CHECK(expected_state == flows_summary.state_summary);

    // check combined filter
    ffc.pkt_type = PktType::UDP;
    ffc.source_port = 1;
    ffc.destination_port = 80;
    flows_summary = {};
    CHECK(cache->dump_flows_summary(flows_summary, ffc) == true);

    expected_type = {};
    expected_type[to_utype(PktType::UDP)] = 1;
    CHECK(expected_type == flows_summary.type_summary);

    expected_state = {};
    expected_state[to_utype(snort::Flow::FlowState::SETUP)] = 1;
    CHECK(expected_state == flows_summary.state_summary);

    cache->purge();
    CHECK(cache->get_flows_allocated() == 0);
    delete cache;
}



TEST_GROUP(flow_cache_lrus) 
{ 
    FlowCacheConfig fcg;
    DummyCache* cache;

    void setup()
    {
        fcg.max_flows = 20;
        cache = new DummyCache(fcg);
    }

    void teardown()
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
        Flow* flow = cache->allocate(&flow_keys[i]);
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

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
