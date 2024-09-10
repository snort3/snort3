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

namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
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

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
