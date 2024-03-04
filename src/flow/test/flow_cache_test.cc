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

#include "detection/detection_engine.h"
#include "flow/expect_cache.h"
#include "flow/flow_cache.h"
#include "flow/ha.h"
#include "flow/session.h"
#include "main/analyzer.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
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

THREAD_LOCAL bool Active::s_suspend = false;
THREAD_LOCAL Active::ActiveSuspendReason Active::s_suspend_reason = Active::ASP_NONE;

THREAD_LOCAL const Trace* stream_trace = nullptr;

void Active::drop_packet(snort::Packet const*, bool) { }
void Active::set_drop_reason(char const*) { }
ExpectCache::ExpectCache(uint32_t) { }
ExpectCache::~ExpectCache() = default;
bool ExpectCache::check(Packet*, Flow*) { return true; }
void DetectionEngine::disable_all(Packet*) { }
Flow* HighAvailabilityManager::import(Packet&, FlowKey&) { return nullptr; }
bool HighAvailabilityManager::in_standby(Flow*) { return false; }
SfIpRet SfIp::set(void const*, int) { return SFIP_SUCCESS; }
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) {}
void ThreadConfig::preemptive_kick() {}

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

time_t packet_time() { return 0; }

void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}

namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
}

int ExpectCache::add_flow(const Packet*, PktType, IpProtocol, const SfIp*, uint16_t,
    const SfIp*, uint16_t, char, FlowData*, SnortProtocolId, bool, bool, bool, bool)
{
    return 1;
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

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
