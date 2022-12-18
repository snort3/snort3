//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "main/policy.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "packet_tracer/packet_tracer.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "stream/stream.h"
#include "utils/util.h"
#include "trace/trace_api.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL bool Active::s_suspend = false;
THREAD_LOCAL Active::ActiveSuspendReason Active::s_suspend_reason = Active::ASP_NONE;

THREAD_LOCAL PacketTracer* snort::s_pkt_trace = nullptr;
THREAD_LOCAL const Trace* stream_trace = nullptr;

void Active::drop_packet(snort::Packet const*, bool) { }
PacketTracer::~PacketTracer() = default;
void PacketTracer::log(const char*, ...) { }
void PacketTracer::open_file() { }
void PacketTracer::dump_to_daq(Packet*) { }
void PacketTracer::reset(bool) { }
void PacketTracer::pause() { }
void PacketTracer::unpause() { }
void Active::set_drop_reason(char const*) { }
Packet::Packet(bool) { }
Packet::~Packet() = default;
uint32_t Packet::get_flow_geneve_vni() const { return 0; }
Flow::Flow()
{
    constexpr size_t offset = offsetof(Flow, key);
    // FIXIT-L need a struct to zero here to make future proof
    memset((uint8_t*)this+offset, 0, sizeof(*this)-offset);
}
Flow::~Flow() = default;
DetectionEngine::DetectionEngine() = default;
ExpectCache::~ExpectCache() = default;
DetectionEngine::~DetectionEngine() = default;
void Flow::init(PktType) { }
void Flow::term() { }
void Flow::flush(bool) { }
void Flow::reset(bool) { }
void Flow::free_flow_data() { }
void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }
void DataBus::publish(unsigned, unsigned, const uint8_t*, unsigned, Flow*) { }
void DataBus::publish(unsigned, unsigned, Packet*, Flow*) { }
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
void Flow::set_client_initiate(Packet*) { }
void Flow::set_direction(Packet*) { }
void set_network_policy(unsigned) { }
void set_inspection_policy(unsigned) { }
void set_ips_policy(const snort::SnortConfig*, unsigned) { }
void Flow::set_mpls_layer_per_dir(Packet*) { }
void DetectionEngine::disable_all(Packet*) { }
void Stream::drop_traffic(const Packet*, char) { }
bool Stream::blocked_flow(Packet*) { return true; }
ExpectCache::ExpectCache(uint32_t) { }
bool ExpectCache::check(Packet*, Flow*) { return true; }
bool ExpectCache::is_expected(Packet*) { return true; }
Flow* HighAvailabilityManager::import(Packet&, FlowKey&) { return nullptr; }
bool HighAvailabilityManager::in_standby(Flow*) { return true; }
SfIpRet SfIp::set(void const*, int) { return SFIP_SUCCESS; }
void snort::trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}
uint8_t snort::TraceApi::get_constraints_generation() { return 0; }
void snort::TraceApi::filter(const Packet&) {}

namespace snort
{
NetworkPolicy* get_network_policy() { return nullptr; }
InspectionPolicy* get_inspection_policy() { return nullptr; }
IpsPolicy* get_ips_policy() { return nullptr; }
unsigned SnortConfig::get_thread_reload_id() { return 0; }

namespace layer
{
const vlan::VlanTagHdr* get_vlan_layer(const Packet* const) { return nullptr; }
}
time_t packet_time() { return 0; }
}

namespace snort
{
namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
}

void Stream::stop_inspection(Flow*, Packet*, char, int32_t, int) { }


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

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
