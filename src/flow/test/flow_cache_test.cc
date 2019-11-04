
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// flow_control_test.cc author Shivakrishna Mulka <smulka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_common.h>

#include "flow/flow_control.h"

#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "memory/memory_cap.h"
#include "packet_io/active.h"
#include "packet_tracer/packet_tracer.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "stream/stream.h"
#include "utils/util.h"
#include "flow/expect_cache.h"
#include "flow/flow_cache.h"
#include "flow/ha.h"
#include "flow/session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL bool Active::s_suspend = false;

THREAD_LOCAL PacketTracer* snort::s_pkt_trace = nullptr;

PacketTracer::PacketTracer() { }
PacketTracer::~PacketTracer() { }
void PacketTracer::log(const char* format, ...) { }
void PacketTracer::open_file() { }
void PacketTracer::dump_to_daq(Packet* p) { }
void PacketTracer::reset() { }
Packet::Packet(bool) { }
Packet::~Packet() { }
Flow::Flow() { memset(this, 0, sizeof(*this)); }
Flow::~Flow() { }
DetectionEngine::DetectionEngine() { }
ExpectCache::~ExpectCache() { }
DetectionEngine::~DetectionEngine() { }
void Flow::init(PktType type) { }
void Flow::term() { }
void Flow::reset(bool) { }
void set_network_policy(SnortConfig* sc, unsigned i) { }
void DataBus::publish(const char* key, const uint8_t* buf, unsigned len, Flow* f) { }
void DataBus::publish(const char* key, Packet* p, Flow* f) { }
SnortConfig* SnortConfig::get_conf() { return nullptr; }
void Flow::set_direction(Packet* p) { }
void set_inspection_policy(SnortConfig* sc, unsigned i) { }
void set_ips_policy(SnortConfig* sc, unsigned i) { }
void Flow::set_mpls_layer_per_dir(Packet* p) { }
void DetectionEngine::disable_all(Packet* p) { }
void Stream::drop_traffic(const Packet* p, char dir) { }
bool Stream::blocked_flow(Packet* p) { return true; }
ExpectCache::ExpectCache(uint32_t max) { }
bool ExpectCache::check(Packet* p, Flow* lws) { return true; }
bool ExpectCache::is_expected(Packet* p) { return true; }
Flow* HighAvailabilityManager::import(Packet& p, FlowKey& key) { return nullptr; }
bool HighAvailabilityManager::in_standby(Flow* flow) { return true; }
SfIpRet SfIp::set(void const*, int) { return SfIpRet::SFIP_SUCCESS; }
namespace memory
{
void MemoryCap::update_allocations(unsigned long m) { }
void MemoryCap::update_deallocations(unsigned long m) { }
bool MemoryCap::over_threshold() { return true; }
}

namespace snort
{
namespace layer
{
const vlan::VlanTagHdr* get_vlan_layer(const Packet* const p) { return nullptr; }
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

void Stream::stop_inspection(
    Flow* flow, Packet* p, char dir,
    int32_t /*bytes*/, int /*response*/) { }


int ExpectCache::add_flow(const Packet *ctrlPkt,
    PktType type, IpProtocol ip_proto,
    const SfIp* cliIP, uint16_t cliPort,
    const SfIp* srvIP, uint16_t srvPort,
    char direction, FlowData* fd, SnortProtocolId snort_protocol_id)
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

    Flow *list_flows[fcg.max_flows];
    int first_port = 1;
    int second_port = 2;

    // Add two flows in the flow cache
    FlowKey flow_key;
    memset(&flow_key, 0, sizeof(FlowKey));
    flow_key.pkt_type = PktType::TCP;
    
    flow_key.port_l = first_port;
    list_flows[0] = cache->allocate(&flow_key);

    flow_key.port_l = second_port;
    list_flows[1] = cache->allocate(&flow_key);

    CHECK(cache->get_count() == fcg.max_flows);

    // block the second flow
    list_flows[1]->block();

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

    Flow *list_flows[fcg.max_flows];
    for ( int i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        list_flows[i] = cache->allocate(&flow_key);
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

    Flow *list_flows[fcg.max_flows];
    for ( int i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        list_flows[i] = cache->allocate(&flow_key);
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

    Flow *list_flows[fcg.max_flows];
    for ( int i = 0; i < fcg.max_flows; i++ )
    {
        FlowKey flow_key;
        flow_key.port_l = port++;
        flow_key.pkt_type = PktType::TCP;
        list_flows[i] = cache->allocate(&flow_key);
        list_flows[i]->block();
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
