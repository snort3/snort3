
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
FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg) { }
FlowCache::~FlowCache() { }
Flow::Flow() = default;
Flow::~Flow() { }
DetectionEngine::DetectionEngine() { }
ExpectCache::~ExpectCache() { }
DetectionEngine::~DetectionEngine() { }
unsigned FlowCache::purge() { return 1; }
Flow* FlowCache::find(const FlowKey* key) { return nullptr; }
Flow* FlowCache::get(const FlowKey* key) { return nullptr; }
void FlowCache::push(Flow* flow) { }
bool FlowCache::prune_one(PruneReason reason, bool do_cleanup) { return true; }
unsigned FlowCache::timeout(unsigned num_flows, time_t thetime) { return 1; }
void Flow::init(PktType type) { }
void set_network_policy(SnortConfig* sc, unsigned i) { } 
void DataBus::publish(const char* key, const uint8_t* buf, unsigned len, Flow* f) { }
void DataBus::publish(const char* key, Packet* p, Flow* f) { }
SnortConfig* SnortConfig::get_conf() { return nullptr; }
void FlowCache::unlink_uni(Flow* flow) { }
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
Flow* HighAvailabilityManager::import(Packet& p, FlowKey& key) { }

namespace memory 
{
bool MemoryCap::over_threshold() { return true; }
}

namespace snort
{
namespace layer
{
const vlan::VlanTagHdr* get_vlan_layer(const Packet* const p) { return nullptr; }
}
}

namespace snort
{
namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
}

bool FlowKey::init(
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    uint16_t vlanId, uint32_t mplsId, uint16_t addrSpaceId)
{
   return true;
}

bool FlowKey::init(
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, const SfIp *dstIP,
    uint32_t id, uint16_t vlanId,
    uint32_t mplsId, uint16_t addrSpaceId)
{
    return true;
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

int FlowCache::release(Flow* flow, PruneReason reason, bool do_cleanup) 
{ 
    return 1; 
}

TEST_GROUP(stale_flow) { };

TEST(stale_flow, stale_flow)
{
    Packet* p = new Packet(false);
    Flow* flow = new Flow;
    FlowCacheConfig fcg;
    FlowCache *cache = new FlowCache(fcg);
    FlowControl *flow_con = new FlowControl(fcg);
    DAQ_PktHdr_t dh = { };

    dh.flags = DAQ_PKT_FLAG_NEW_FLOW;
    p->pkth = &dh;
    CHECK(flow_con->stale_flow_cleanup(cache, flow, p) == nullptr);

    dh.flags &= ~DAQ_PKT_FLAG_NEW_FLOW;
    CHECK(flow_con->stale_flow_cleanup(cache, flow, p) == flow);

    p->pkth = nullptr;
    delete flow;
    delete p;
    delete flow_con;
    delete cache;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
} 
