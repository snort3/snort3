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

// flow_control_test.cc author Shivakrishna Mulka <smulka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_common.h>

#include "flow/flow_control.h"

#include "detection/detection_engine.h"
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
#include "flow/expect_cache.h"
#include "flow/flow_cache.h"
#include "flow/ha.h"
#include "flow/session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

THREAD_LOCAL bool Active::s_suspend = false;
THREAD_LOCAL Active::ActiveSuspendReason Active::s_suspend_reason = Active::ASP_NONE;

THREAD_LOCAL PacketTracer* snort::s_pkt_trace = nullptr;
THREAD_LOCAL bool FlowCache::pruning_in_progress = false;

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
FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg) { }
FlowCache::~FlowCache() = default;
Flow::Flow() = default;
Flow::~Flow() = default;
DetectionEngine::DetectionEngine() = default;
DetectionEngine::~DetectionEngine() = default;
ExpectCache::~ExpectCache() = default;
unsigned FlowCache::purge() { return 1; }
Flow* FlowCache::find(const FlowKey*) { return nullptr; }
Flow* FlowCache::allocate(const FlowKey*) { return nullptr; }
void FlowCache::push(Flow*) { }
bool FlowCache::prune_one(PruneReason, bool) { return true; }
unsigned FlowCache::delete_flows(unsigned) { return 0; }
unsigned FlowCache::timeout(unsigned, time_t) { return 1; }
size_t FlowCache::uni_flows_size() const { return 0; }
size_t FlowCache::uni_ip_flows_size() const { return 0; }
size_t FlowCache::flows_size() const { return 0; }
void Flow::init(PktType) { }
void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }
void DataBus::publish(unsigned, unsigned, const uint8_t*, unsigned, Flow*) { }
void DataBus::publish(unsigned, unsigned, Packet*, Flow*) { }
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
void FlowCache::unlink_uni(Flow*) { }
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
}

namespace snort
{
namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
}

bool FlowKey::init(
    const SnortConfig*,
    PktType, IpProtocol,
    const SfIp*, uint16_t,
    const SfIp*, uint16_t,
    uint16_t, uint32_t,
    uint32_t, int16_t, int16_t)
{
   return true;
}

bool FlowKey::init(
    const SnortConfig*,
    PktType, IpProtocol,
    const SfIp*, uint16_t,
    const SfIp*, uint16_t,
    uint16_t, uint32_t, const DAQ_PktHdr_t&)
{
   return true;
}

bool FlowKey::init(
    const SnortConfig*,
    PktType, IpProtocol,
    const SfIp*, const SfIp*,
    uint32_t, uint16_t,
    uint32_t, uint32_t, int16_t,
    int16_t)
{
    return true;
}

bool FlowKey::init(
    const SnortConfig*,
    PktType, IpProtocol,
    const SfIp*, const SfIp*,
    uint32_t, uint16_t,
    uint32_t, const DAQ_PktHdr_t&)
{
    return true;
}

void Stream::stop_inspection(Flow*, Packet*, char, int32_t, int) { }

int ExpectCache::add_flow(const Packet*,
    PktType, IpProtocol,
    const SfIp*, uint16_t,
    const SfIp*, uint16_t,
    char, FlowData*, SnortProtocolId, bool, bool, bool, bool)
{
    return 1;
}

bool FlowCache::release(Flow*, PruneReason, bool) { return true; }

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
