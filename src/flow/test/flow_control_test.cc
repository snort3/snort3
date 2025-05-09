//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
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

#include "flow_stubs.h"

using namespace snort;

void Active::drop_packet(snort::Packet const*, bool) { }
void Active::suspend(ActiveSuspendReason) { }
void Active::resume() { }
void Active::set_drop_reason(char const*) { }
FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg) { }
FlowCache::~FlowCache() = default;
Flow::~Flow() = default;
DetectionEngine::DetectionEngine() { context = nullptr; }
DetectionEngine::~DetectionEngine() = default;
unsigned FlowCache::purge() { return 1; }
unsigned FlowCache::get_flows_allocated() const { return 0; }
Flow* FlowCache::find(const FlowKey*) { return nullptr; }
Flow* FlowCache::allocate(const FlowKey*) { return nullptr; }
void FlowCache::push(Flow*) { }
bool FlowCache::prune_one(PruneReason, bool, uint8_t) { return true; }
unsigned FlowCache::prune_multiple(PruneReason , bool) { return 0; }
unsigned FlowCache::delete_flows(unsigned) { return 0; }
unsigned FlowCache::timeout(unsigned, time_t) { return 1; }
size_t FlowCache::uni_flows_size() const { return 0; }
size_t FlowCache::uni_ip_flows_size() const { return 0; }
size_t FlowCache::flows_size() const { return 0; }
void Flow::init(PktType) { }
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
void FlowCache::unlink_uni(Flow*) { }
bool FlowCache::dump_flows(std::fstream&, unsigned, const FilterFlowCriteria&, bool, uint8_t) const { return false; }
bool FlowCache::dump_flows_summary(FlowsSummary&, const FilterFlowCriteria&) const { return false; }
void FlowCache::output_flow(std::fstream&, const Flow&, const struct timeval& ) const { }
bool FlowCache::filter_flows(const Flow&, const FilterFlowCriteria&) const { return true; };
void Flow::set_client_initiate(Packet*) { }
void Flow::set_direction(Packet*) { }
void Flow::set_mpls_layer_per_dir(Packet*) { }
void DetectionEngine::disable_all(Packet*) { }
ExpectCache::ExpectCache(uint32_t) { }
ExpectCache::~ExpectCache() = default;
bool ExpectCache::check(Packet*, Flow*) { return true; }
Flow* HighAvailabilityManager::import(Packet&, FlowKey&) { return nullptr; }
bool FlowCache::move_to_allowlist(snort::Flow*) { return true; }
uint64_t FlowCache::get_lru_flow_count(uint8_t) const { return 0; }
SO_PUBLIC void snort::ts_print(const struct timeval*, char*, bool) { }

namespace snort
{
namespace ip
{
uint32_t IpApi::id() const { return 0; }
}
bool Stream::midstream_allowed(Packet const*, bool)
{ return false; }
}

bool FlowKey::init(
    const SnortConfig*,
    PktType, IpProtocol,
    const SfIp*, uint16_t,
    const SfIp*, uint16_t,
    uint16_t, uint32_t,
    uint32_t,
#ifndef DISABLE_TENANT_ID
    uint32_t,
#endif
    bool, int16_t, int16_t)
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
    uint32_t, const DAQ_PktHdr_t&)
{
    return true;
}

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
