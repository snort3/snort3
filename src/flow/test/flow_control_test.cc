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

// flow_control_test.cc author Shivakrishna Mulka <smulka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_common.h>

// Preload FlowControl dependencies before redefining private below.
#include <cstdint>
#include <fstream>
#include <vector>

#include "flow/flow_config.h"
#include "flow/flow_cache.h"
#include "framework/counts.h"
#include "framework/decode_data.h"
#include "framework/inspector.h"

#define private public
#include "flow/flow_control.h"
#undef private

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
#include "stream/base/stream_module.h"
#include "stream/stream.h"
#include "utils/util.h"
#include "flow/expect_cache.h"
#include "flow/ha.h"
#include "flow/session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "flow_stubs.h"

#include "trace/trace.h"

using namespace snort;

namespace snort
{
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}
DataBus::DataBus() = default;
DataBus::~DataBus() = default;
}

NetworkPolicy::NetworkPolicy(PolicyId id, PolicyId default_ips_id)
    : file_policy(nullptr), policy_id(id), default_ips_policy_id(default_ips_id)
{ }

NetworkPolicy::~NetworkPolicy() = default;

InspectionPolicy::InspectionPolicy(PolicyId id) : policy_id(id) { }
InspectionPolicy::~InspectionPolicy() = default;

IpsPolicy::IpsPolicy(PolicyId id)
    : policy_id(id), policy_mode(POLICY_MODE__MAX), enable_builtin_rules(false), var_id(0),
      var_table(nullptr), ip_vartable(nullptr), portVarTable(nullptr), nonamePortVarTable(nullptr),
      obfuscate_pii(false)
{ }

IpsPolicy::~IpsPolicy() = default;


void Active::drop_packet(snort::Packet const*, bool) { }
void Active::suspend(ActiveSuspendReason) { }
void Active::resume() { }
void Active::set_drop_reason(char const*) { }
FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg) { }
FlowCache::~FlowCache() = default;
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;
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
unsigned SnortConfig::get_reload_id() { return 0; }
void FlowCache::unlink_uni(Flow*) { }
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
THREAD_LOCAL BaseStats stream_base_stats = {};

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

TEST_GROUP(policy_persistence)
{
    FlowControl* flow_control = nullptr;
    NetworkPolicy* network_policy = nullptr;
    InspectionPolicy* inspection_policy = nullptr;
    IpsPolicy* ips_policy = nullptr;

    void setup() override
    {
        FlowCacheConfig fcg;
        flow_control = new FlowControl(fcg);
        flow_control->init_exp(1);

        network_policy = new NetworkPolicy(3);
        inspection_policy = new InspectionPolicy(5);
        ips_policy = new IpsPolicy(7);

        snort::test_network_policy = network_policy;
        snort::test_inspection_policy = inspection_policy;
        snort::test_ips_policy = ips_policy;
        snort::test_get_inspection_policy_calls = 0;
        snort::test_get_ips_policy_calls = 0;
    }

    void teardown() override
    {
        snort::test_network_policy = nullptr;
        snort::test_inspection_policy = nullptr;
        snort::test_ips_policy = nullptr;

        delete ips_policy;
        delete inspection_policy;
        delete network_policy;
        delete flow_control;
    }
};

TEST(policy_persistence, new_flow_saves_selected_policy_ids)
{
    Flow flow;
    Packet packet(false);
    DAQ_PktHdr_t pkth = { };
    packet.pkth = &pkth;

    UNSIGNED_LONGS_EQUAL(1, flow_control->process(&flow, &packet, false));
    UNSIGNED_LONGS_EQUAL(network_policy->policy_id, flow.network_policy_id);
    UNSIGNED_LONGS_EQUAL(inspection_policy->policy_id, flow.inspection_policy_id);
    UNSIGNED_LONGS_EQUAL(ips_policy->policy_id, flow.ips_policy_id);
    UNSIGNED_LONGS_EQUAL(1, snort::test_get_inspection_policy_calls);
    UNSIGNED_LONGS_EQUAL(1, snort::test_get_ips_policy_calls);
}

TEST(policy_persistence, new_default_flow_skips_redundant_policy_persistence)
{
    network_policy->policy_id = 0;

    Flow flow;
    Packet packet(false);
    DAQ_PktHdr_t pkth = { };
    packet.pkth = &pkth;

    UNSIGNED_LONGS_EQUAL(1, flow_control->process(&flow, &packet, false));
    UNSIGNED_LONGS_EQUAL(0, flow.network_policy_id);
    UNSIGNED_LONGS_EQUAL(0, flow.inspection_policy_id);
    UNSIGNED_LONGS_EQUAL(0, flow.ips_policy_id);
    UNSIGNED_LONGS_EQUAL(0, snort::test_get_inspection_policy_calls);
    UNSIGNED_LONGS_EQUAL(0, snort::test_get_ips_policy_calls);
}

TEST(policy_persistence, reload_refreshes_selected_policy_ids)
{
    Flow flow;
    flow.flow_state = Flow::FlowState::ALLOW;
    flow.reload_id = 1;
    flow.network_policy_id = 11;
    flow.inspection_policy_id = 13;
    flow.ips_policy_id = 17;

    Packet packet(false);
    DAQ_PktHdr_t pkth = { };
    packet.pkth = &pkth;

    UNSIGNED_LONGS_EQUAL(0, flow_control->process(&flow, &packet, false));
    UNSIGNED_LONGS_EQUAL(network_policy->policy_id, flow.network_policy_id);
    UNSIGNED_LONGS_EQUAL(inspection_policy->policy_id, flow.inspection_policy_id);
    UNSIGNED_LONGS_EQUAL(ips_policy->policy_id, flow.ips_policy_id);
    UNSIGNED_LONGS_EQUAL(1, snort::test_get_inspection_policy_calls);
    UNSIGNED_LONGS_EQUAL(1, snort::test_get_ips_policy_calls);
}

TEST_GROUP(stale_flow) { };

TEST(stale_flow, stale_flow)
{
    Packet* p = new Packet(false);
    Flow* flow = new Flow;
    FlowCacheConfig fcg;
    FlowCache *cache = new FlowCache(fcg);
    FlowControl *flow_control = new FlowControl(fcg);
    DAQ_PktHdr_t dh = { };

    dh.flags = DAQ_PKT_FLAG_NEW_FLOW;
    p->pkth = &dh;
    CHECK(flow_control->stale_flow_cleanup(cache, flow, p) == nullptr);

    dh.flags &= ~DAQ_PKT_FLAG_NEW_FLOW;
    CHECK(flow_control->stale_flow_cleanup(cache, flow, p) == flow);

    p->pkth = nullptr;
    delete flow;
    delete p;
    delete flow_control;
    delete cache;
}

// A UDP tunnel packet must not attach to a Flow
// created by bare traffic on the same inner tuple, and vice versa
//
// The mismatch causes it to be treated as stale and the flow is released.
TEST(stale_flow, tunnel_bare_mismatch)
{
    Packet* p = new Packet(false);
    Flow* flow = new Flow;
    FlowCacheConfig fcg;
    FlowCache* cache = new FlowCache(fcg);
    FlowControl* flow_control = new FlowControl(fcg);
    DAQ_PktHdr_t dh = { };

    dh.flags = 0;
    p->pkth = &dh;

    // Bare flow, tunneled packet -> stale
    snort::udp::UDPHdr udph = { };
    p->ptrs.udph = &udph;
    p->proto_bits = PROTO_BIT__UDP_TUNNELED;
    flow->flags.udp_tunneled = false;
    CHECK(flow_control->stale_flow_cleanup(cache, flow, p) == nullptr);

    // Tunneled flow, bare packet -> stale
    p->flow = nullptr;
    p->proto_bits = 0;
    p->ptrs.udph = nullptr;
    flow->flags.udp_tunneled = true;
    CHECK(flow_control->stale_flow_cleanup(cache, flow, p) == nullptr);

    // Tunneled flow, tunneled packet -> attach
    p->proto_bits = PROTO_BIT__UDP_TUNNELED;
    p->ptrs.udph = &udph;
    flow->flags.udp_tunneled = true;
    CHECK(flow_control->stale_flow_cleanup(cache, flow, p) == flow);

    p->pkth = nullptr;
    p->ptrs.udph = nullptr;
    delete flow;
    delete p;
    delete flow_control;
    delete cache;
}

TEST_GROUP(move_to_allowlist) { };

static bool try_move_to_allowlist(FlowControl* flow_control, PktType type)
{
    Flow* flow = new Flow;
    FlowKey key = { };
    key.pkt_type = type;
    flow->key = &key;

    bool moved = flow_control->move_to_allowlist(flow);

    flow->key = nullptr;
    delete flow;
    return moved;
}

// Only TCP flows are admitted to the allowlist LRU. UDP (and other protocols)
// are rejected so they keep honoring the idle timeout
TEST(move_to_allowlist, tcp_admitted_udp_rejected)
{
    FlowCacheConfig fcg;
    FlowControl* flow_control = new FlowControl(fcg);

    CHECK(try_move_to_allowlist(flow_control, PktType::TCP) == true);
    CHECK(try_move_to_allowlist(flow_control, PktType::UDP) == false);
    CHECK(try_move_to_allowlist(flow_control, PktType::ICMP) == false);

    delete flow_control;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
