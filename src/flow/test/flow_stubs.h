//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// flow_stubs.h author Ron Dempster <rdempste@cisco.com>

#ifndef FLOW_STUBS_H
#define FLOW_STUBS_H

#include <cstdlib>

#include "framework/data_bus.h"
#include "log/messages.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/plugin_manager.h"
#include "managers/inspector_manager.h"
#include "packet_io/packet_tracer.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "stream/stream_log.h"
#include "trace/trace.h"

namespace snort
{
void ErrorMessage(const char*,...) { }
void LogMessage(const char*,...) { }
[[noreturn]] void FatalError(const char*, ...) { std::abort(); }

void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }
void DataBus::publish(unsigned, unsigned, const uint8_t*, unsigned, Flow*) { }
void DataBus::publish(unsigned, unsigned, Packet*, Flow*) { }

void InspectorManager::thread_drain_pending_tterm_if_pending(const Inspector*) { }

Packet::Packet(bool)
{
    ip_proto_next = IpProtocol::PROTO_NOT_SET;
    packet_flags = PKT_FROM_CLIENT;
}
Packet::~Packet()  = default;
uint32_t Packet::get_flow_geneve_vni() const { return 0; }

THREAD_LOCAL PacketTracer* PacketTracer::s_pkt_trace = nullptr;

PacketTracer::~PacketTracer() = default;
void PacketTracer::log(const char*, ...) { }
void PacketTracer::daq_log(const char*, ...) { }
void PacketTracer::open_file() { }
void PacketTracer::dump_to_daq(Packet*) { }
void PacketTracer::reset(bool) { }
void PacketTracer::pause() { }
void PacketTracer::unpause() { }
bool PacketTracer::is_paused() { return true; }
bool PacketTracer::is_active() { return false; }
bool PacketTracer::is_daq_activated() { return false; }
uint64_t PacketTracer::get_time() { return 0; }

THREAD_LOCAL const snort::Trace* stream_tcp_trace = nullptr;
THREAD_LOCAL bool stream_tcp_trace_enabled = false;
} // namespace snort

void stream_daq_log_start() { }
void stream_daq_log_end(snort::Packet*) { }
void stream_log(const snort::Packet*, const char*, ...) { }
void flow_log(const char*, ...) { }
void StreamLog::add_ip_header_info(const snort::Packet&, bool) { }
void StreamLog::add_eth_header_info(const snort::Packet&) { }
void StreamLog::add_packet_type_info(const snort::Packet&) { }
void StreamLog::add_tunnel_info(const snort::Packet&) { }

namespace snort
{
namespace layer
{
const vlan::VlanTagHdr* get_vlan_layer(const Packet* const) { return nullptr; }
}

void Stream::drop_traffic(const Packet*, char) { }
bool Stream::blocked_flow(Packet*) { return true; }
void Stream::stop_inspection(Flow*, Packet*, char, int32_t, int) { }

static NetworkPolicy* test_network_policy = nullptr;
static InspectionPolicy* test_inspection_policy = nullptr;
static IpsPolicy* test_ips_policy = nullptr;
static unsigned test_get_inspection_policy_calls = 0;
static unsigned test_get_ips_policy_calls = 0;

NetworkPolicy* get_network_policy() { return test_network_policy; }
InspectionPolicy* get_inspection_policy()
{
    ++test_get_inspection_policy_calls;
    return test_inspection_policy;
}
IpsPolicy* get_ips_policy()
{
    ++test_get_ips_policy_calls;
    return test_ips_policy;
}
void set_network_policy(NetworkPolicy* p) { test_network_policy = p; }
void set_inspection_policy(InspectionPolicy* p) { test_inspection_policy = p; }
void set_ips_policy(IpsPolicy* p) { test_ips_policy = p; }
}

void set_network_policy(unsigned) { }
void set_inspection_policy(unsigned) { }
void set_ips_policy(const snort::SnortConfig*, unsigned) { }
void select_default_policy(const _daq_pkt_hdr&, const snort::SnortConfig*) { }

PluginPtr PluginManager::get_plugin(const char*) { return nullptr; }

#endif
