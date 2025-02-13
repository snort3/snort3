//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "log/messages.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "packet_io/packet_tracer.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "stream/stream.h"

namespace snort
{
void ErrorMessage(const char*,...) { }
void LogMessage(const char*,...) { }

void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }
void DataBus::publish(unsigned, unsigned, const uint8_t*, unsigned, Flow*) { }
void DataBus::publish(unsigned, unsigned, Packet*, Flow*) { }

Packet::Packet(bool)
{
    memset((char*) this , 0, sizeof(*this));
    ip_proto_next = IpProtocol::PROTO_NOT_SET;
    packet_flags = PKT_FROM_CLIENT;
}
Packet::~Packet()  = default;
uint32_t Packet::get_flow_geneve_vni() const { return 0; }

THREAD_LOCAL PacketTracer* PacketTracer::s_pkt_trace = nullptr;

PacketTracer::~PacketTracer() = default;
void PacketTracer::log(const char*, ...) { }
void PacketTracer::open_file() { }
void PacketTracer::dump_to_daq(Packet*) { }
void PacketTracer::reset(bool) { }
void PacketTracer::pause() { }
void PacketTracer::unpause() { }

namespace layer
{
const vlan::VlanTagHdr* get_vlan_layer(const Packet* const) { return nullptr; }
}

void Stream::drop_traffic(const Packet*, char) { }
bool Stream::blocked_flow(Packet*) { return true; }
void Stream::stop_inspection(Flow*, Packet*, char, int32_t, int) { }

NetworkPolicy* get_network_policy() { return nullptr; }
InspectionPolicy* get_inspection_policy() { return nullptr; }
IpsPolicy* get_ips_policy() { return nullptr; }
void set_network_policy(NetworkPolicy*) { }
void set_inspection_policy(InspectionPolicy*) { }
void set_ips_policy(IpsPolicy*) { }
unsigned SnortConfig::get_thread_reload_id() { return 0; }
}

void set_network_policy(unsigned) { }
void set_inspection_policy(unsigned) { }
void set_ips_policy(const snort::SnortConfig*, unsigned) { }
void select_default_policy(const _daq_pkt_hdr&, const snort::SnortConfig*) { }

#endif
