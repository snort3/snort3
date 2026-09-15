//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// dump_flows_serializer.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dump_flows_serializer.h"

#include "stream/base/stream_module.h"
#include "stream/tcp/tcp_session.h"
#include "stream/tcp/tcp_trace.h"

#include "flow.h"
#include "flow_key.h"

using namespace snort;

void DumpFlowsSerializer::initialize(const Flow& flow, const struct timeval& now)
{
    dfd.bin.flow_id = flow.flow_id;

    if ( flow.flags.key_is_reversed )
    {
        dfd.bin.client_ip.set(flow.key->ip_h);
        dfd.bin.server_ip.set(flow.key->ip_l);
        dfd.bin.client_port = flow.key->port_h;
        dfd.bin.server_port = flow.key->port_l;
    }
    else
    {
        dfd.bin.client_ip.set(flow.key->ip_l);
        dfd.bin.server_ip.set(flow.key->ip_h);
        dfd.bin.client_port = flow.key->port_l;
        dfd.bin.server_port = flow.key->port_h;
    }

    dfd.bin.instance_number = get_relative_instance_number();
    dfd.bin.address_space_id = flow.key->addressSpaceId;
    dfd.bin.pkt_type = static_cast<uint8_t>(flow.key->pkt_type);
    if ( flow.key->pkt_type == PktType::TCP && flow.session )
    {
        TcpSession* tcp_session = static_cast<TcpSession*>(flow.session);
        dfd.bin.tcp_client_state = static_cast<uint8_t>(tcp_session->client.get_tcp_state());
        dfd.bin.tcp_server_state = static_cast<uint8_t>(tcp_session->server.get_tcp_state());
    }
    else
    {
        dfd.bin.tcp_client_state = static_cast<uint8_t>(TcpStreamTracker::TCP_MAX_STATES);
        dfd.bin.tcp_server_state = static_cast<uint8_t>(TcpStreamTracker::TCP_MAX_STATES);
    }

    dfd.bin.client_pkts = flow.flowstats.client_pkts;
    dfd.bin.server_pkts = flow.flowstats.server_pkts;
    dfd.bin.client_bytes = flow.flowstats.client_bytes;
    dfd.bin.server_bytes = flow.flowstats.server_bytes;

    dfd.bin.idle_time = now.tv_sec - flow.last_data_seen;
    dfd.bin.up_time = now.tv_sec - flow.flowstats.start_time.tv_sec;
    dfd.bin.remaining_time = (flow.last_data_seen + flow.idle_timeout) - now.tv_sec;
    if ( flow.is_hard_expiration() )
         dfd.bin.expiration_time = abs((int)(flow.expire_time - now.tv_sec));
    else
         dfd.bin.expiration_time = abs(dfd.bin.remaining_time);

    dfd.bin.allowed_on_excess = flow.flags.allowed_on_excess;
    dfd.bin.in_allowlist = flow.flags.in_allowlist;

    dfd.bin.flow_mem = flow.get_mem_usage();
    dfd.bin.peak_flow_mem = flow.get_peak_mem_usage();
}

void DumpFlowsSerializer::write (std::fstream& stream) const
{
    stream.write(reinterpret_cast<const char*>(&dfd.bin), sizeof(DumpFlowsBinaryDescriptor));
}
