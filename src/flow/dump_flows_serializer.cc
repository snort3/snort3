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
    dfd.flow_id = flow.flow_id;
    
    if ( flow.flags.key_is_reversed )
    {
        dfd.client_ip.set(flow.key->ip_h);
        dfd.server_ip.set(flow.key->ip_l);
        dfd.client_port = flow.key->port_h;
        dfd.server_port = flow.key->port_l;
    }
    else
    {
        dfd.client_ip.set(flow.key->ip_l);
        dfd.server_ip.set(flow.key->ip_h);
        dfd.client_port = flow.key->port_l;
        dfd.server_port = flow.key->port_h;
    }
     
    dfd.instance_number = get_relative_instance_number();
    dfd.address_space_id = flow.key->addressSpaceId;
    dfd.pkt_type = static_cast<uint8_t>(flow.key->pkt_type);
    if ( flow.key->pkt_type == PktType::TCP && flow.session )
    {
        TcpSession* tcp_session = static_cast<TcpSession*>(flow.session);
        dfd.tcp_client_state = static_cast<uint8_t>(tcp_session->client.get_tcp_state());
        dfd.tcp_server_state = static_cast<uint8_t>(tcp_session->server.get_tcp_state());
    }
    else
    {
        dfd.tcp_client_state = static_cast<uint8_t>(TcpStreamTracker::TCP_MAX_STATES);
        dfd.tcp_server_state = static_cast<uint8_t>(TcpStreamTracker::TCP_MAX_STATES);
    }
        
    dfd.client_pkts = flow.flowstats.client_pkts;
    dfd.server_pkts = flow.flowstats.server_pkts;
    dfd.client_bytes = flow.flowstats.client_bytes;
    dfd.server_bytes = flow.flowstats.server_bytes;
    
    dfd.idle_time = now.tv_sec - flow.last_data_seen;
    dfd.up_time = now.tv_sec - flow.flowstats.start_time.tv_sec;
    dfd.remaining_time = (flow.last_data_seen + flow.idle_timeout) - now.tv_sec;
    if ( flow.is_hard_expiration() )
         dfd.expiration_time = abs((int)(flow.expire_time - now.tv_sec));
    else
         dfd.expiration_time = abs(dfd.remaining_time);

    dfd.allowed_on_excess = flow.flags.allowed_on_excess;
    dfd.in_allowlist = flow.flags.in_allowlist;
}

void DumpFlowsSerializer::write (std::fstream& stream) const
{
    stream.write(reinterpret_cast<const char*>(&dfd), sizeof(DumpFlowsDescriptor));
}
