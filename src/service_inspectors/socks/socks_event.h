//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_event.h - author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_EVENT_H
#define SOCKS_EVENT_H

#include "framework/data_bus.h"
#include "sfip/sf_ip.h"
#include <string>

#include "socks_flow_data.h"

// Event IDs for SOCKS events
struct SocksEventIds { enum : unsigned { SOCKS_TUNNEL_ESTABLISHED, SOCKS_TUNNEL_FAILED, num_ids }; };

const snort::PubKey socks_pub_key { "socks", SocksEventIds::num_ids };

// SOCKS tunnel event published when tunnel is established or fails
// Provides access to target destination for logging/correlation
class SocksTunnelEvent : public snort::DataEvent
{
public:
    SocksTunnelEvent(const SocksFlowData* fd, bool success) : 
        flow_data(fd), tunnel_success(success) { }


    // Target destination information (where client wants to go)
    const std::string& get_target_address() const
    {
        static const std::string empty;
        return flow_data ? flow_data->get_target_address() : empty;
    }

    uint16_t get_target_port() const
    {
        return flow_data ? flow_data->get_target_port() : 0;
    }

    const snort::SfIp* get_target_ip() const
    {
        return flow_data ? flow_data->get_target_ip() : nullptr;
    }

    // SOCKS command type
    SocksCommand get_command() const
    {
        return flow_data ? flow_data->get_command() : SOCKS_CMD_CONNECT;
    }

    // Tunnel establishment status
    bool is_tunnel_successful() const
    {
        return tunnel_success;
    }

    SocksReplyCode get_reply_code() const
    {
        return flow_data ? flow_data->get_last_error() : SOCKS5_REP_SUCCESS;
    }

private:
    const SocksFlowData* flow_data;
    bool tunnel_success;
};

#endif
