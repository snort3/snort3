//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// socks_splitter.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_SPLITTER_H
#define SOCKS_SPLITTER_H

#include "stream/stream_splitter.h"
#include "socks_flow_data.h"

class SocksSplitter : public snort::StreamSplitter
{
public:
    SocksSplitter(bool c2s);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len,
                uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    uint32_t parse_client_packet(const uint8_t* data, uint32_t len, SocksState state);
    uint32_t parse_server_packet(const uint8_t* data, uint32_t len, SocksState state);

    // SOCKS4 parsing
    uint32_t parse_socks4_request(const uint8_t* data, uint32_t len);
    uint32_t parse_socks4_response(const uint8_t* data, uint32_t len);

    // SOCKS5 parsing
    uint32_t parse_auth_negotiation(const uint8_t* data, uint32_t len);
    uint32_t parse_auth_response(const uint8_t* data, uint32_t len);
    uint32_t parse_username_password_auth(const uint8_t* data, uint32_t len);
    uint32_t parse_username_password_auth_response(const uint8_t* data, uint32_t len);
    uint32_t parse_connect_request(const uint8_t* data, uint32_t len);
    uint32_t parse_connect_response(const uint8_t* data, uint32_t len);

    uint32_t parse_address_port_length(const uint8_t* data, uint32_t len, uint32_t atyp_offset);
};

#endif
