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

// socks_splitter.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "socks_splitter.h"

#include <iomanip>
#include <sstream>

#include "flow/flow.h"
#include "protocols/packet.h"
#include "socks_flow_data.h"

using namespace snort;


SocksSplitter::SocksSplitter(bool c2s) : StreamSplitter(c2s)
{ }

StreamSplitter::Status SocksSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    if ( !data or len == 0 )
        return SEARCH;

    const Flow* flow = p->flow;
    const SocksFlowData* flow_data = static_cast<const SocksFlowData*>(
        flow->get_flow_data(SocksFlowData::get_inspector_id()));

    // After tunnel is established or handoff completed, STOP scanning
    // to allow wizard to take over for tunneled protocol detection
    if ( flow_data and (flow_data->get_state() == SOCKS_STATE_ESTABLISHED or
                        flow_data->is_handoff_completed()) )
    {
        return STOP;
    }

    bool from_client = (flags & PKT_FROM_CLIENT) != 0;
    uint32_t msg_len = 0;
    SocksState state = flow_data ? flow_data->get_state() : SOCKS_STATE_INIT;

    // ERROR state: flush data to allow error handling at higher layers
    if ( state == SOCKS_STATE_ERROR )
    {
        *fp = len;
        return FLUSH;
    }

    if ( from_client )
        msg_len = parse_client_packet(data, len, state);
    else
        msg_len = parse_server_packet(data, len, state);

    if ( msg_len > 0 and msg_len <= len )
    {
        *fp = msg_len;
        return FLUSH;
    }

    return SEARCH;
}

uint32_t SocksSplitter::parse_client_packet(const uint8_t* data, uint32_t len, SocksState state)
{
    switch (state)
    {
        case SOCKS_STATE_INIT:
        case SOCKS_STATE_V5_AUTH_NEGOTIATION:
            if ( len >= 9 and data[0] == SOCKS4_VERSION )
            {
                uint32_t socks4_len = parse_socks4_request(data, len);
                if ( socks4_len > 0 )
                    return socks4_len;
            }

            if ( len >= 2 and data[0] == SOCKS5_VERSION )
            {
                uint32_t auth_len = parse_auth_negotiation(data, len);
                if ( auth_len > 0 )
                    return auth_len;
            }
            break;

        case SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH:
            return parse_username_password_auth(data, len);

        case SOCKS_STATE_V5_CONNECT_REQUEST:
            return parse_connect_request(data, len);

        case SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE:
            if ( len >= 2 && data[0] == SOCKS5_USERPASS_VERSION )
                return parse_username_password_auth(data, len);

            return parse_auth_negotiation(data, len);

        case SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION:
        {
            // Client sends auth method selection (2 bytes) or may pipeline username/password auth
            uint32_t auth_len = parse_auth_response(data, len);
            if ( auth_len )
                return auth_len;

            return parse_username_password_auth(data, len);
        }

        case SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST:
        {
            // Server may pipeline auth negotiation + connect request before client responds.
            // Client still sends auth response first (exactly 2 bytes), then connect response.
            // Check for combined auth+connect: 05 XX 05 YY 00 ... (auth response followed by connect response)
            if ( len >= 4 and data[0] == SOCKS5_VERSION and data[2] == SOCKS5_VERSION )
            {
                // Combined PDU detected - flush auth response (2 bytes), inspector will rescan
                return 2;
            }

            // Standalone auth response (exactly 2 bytes)
            if ( len == 2 )
            {
                uint32_t auth_len = parse_auth_response(data, len);
                if ( auth_len )
                    return auth_len;
            }

            return parse_connect_response(data, len);
        }

        case SOCKS_STATE_V5_BIND_REVERSE_CONNECT_RESPONSE:
            return parse_connect_request(data, len);

        // ESTABLISHED and ERROR states are now handled at the top of scan()
        // by returning STOP, so we should never reach here for those states
        case SOCKS_STATE_ESTABLISHED:
        case SOCKS_STATE_ERROR:
            return 0;  // Should not reach here

        default:
            break;
    }

    return 0;
}

uint32_t SocksSplitter::parse_server_packet(const uint8_t* data, uint32_t len, SocksState state)
{
    switch (state)
    {
        case SOCKS_STATE_INIT:
        case SOCKS_STATE_V5_AUTH_NEGOTIATION:
            return parse_auth_response(data, len);

        case SOCKS_STATE_V4_CONNECT_RESPONSE:
            return parse_socks4_response(data, len);

        case SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH:
            return parse_username_password_auth_response(data, len);

        case SOCKS_STATE_V5_CONNECT_REQUEST:
            return parse_connect_response(data, len);

        case SOCKS_STATE_V5_CONNECT_RESPONSE:
            return parse_connect_response(data, len);

        case SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION:
            return parse_auth_response(data, len);

        case SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE:
            return parse_connect_response(data, len);

        case SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST:
            return parse_connect_response(data, len);

        // Terminal states: return full length to flush all remaining data
        case SOCKS_STATE_V5_BIND_REVERSE_CONNECT_RESPONSE:
        case SOCKS_STATE_ESTABLISHED:
        case SOCKS_STATE_ERROR:
            return len;

        default:
            break;
    }
    
    return 0;
}

uint32_t SocksSplitter::parse_auth_negotiation(const uint8_t* data, uint32_t len)
{
    // Format: VER(1) + NMETHODS(1) + METHODS(1-255)
    if ( len < 2 or data[0] != 0x05 )
        return 0;

    uint8_t num_methods = data[1];

    if ( num_methods == 0 )
        return 0;
    
    uint32_t expected_len = 2 + num_methods;

    if ( len >= expected_len )
        return expected_len;
    
    return 0;
}

uint32_t SocksSplitter::parse_auth_response(const uint8_t* data, uint32_t len)
{
    if ( len < 2 )
        return 0;

    // SOCKS5 auth response: 05 XX
    if ( data[0] == 0x05 )
    {
        uint8_t auth_method = data[1];

        if ( auth_method != 0x00 and auth_method != 0x02 and auth_method != 0xFF )
            return len;  // Consume entire packet for unsupported auth
        
        return 2;
    }

    // SOCKS4 response: 00 XX ... (8 bytes total)
    if ( data[0] == 0x00 )
    {
        return parse_socks4_response(data, len);
    }

    return 0;
}

uint32_t SocksSplitter::parse_username_password_auth(const uint8_t* data, uint32_t len)
{
    // Format: VER(1) + ULEN(1) + UNAME(1-255) + PLEN(1) + PASSWD(1-255)
    if ( len < 3 or data[0] != SOCKS5_USERPASS_VERSION )
        return 0;

    uint8_t ulen = data[1];
    if ( len < 3 + static_cast<uint32_t>(ulen) )
        return 0;

    uint8_t plen = data[2 + ulen];
    uint32_t required_len = 3 + ulen + plen;

    if ( len >= required_len )
        return required_len;
    
    return 0;
}

uint32_t SocksSplitter::parse_username_password_auth_response(const uint8_t* data, uint32_t len)
{
    // Format: VER(1) + STATUS(1)
    if ( len < 2 or data[0] != SOCKS5_USERPASS_VERSION )
        return 0;

    return 2;
}

uint32_t SocksSplitter::parse_connect_request(const uint8_t* data, uint32_t len)
{
    // Format: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2)
    if ( len < 4 or data[0] != 0x05 )
        return 0;

    return parse_address_port_length(data, len, 3);
}

uint32_t SocksSplitter::parse_connect_response(const uint8_t* data, uint32_t len)
{
    // Format: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(var) + BND.PORT(2)
    if ( len < 4 or data[0] != 0x05 )
        return 0;

    return parse_address_port_length(data, len, 3);
}

uint32_t SocksSplitter::parse_address_port_length(const uint8_t* data, uint32_t len, uint32_t atyp_offset)
{
    if ( len <= atyp_offset )
        return 0;

    uint8_t atyp = data[atyp_offset];
    uint32_t addr_len;

    switch (atyp)
    {
        case 0x01: // IPv4
            addr_len = 4;
            break;
        case 0x03: // Domain name
        {
            if ( len < atyp_offset + 2 )
                return 0;
            // Validate domain length to prevent integer overflow and DoS
            uint8_t domain_len = data[atyp_offset + 1];
            if ( domain_len == 0 or domain_len > 253 )  // RFC 1035 max domain length
                return 0;
            addr_len = 1 + static_cast<uint32_t>(domain_len);  // Explicit cast to prevent overflow
            break;
        }
        case 0x04: // IPv6
            addr_len = 16;
            break;
        default:
            return 0;
    }

    uint32_t required_len = atyp_offset + 1 + addr_len + 2;

    if ( len >= required_len )
        return required_len;
    
    return 0;
}

//-------------------------------------------------------------------------
// SOCKS4 parsing functions
//-------------------------------------------------------------------------

uint32_t SocksSplitter::parse_socks4_request(const uint8_t* data, uint32_t len)
{
    // SOCKS4 request: VER(1) CMD(1) PORT(2) IP(4) USERID(variable) NULL(1)
    // Minimum: 9 bytes
    if ( len < 9 or data[0] != 0x04 )
        return 0;

    // Find NULL terminator for userid (starts at offset 8)
    uint32_t offset = 8;
    uint32_t userid_start = offset;
    while ( offset < len and data[offset] != 0 )
    {
        offset++;
            if ( offset - userid_start > 255 )
            return 0;
    }

    if ( offset >= len )
        return 0;  // Need more data

    offset++;  // Skip NULL terminator

    // Check for SOCKS4a (IP is 0.0.0.x where x != 0)
    uint32_t ip = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    bool is_socks4a = (ip & 0xFFFFFF00) == 0 and (ip & 0xFF) != 0;

    if ( is_socks4a )
    {
        // SOCKS4a: domain name follows, also NULL-terminated
        uint32_t domain_start = offset;
        while ( offset < len and data[offset] != 0 )
        {
            offset++;
            // Prevent DoS: domain should be reasonable length (max 253 per RFC 1035)
            if ( offset - domain_start > 253 )
                return 0;
        }

        if ( offset >= len )
            return 0;  // Need more data

        offset++;  // Skip domain NULL terminator
    }

    return offset;
}

uint32_t SocksSplitter::parse_socks4_response(const uint8_t* data, uint32_t len)
{
    // SOCKS4 response: VER(1) STATUS(1) PORT(2) IP(4)
    // Total: 8 bytes
    // Note: VER is 0x00, not 0x04!
    if ( len < 8 )
        return 0;

    if ( data[0] != 0x00 )
        return 0;

    return 8;
}
