//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// socks_curse.h - author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_CURSE_H
#define SOCKS_CURSE_H

#include <cstdint>

enum SocksCurseState
{
    SOCKS_STATE__VERSION = 0,
    SOCKS_STATE__V4_COMMAND,
    SOCKS_STATE__V4_PORT_MSB,
    SOCKS_STATE__V4_PORT_LSB,
    SOCKS_STATE__V4_IP_1,
    SOCKS_STATE__V4_IP_2,
    SOCKS_STATE__V4_IP_3,
    SOCKS_STATE__V4_IP_4,
    SOCKS_STATE__V4_USERID,
    SOCKS_STATE__V4A_DOMAIN,
    SOCKS_STATE__V5_NMETHODS,
    SOCKS_STATE__V5_METHODS,
    // 4-byte request header confirmation states (no common methods case)
    // Confirms SOCKS5 by validating: VER(0x05) CMD(0x01-0x03) RSV(0x00) ATYP(0x01/0x03/0x04)
    SOCKS_STATE__V5_REQ_VER,
    SOCKS_STATE__V5_REQ_CMD,
    SOCKS_STATE__V5_REQ_RSV,
    SOCKS_STATE__V5_REQ_ATYP,
    SOCKS_STATE__FOUND,
    SOCKS_STATE__NOT_FOUND
};

struct SocksTracker
{
    SocksCurseState state = SOCKS_STATE__VERSION;
    uint8_t version = 0;
    uint8_t command = 0;
    uint8_t nmethods = 0;
    uint8_t methods_remaining = 0;
    uint16_t port = 0;
    uint32_t ip_addr = 0;
    uint8_t userid_length = 0;
    uint8_t domain_length = 0;
    bool is_socks4a = false;
    // Method tracking for false positive detection
    uint64_t methods_seen[4] = {};  // 256-bit bitmask (4 x 64 bits)
    uint8_t unique_methods = 0;     // Count of unique methods seen
    bool saw_duplicate = false;     // True if any method repeated
    bool has_common = false;        // True if saw 0x00, 0x01, or 0x02
    uint8_t v5_confirm_budget = 0;  // Limits bytes spent in V5_REQ_* confirm states
};

#endif
