//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// cdp.h author davis mcpherson <davmcphe@cisco.com>

// Represents the CDP (Cisco Discovery Protocol) frame format

#ifndef PROTOCOLS_CDP_H
#define PROTOCOLS_CDP_H

#include <cstdint>
#include <cstring>

namespace snort
{
namespace cdp
{
#define CDP_HDLC_PROTOCOL_TYPE 0x2000

// CDP data type values
#define RNA_CDP_ADDRESS_TYPE 0x0002
#define RNA_CDP_CAPABILITIES_TYPE 0x0004

#define RNA_CDP_CAPABILITIES_ROUTER 0x0001
#define RNA_CDP_CAPABILITIES_SWITCH 0x000A
#define RNA_CDP_CAPABILITIES_MASK (RNA_CDP_CAPABILITIES_ROUTER | RNA_CDP_CAPABILITIES_SWITCH)

static const uint8_t CDP_DEST[6] = {0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC};

bool is_cdp(const uint8_t mac[6]);

struct RNA_CDP
{
    uint8_t org_code[3];
    uint16_t pid;
    uint8_t version;
    uint8_t ttl;
    uint16_t checksum;
}  __attribute__((__packed__));

struct RNA_CDP_DATA
{
    uint16_t type;
    uint16_t length;
}  __attribute__((__packed__));

bool is_cdp(const uint8_t mac[6])
{ return (memcmp(mac, CDP_DEST, sizeof(CDP_DEST)) == 0); }

} // namespace cdp
} // namespace snort

#endif
