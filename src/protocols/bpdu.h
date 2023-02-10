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
// bpdu.h author Michael Matirko <mmatirko@cisco.com>

// Represents the BPDU (bridge protocol data unit) payload used for Spanning Tree Protocol

#ifndef PROTOCOLS_BPDU_H
#define PROTOCOLS_BPDU_H

namespace snort
{
namespace bpdu
{

#define BPDU_TYPE_TOPCHANGE  0x80    // Topology change type BPDU

static const uint8_t BPDU_DEST[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};

bool isBPDU(const uint8_t mac[6]);

struct BPDUData
{
    uint16_t id;
    uint8_t version;
    uint8_t type;
} __attribute__((__packed__));


bool isBPDU(const uint8_t mac[6])
{
    return (memcmp(mac, BPDU_DEST, sizeof(BPDU_DEST)) == 0);
}

} // namespace bpdu
} // namespace snort

#endif
