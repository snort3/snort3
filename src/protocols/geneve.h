//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// geneve.h author Raman S. Krishnan <ramanks@cisco.com>

#ifndef PROTOCOLS_GENEVE_H
#define PROTOCOLS_GENEVE_H

namespace snort
{
namespace geneve
{
struct GeneveHdr
{
    uint8_t g_vl;
    uint8_t g_flags;
    uint16_t g_proto;
    uint8_t g_vni[ 3 ];
    uint8_t g_rsvd;

    uint16_t hlen() const
    { return (sizeof(GeneveHdr) + ((g_vl & 0x3f) * 4)); }

    uint8_t version() const
    { return (g_vl >> 6); }

    uint8_t optlen() const
    { return ((g_vl & 0x3f) * 4); }

    bool is_set(uint16_t which) const
    { return (g_flags & which); }

    uint16_t proto() const
    { return (ntohs(g_proto)); }

    uint32_t vni() const
    { return ((g_vni[0] << 16) | (g_vni[1] << 8) | g_vni[2]); }
};

} // namespace geneve
} // namespace snort

#endif
