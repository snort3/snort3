//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// vlan.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_VLAN_H
#define PROTOCOLS_VLAN_H

#include <arpa/inet.h>

namespace snort
{
namespace vlan
{
struct VlanTagHdr
{
    uint16_t vth_pri_cfi_vlan;
    uint16_t vth_proto;  /* protocol field... */

    inline uint16_t priority() const
    { return ntohs(vth_pri_cfi_vlan) >> 13; }

    inline uint16_t cfi() const
    { return (ntohs(vth_pri_cfi_vlan) & 0x1000) >> 12; }

    inline uint16_t vid() const
    { return ntohs(vth_pri_cfi_vlan) & 0x0FFF; }

    inline uint16_t proto() const
    { return ntohs(vth_proto); }
};
} // namespace vlan
} // namespace snort

#endif

