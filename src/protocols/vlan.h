/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#ifndef PROTOCOLS_VLAN_H
#define PROTOCOLS_VLAN_H

namespace vlan
{

struct VlanTagHdr
{
    uint16_t vth_pri_cfi_vlan;
    uint16_t vth_proto;  /* protocol field... */
};


static inline uint16_t vth_priority(const VlanTagHdr* vh)
{
    return (ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13;
}

static inline uint16_t vth_cfi(const VlanTagHdr* vh)
{
    return (ntohs((vh)->vth_pri_cfi_vlan) & 0x1000) >> 12;
}

static inline uint16_t vth_vlan(const VlanTagHdr* vh)
{
    return ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF;
}

} // namespace vlan

#endif

