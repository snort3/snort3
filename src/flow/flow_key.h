//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

// FlowKey is used to store Flows in the caches.  the data members are
// sequenced to avoid void space.

#include <cstdint>

#include "framework/decode_data.h"
#include "utils/cpp_macros.h"

struct HashFnc;

namespace snort
{
struct SfIp;

PADDING_GUARD_BEGIN
struct SO_PUBLIC FlowKey
{
    uint32_t   ip_l[4]; /* Low IP */
    uint32_t   ip_h[4]; /* High IP */
    uint32_t   mplsLabel;
    uint16_t   port_l;  /* Low Port - 0 if ICMP */
    uint16_t   port_h;  /* High Port - 0 if ICMP */
    uint16_t   vlan_tag;
    uint16_t   addressSpaceId;
    uint8_t    ip_protocol;
    PktType    pkt_type;
    uint8_t    version;
    uint8_t    padding;

    /* The init() functions return true if the key IP/port fields were actively
        normalized, reversing the source and destination addresses internally.
        The IP-only init() will always return false as we will not reorder its
        addresses at this time. */
    bool init(
        PktType, IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        uint16_t vlanId, uint32_t mplsId, uint16_t addrSpaceId);

    bool init(
        PktType, IpProtocol,
        const snort::SfIp *srcIP, const snort::SfIp *dstIP,
        uint32_t id, uint16_t vlanId,
        uint32_t mplsId, uint16_t addrSpaceId);

    void init_mpls(uint32_t);
    void init_vlan(uint16_t);
    void init_address_space(uint16_t);

    // XXX If this data structure changes size, compare must be updated!
    static uint32_t hash(HashFnc*, const unsigned char* d, int);
    static int compare(const void* s1, const void* s2, size_t);

private:
    bool init4(
        IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        uint32_t mplsId, bool order = true);

    bool init6(
        IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        uint32_t mplsId, bool order = true);
};
PADDING_GUARD_END

}

#endif

