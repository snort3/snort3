//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <daq_common.h>

#include "framework/decode_data.h"
#include "hash/hash_key_operations.h"
#include "utils/cpp_macros.h"

namespace snort
{
struct SfIp;
struct SnortConfig;

class FlowHashKeyOps : public HashKeyOperations
{
public:
    FlowHashKeyOps(int rows)
        : HashKeyOperations(rows)
    { }

    unsigned do_hash(const unsigned char* k, int len) override;
    bool key_compare(const void* k1, const void* k2, size_t) override;
};

PADDING_GUARD_BEGIN
struct SO_PUBLIC FlowKey
{
    uint32_t   ip_l[4]; /* Low IP */
    uint32_t   ip_h[4]; /* High IP */
    uint32_t   mplsLabel;
    uint32_t   addressSpaceId;
#ifndef DISABLE_TENANT_ID
    uint32_t   tenant_id; // included by default
#endif
    uint16_t   port_l;  /* Low Port - 0 if ICMP */
    uint16_t   port_h;  /* High Port - 0 if ICMP */
    int16_t    group_l;
    int16_t    group_h;
    uint16_t   vlan_tag;
    uint16_t   padding;
    uint8_t    ip_protocol;
    PktType    pkt_type;
    uint8_t    version;
    struct
    {
        bool group_used : 1;
        uint8_t padding_bits : 7;
    } flags;

    // The init() functions return true if the key IP/port fields were actively
    // normalized, reversing the source and destination addresses internally.
    // The IP-only init() will always return false as we will not reorder its
    // addresses at this time.
    bool init(
        const SnortConfig*, PktType, IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        uint16_t vlanId, uint32_t mplsId, uint32_t addrSpaceId, 
#ifndef DISABLE_TENANT_ID
        uint32_t tid, 
#endif
        bool significant_groups,
        int16_t group_h = DAQ_PKTHDR_UNKNOWN, int16_t group_l = DAQ_PKTHDR_UNKNOWN);

    bool init(
        const SnortConfig*, PktType, IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        uint16_t vlanId, uint32_t mplsId, const DAQ_PktHdr_t&);

    // IP fragment key
    bool init(
        const SnortConfig*, PktType, IpProtocol,
        const snort::SfIp *srcIP, const snort::SfIp *dstIP,
        uint32_t id, uint16_t vlanId, uint32_t mplsId, const DAQ_PktHdr_t&);

    void init_mpls(const SnortConfig*, uint32_t);
    void init_vlan(const SnortConfig*, uint16_t);
    void init_address_space(const SnortConfig*, uint32_t);
    void init_groups(int16_t, int16_t, bool);

    static bool is_equal(const FlowKey* k1, const FlowKey* k2)
    {
        return 0 == memcmp(k1, k2, sizeof(FlowKey));
    }


private:
    bool init4(IpProtocol, const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort, bool order = true);

    bool init6(IpProtocol, const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort, bool order = true);
};
PADDING_GUARD_END

}

#endif

