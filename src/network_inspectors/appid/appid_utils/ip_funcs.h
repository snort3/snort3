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

// ip_funcs.h author Sourcefire Inc.

#ifndef IP_FUNCS_H
#define IP_FUNCS_H

#include <cstdint>
#include <cstring>

#include "sfip/sf_ip.h"

#include "network_set.h"

#define IPFUNCS_EXCEPT_IP                0x01
#define IPFUNCS_SECONDARY_IP             0x02
#define IPFUNCS_USER_IP                  0x04
#define IPFUNCS_HOSTS_IP                 0x08
#define IPFUNCS_APPLICATION              0x10
#define IPFUNCS_CHECKED                  0x80000000

#ifdef USE_RNA_CONFIG
struct RNAIpAddrSet
{
    uint32_t range_min;
    uint32_t range_max;
    uint32_t addr_flags;
    unsigned netmask;
    uint32_t netmask_mask;
};

RNAIpAddrSet* ParseIpCidr(char*, uint32_t*);

struct RNAIpv6AddrSet
{
    NSIPv6Addr range_min;
    NSIPv6Addr range_max;
    uint32_t addr_flags;
    unsigned netmask;
    NSIPv6Addr netmask_mask;
};

RNAIpv6AddrSet* ParseIpv6Cidr(char*);

inline void copyIpv4ToIpv6Network(ip::snort_in6_addr* keyIp, const uint32_t ip)
{
    keyIp->u6_addr32[0] = keyIp->u6_addr32[1] = 0;
    keyIp->u6_addr16[4] = 0;
    keyIp->u6_addr16[5] = 0xFFFF;
    keyIp->u6_addr32[3] = ip;
}

//these functions are needed since snort does not store IPv4 address in highest 4 bytes
//of 16 byte ip.
inline void copySnortIpToIpv6Network(ip::snort_in6_addr* keyIp, const SfIp* snortIp)
{
    memcpy(keyIp, snortIp->get_ip6_ptr(), sizeof(*keyIp));
}

inline int cmpSnortIpToHostKey(const ip::snort_in6_addr* keyIp, const SfIp* snortIp)
{
    return memcmp(keyIp, snortIp->get_ip6_ptr(), sizeof(*keyIp));
}

#endif

#endif

