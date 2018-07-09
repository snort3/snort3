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

// network_set.h author Sourcefire Inc.

#ifndef NETWORK_SET_H
#define NETWORK_SET_H

#ifdef USE_RNA_CONFIG

#include <cstdio>
#include <unordered_set>

#include "protocols/ipv6.h"
#include "utils/sflsq.h"

// network_set.h author Sourcefire Inc.

#ifndef ULLONG_MAX
#   define ULLONG_MAX   18446744073709551615ULL
#endif

#define BYTE_SWAP_16(x) \
    ((uint16_t)((((uint16_t)(x) & 0xff00) >> 8) | \
    (((uint16_t)(x) & 0x00ff) << 8)))

#define BYTE_SWAP_32(x) \
    ((uint32_t)((((uint32_t)(x) & 0xff000000) >> 24) | \
    (((uint32_t)(x) & 0x00ff0000) >>  8) | \
    (((uint32_t)(x) & 0x0000ff00) <<  8) | \
    (((uint32_t)(x) & 0x000000ff) << 24)))

#define BYTE_SWAP_64(x) \
    ((uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
    (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
    (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
    (((uint64_t)(x) & 0x000000ff00000000ULL) >>  8) | \
    (((uint64_t)(x) & 0x00000000ff000000ULL) <<  8) | \
    (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
    (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
    (((uint64_t)(x) & 0x00000000000000ffULL) << 56)))

#if defined(WORDS_BIGENDIAN)
struct NSIPv6Addr
{
    uint64_t hi = 0;
    uint64_t lo = 0;
};
#else
struct NSIPv6Addr
{
    uint64_t lo = 0;
    uint64_t hi = 0;
};
#endif

//IPv6 address a must be in network order
#define NSIP_IS_ADDR_MULTICAST(a) \
    (IN6_IS_ADDR_MULTICAST(a) \
    || ((IN6_IS_ADDR_V4MAPPED(a) || IN6_IS_ADDR_V4COMPAT(a)) && (((__const uint32_t*)(a))[3] == \
    0xffffffff)))

struct NSNetworkInfo
{
    unsigned id;
    unsigned netmask;
    int ip_not;
    unsigned type;
};

struct Network
{
    NSNetworkInfo info;
    uint32_t range_min;
    uint32_t range_max;
};

struct Network6
{
    NSNetworkInfo info;
    NSIPv6Addr range_min;
    NSIPv6Addr range_max;
};

struct NetworkSet
{
    NetworkSet* next;
    SF_LIST networks;
    std::unordered_set<unsigned> ids;
    Network** pnetwork;
    unsigned count;
    SF_LIST networks6;
    std::unordered_set<unsigned> ids6;
    Network6** pnetwork6;
    unsigned count6;
};

// FIXIT-L - this should be integrated into the snort3 general IP address support library
class NetworkSetManager
{
public:
    static int create(NetworkSet**);
    static int destroy(NetworkSet*);
    static NetworkSet* copy(NetworkSet*);
    static int add_set(NetworkSet* dest_set, NetworkSet* src_set);
    static int add_cidr_block_ex(NetworkSet*, uint32_t ip,
        unsigned cidr_bits, int ip_not, unsigned id, unsigned type);
    static int add_cidr_block6_ex(NetworkSet*, NSIPv6Addr*,
        unsigned cidr_bits, int ip_not, unsigned id, unsigned type);
    static int add_cidr_block(NetworkSet*, uint32_t ip,
        unsigned cidr_bits, int ip_not, unsigned id);
    static int add_cidr_block6(NetworkSet*, NSIPv6Addr*,
        unsigned cidr_bits, int ip_not, unsigned id);
    static int add_network_range_ex(NetworkSet*, uint32_t range_min,
        uint32_t range_max, unsigned cidr_bits, int ip_not, unsigned id, unsigned type);
    static int add_network_range6(NetworkSet*, NSIPv6Addr* range_min,
        NSIPv6Addr* range_max, unsigned cidr_bits, int ip_not, unsigned id, unsigned type);
    static int add_network_range(NetworkSet*, uint32_t range_min,
        uint32_t range_max, unsigned cidr_bits, int ip_not, unsigned id);
    static int add_network_range6(NetworkSet*, NSIPv6Addr* range_min,
        NSIPv6Addr* range_max, unsigned cidr_bits, int ip_not, unsigned id);
    static int add_network_range_only_ipv6(NetworkSet*, int ip_not,
        unsigned id, unsigned type);
    static int reduce(NetworkSet*);
    static int log_network_set(NetworkSet*, const char* prefix, FILE* stream);

    static void pack_ipv4_to_ipv6(NSIPv6Addr* ipv6Addr, uint32_t ipv4Addr)
    {
        ipv6Addr->hi = 0ULL;
        ipv6Addr->lo = (uint64_t)ipv4Addr | 0x0000FFFF00000000ULL;
    }

    static int unpack_ipv4_from_ipv6(const NSIPv6Addr* ipv6Addr, uint32_t* ipv4Addr)
    {
        if (!ipv6Addr->hi)
        {
            uint64_t lo = ipv6Addr->lo & 0xFFFFFFFF00000000ULL;
            if (!lo || lo == 0x0000FFFF00000000ULL)
            {
                *ipv4Addr = (uint32_t)ipv6Addr->lo;
                return 0;
            }
        }
        return -1;
    }

    static void copy_ipv6_address(const NSIPv6Addr* src, NSIPv6Addr* dst)
    {
        dst->hi = src->hi;
        dst->lo = src->lo;
    }

    static int compare_ipv6_address(const NSIPv6Addr* a, const NSIPv6Addr* b)
    {
        if (a->hi < b->hi)
            return -1;
        else if (a->hi > b->hi)
            return 1;
        if (a->lo < b->lo)
            return -1;
        else if (a->lo > b->lo)
            return 1;
        return 0;
    }

#if defined(WORDS_BIGENDIAN)
#define ntoh_ipv6(ip6) do { } while (0)
#else
    static void ntoh_ipv6(NSIPv6Addr* ip6)
    {
        uint64_t tmp;

        tmp = BYTE_SWAP_64(ip6->hi);
        ip6->hi = BYTE_SWAP_64(ip6->lo);
        ip6->lo = tmp;
    }

#endif

#if defined(WORDS_BIGENDIAN)

    static void _swap_ipv6(const NSIPv6Addr* ip6, NSIPv6Addr* ip6h)
    {
        ip6h->hi = ip6->hi;
        ip6h->lo = ip6->lo;
    }

#else
    static void _swap_ipv6(const NSIPv6Addr* ip6, NSIPv6Addr* ip6h)
    {
        ip6h->hi = BYTE_SWAP_64(ip6->lo);
        ip6h->lo = BYTE_SWAP_64(ip6->hi);
    }

#endif

    static void ntoh_swap_ipv6(const ip::snort_in6_addr* ip6, NSIPv6Addr* ip6h)
    {
        _swap_ipv6((const NSIPv6Addr*)ip6, ip6h);
    }

    static void hton_swap_ipv6(const NSIPv6Addr* ip6, ip::snort_in6_addr* ip6h)
    {
        _swap_ipv6(ip6, (NSIPv6Addr*)ip6h);
    }

    static void increment_ipv6_addr(NSIPv6Addr* ip6)
    {
        if (ip6->lo == ULLONG_MAX)
        {
            ip6->lo = 0;
            ip6->hi++;
        }
        else
            ip6->lo++;
    }

    static void decrement_ipv6_addr(NSIPv6Addr* ip6)
    {
        if (!ip6->lo)
        {
            ip6->lo = ULLONG_MAX;
            ip6->hi--;
        }
        else
            ip6->lo--;
    }

    static int contains_ex(NetworkSet* network_set, uint32_t ipaddr, unsigned* type)
    {
        int low=0;
        int high=0;
        *type = 0;

        if (!network_set)
            return 0;

        if (!network_set->count)
            return 0;

        high = network_set->count - 1;

        if (ipaddr < network_set->pnetwork[low]->range_min || ipaddr >
            network_set->pnetwork[high]->range_max)
            return 0;

        while (low <= high)
        {
            int middle = low + ((high - low)>>1);

            if (ipaddr < network_set->pnetwork[middle]->range_min)
                high = middle - 1;
            else if (ipaddr > network_set->pnetwork[middle]->range_max)
                low = middle + 1;
            else
            {
                *type = network_set->pnetwork[middle]->info.type;
                return 1;
            }
        }
        return 0;
    }

    static int contains6_ex(NetworkSet* network_set, NSIPv6Addr* ipaddr, unsigned* type)
    {
        int low=0;
        int high=0;
        *type = 0;

        if (!network_set)
            return 0;

        if (!network_set->count6)
            return 0;

        high = network_set->count6 - 1;

        if (compare_ipv6_address(ipaddr, &network_set->pnetwork6[low]->range_min) < 0 ||
            compare_ipv6_address(ipaddr, &network_set->pnetwork6[high]->range_max) > 0)
        {
            return 0;
        }
        while (low <= high)
        {
            int middle = low + ((high - low)>>1);

            if (compare_ipv6_address(ipaddr, &network_set->pnetwork6[middle]->range_min) < 0)
                high = middle - 1;
            else if (compare_ipv6_address(ipaddr, &network_set->pnetwork6[middle]->range_max) > 0)
                low = middle + 1;
            else
            {
                *type = network_set->pnetwork6[middle]->info.type;
                return 1;
            }
        }
        return 0;
    }

    static int contains(NetworkSet* network_set, uint32_t ipaddr)
    {
        unsigned type;
        return contains_ex(network_set, ipaddr, &type);
    }

    static int contains6(NetworkSet* network_set, NSIPv6Addr* ipaddr)
    {
        unsigned type;
        return contains6_ex(network_set, ipaddr, &type);
    }

    static int count4(NetworkSet* network_set, unsigned* count)
    {
        if (!network_set || !count)
            return -1;

        *count = sflist_count(&network_set->networks);

        return 0;
    }

    static int count6(NetworkSet* network_set, unsigned* count)
    {
        if (!network_set || !count)
            return -1;

        *count = sflist_count(&network_set->networks6);

        return 0;
    }

    static unsigned count_ex(NetworkSet* network_set)
    {
        if (!network_set)
            return 0;

        return sflist_count(&network_set->networks);
    }

    static unsigned count6_ex(NetworkSet* network_set)
    {
        if (!network_set)
            return 0;

        return sflist_count(&network_set->networks6);
    }

private:
    static int order_by_netmask(SF_LIST* ordered_networks, SF_LIST* networks, unsigned id);
    static int add_network_list(SF_LIST* networks, SF_LIST* new_networks);
    static int reduce_network_set(SF_LIST* networks);
    static int reduce_network_set6(SF_LIST* networks);
};
#endif

#endif

