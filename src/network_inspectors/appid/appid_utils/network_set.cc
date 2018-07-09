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

// network_set.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_set.h"

#ifdef USE_RNA_CONFIG

#include <sys/socket.h>

#include "log/messages.h"
#include "utils/util.h"

int NetworkSetManager::create(NetworkSet** network_set)
{
    if (!network_set)
        return -1;

    NetworkSet* tmp = (NetworkSet*)snort_calloc(sizeof(NetworkSet));
    sflist_init(&tmp->networks);
    sflist_init(&tmp->networks6);
    *network_set = tmp;
    return 0;
}

int NetworkSetManager::destroy(NetworkSet* network_set)
{
    if (!network_set)
        return -1;

    if (network_set->pnetwork)
    {
        snort_free(network_set->pnetwork);
        network_set->pnetwork = nullptr;
    }
    sflist_static_free_all(&network_set->networks, &snort_free);
    network_set->ids.clear();
    if (network_set->pnetwork6)
    {
        snort_free(network_set->pnetwork6);
        network_set->pnetwork6 = nullptr;
    }
    sflist_static_free_all(&network_set->networks6, &snort_free);
    network_set->ids6.clear();
    snort_free(network_set);

    return 0;
}

int NetworkSetManager::add_network_range_ex(NetworkSet* network_set, uint32_t range_min,
    uint32_t range_max, unsigned cidr_bits, int ip_not, unsigned id, unsigned type)
{
    if (!network_set)
        return -1;

    Network* network = (Network*)snort_calloc(sizeof(Network));
    network->info.id = id;
    network->info.ip_not = ip_not;
    network->info.type = type;
    network->info.netmask = cidr_bits;
    if (range_min <= range_max)
    {
        network->range_min = range_min;
        network->range_max = range_max;
    }
    else
    {
        network->range_min = range_max;
        network->range_max = range_min;
    }

    if (!network->info.ip_not)
    {
        SF_LNODE* iter = nullptr;

        for (Network* iNetwork = (Network*)sflist_first(&network_set->networks, &iter);
            iNetwork;
            iNetwork = (Network*)sflist_next(&iter))
        {
            if (iNetwork->info.id == network->info.id &&
                iNetwork->range_min == network->range_min &&
                iNetwork->range_max == network->range_max)
            {
                iNetwork->info.type |= network->info.type;
                snort_free(network);
                return 0;
            }
        }
    }

    sflist_add_tail(&network_set->networks, (void*)network);
    if (network_set->ids.insert(network->info.id).second == false)
    {
        ErrorMessage("NetworkSet: Failed to add id %u\n", network->info.id);
        return -1;
    }

    return 0;
}

int NetworkSetManager::add_network_range(NetworkSet* network_set, uint32_t range_min,
    uint32_t range_max, unsigned cidr_bits, int ip_not, unsigned id)
{
    return add_network_range_ex(network_set, range_min, range_max, cidr_bits, ip_not, id,
        0);
}

int NetworkSetManager::add_network_range6(NetworkSet* network_set, NSIPv6Addr* range_min,
    NSIPv6Addr* range_max, unsigned cidr_bits, int ip_not, unsigned id, unsigned type)
{
    if (!network_set)
        return -1;

    Network6* network = (Network6*)snort_calloc(sizeof(Network6));
    network->info.id = id;
    network->info.ip_not = ip_not;
    network->info.type = type;
    network->info.netmask = cidr_bits;
    if (compare_ipv6_address(range_min, range_max) <= 0)
    {
        network->range_min = *range_min;
        network->range_max = *range_max;
    }
    else
    {
        network->range_min = *range_max;
        network->range_max = *range_min;
    }

    if (!network->info.ip_not)
    {
        SF_LNODE* iter = nullptr;

        for (Network6* iNetwork = (Network6*)sflist_first(&network_set->networks6, &iter);
            iNetwork;
            iNetwork = (Network6*)sflist_next(&iter))
        {
            if (iNetwork->info.id == network->info.id &&
                !compare_ipv6_address(&iNetwork->range_min, &network->range_min) &&
                !compare_ipv6_address(&iNetwork->range_max, &network->range_max))
            {
                iNetwork->info.type |= network->info.type;
                snort_free(network);
                return 0;
            }
        }
    }

    sflist_add_tail(&network_set->networks6, (void*)network);
    if (network_set->ids6.insert(network->info.id).second == false)
    {
        ErrorMessage("NetworkSet: Failed to add IPv6 id %u\n", network->info.id);
        return -1;
    }

    return 0;
}

int NetworkSetManager::add_network_range6(NetworkSet* network_set, NSIPv6Addr* range_min,
    NSIPv6Addr* range_max, unsigned cidr_bits, int ip_not, unsigned id)
{
    return add_network_range6(network_set, range_min, range_max, cidr_bits, ip_not, id,
        0);
}

int NetworkSetManager::add_network_range_only_ipv6(
    NetworkSet* network_set, int ip_not, unsigned id, unsigned type)
{
    // Use two ranges to represent all of IPv6, excluding the IPv4-mapped range, ::FFFF:*.*.*.*
    NSIPv6Addr range_min, range_max;
    range_min.lo = 0;
    range_min.hi = 0;
    range_max.lo = 0x0000FFFEFFFFFFFFULL;  // 0x0000FFFF00000000 - 1
    range_max.hi = 0;
    int rval = add_network_range6(network_set, &range_min, &range_max, 0, ip_not, id, type);
    range_min.lo = 0x0001000000000000ULL;  // 0x0000FFFFFFFFFFFF + 1
    range_min.hi = 0;
    range_max.lo = 0xFFFFFFFFFFFFFFFFULL;
    range_max.hi = 0xFFFFFFFFFFFFFFFFULL;
    return rval ? rval : add_network_range6(network_set, &range_min, &range_max, 0,
        ip_not, id, type);
}

int NetworkSetManager::add_cidr_block_ex(NetworkSet* network_set, uint32_t ip,
    unsigned cidr_bits, int ip_not, unsigned id, unsigned type)
{
    if (cidr_bits > 32)
        return -1;

    uint32_t mask = (cidr_bits == 0) ? 0 : 0xffffffff << (32 - cidr_bits);
    uint32_t range_min = ip & mask;
    uint32_t range_max = range_min + ~mask;
    return add_network_range_ex(network_set, range_min, range_max, cidr_bits,
        ip_not, id, type);
}

int NetworkSetManager::add_cidr_block(NetworkSet* network_set, uint32_t ip,
    unsigned cidr_bits, int ip_not, unsigned id)
{
    return add_cidr_block_ex(network_set, ip, cidr_bits, ip_not, id, 0);
}

int NetworkSetManager::add_cidr_block6_ex(NetworkSet* network_set, NSIPv6Addr* ip,
    unsigned cidr_bits, int ip_not, unsigned id, unsigned type)
{
    NSIPv6Addr mask;

    if (cidr_bits > 128)
        return -1;

    /* Convert cidr to netmask */
    if (!cidr_bits)
    {
        mask.hi = 0;
        mask.lo = 0;
    }
    else if (cidr_bits < 64)
    {
        mask.hi = ULLONG_MAX << (64 - cidr_bits);
        mask.lo = 0;
    }
    else if (cidr_bits == 64)
    {
        mask.hi = ULLONG_MAX;
        mask.lo = 0;
    }
    else
    {
        mask.hi = ULLONG_MAX;
        mask.lo = ULLONG_MAX << (128 - cidr_bits);
    }

    NSIPv6Addr range_min;
    NSIPv6Addr range_max;

    range_min.lo = ip->lo & mask.lo;
    range_min.hi = ip->hi & mask.hi;
    range_max.lo = range_min.lo + ~mask.lo;
    range_max.hi = range_min.hi + ~mask.hi;
    return add_network_range6(network_set, &range_min, &range_max, cidr_bits, ip_not,
        id, type);
}

int NetworkSetManager::add_cidr_block6(NetworkSet* network_set, NSIPv6Addr* ip,
    unsigned cidr_bits, int ip_not, unsigned id)
{
    return add_cidr_block6_ex(network_set, ip, cidr_bits, ip_not, id, 0);
}

int NetworkSetManager::log_network_set(NetworkSet* network_set, const char* prefix, FILE* stream)
{
    SF_LNODE* iter = nullptr;
    char min_ip[INET6_ADDRSTRLEN];
    char max_ip[INET6_ADDRSTRLEN];

    if (!network_set)
        return -1;

    if (!prefix)
        prefix = "";

    if (!stream)
        stream = stdout;

    for (Network* network = (Network*)sflist_first(&network_set->networks, &iter);
        network;
        network = (Network*)sflist_next(&iter))
    {
        struct in_addr four;
        four.s_addr = htonl(network->range_min);
        inet_ntop(AF_INET, &four, min_ip, sizeof(min_ip));
        four.s_addr = htonl(network->range_max);
        inet_ntop(AF_INET, &four, max_ip, sizeof(max_ip));

        /* check containment for this network */
        fprintf(stream, "%s%s%s-%s for %u with %08X\n", prefix, network->info.ip_not ? "!" : "",
            min_ip, max_ip, network->info.id, network->info.type);
    }

    for (Network6* network6 = (Network6*)sflist_first(&network_set->networks6, &iter);
        network6;
        network6 = (Network6*)sflist_next(&iter))
    {
        NSIPv6Addr six = network6->range_min;
        ntoh_ipv6(&six);
        inet_ntop(AF_INET6, (struct in6_addr*)&six, min_ip, sizeof(min_ip));
        six = network6->range_max;
        ntoh_ipv6(&six);
        inet_ntop(AF_INET6, (struct in6_addr*)&six, max_ip, sizeof(max_ip));

        /* check containment for this network */
        fprintf(stream, "%s%s%s-%s for %u with %08X\n", prefix, network6->info.ip_not ? "!" : "",
            min_ip, max_ip, network6->info.id, network6->info.type);
    }

    return 0;
}

int NetworkSetManager::order_by_netmask(SF_LIST* ordered_networks, SF_LIST* networks, unsigned
    id)
{
    SF_LNODE* node = nullptr;
    NODE_DATA node_data;

    sflist_init(ordered_networks);
    do
    {
        SF_LNODE* iter = nullptr;

        node_data = nullptr;
        for (NSNetworkInfo* network = (NSNetworkInfo*)sflist_first(networks, &iter);
            network;
            network = (NSNetworkInfo*)sflist_next(&iter))
        {
            if ( network->id == id && (node_data == nullptr ||
                network->netmask < ((NSNetworkInfo*)node_data)->netmask ||
                ( ( network->netmask == ((NSNetworkInfo*)node_data)->netmask) &&
                !network->ip_not ) ) )
            {
                node_data = network;
                node = iter;
            }
        }

        if (node_data)
        {
            sflist_add_tail(ordered_networks, node_data);
            sflist_remove_node(networks, node);
        }
    }
    while (node_data);

    return 0;
}

int NetworkSetManager::add_network_list(SF_LIST* networks, SF_LIST* new_networks)
{
    void* network;

    while ((network = sflist_remove_head(new_networks)))
        sflist_add_tail(networks, network);

    return 0;
}

int NetworkSetManager::reduce_network_set(SF_LIST* networks)
{
    Network* ias;
    Network* i_ias;
    Network* new_ias;
    uint32_t tmp;
    bool changed;
    SF_LIST reduced_networks;

    if (!sflist_count(networks))
        return 0;

    sflist_init(&reduced_networks);
    while ( ( ias = (Network*)sflist_remove_head(networks) ) )
    {
        SF_LNODE* iter = nullptr;

        /* ias is lowest in the list, so it takes precedence */
        if (ias->info.ip_not)
        {
            i_ias = (Network*)sflist_first(&reduced_networks, &iter);
            while (i_ias)
            {
                changed = false;

                /*
                       i_ias      ******
                       ias   ***************
                 */
                if (ias->range_min <= i_ias->range_min && ias->range_max >= i_ias->range_max)
                {
                    sflist_remove_node(&reduced_networks, iter);
                    changed = true;
                }
                /*
                        i_ias ************
                        ias        ***
                              or
                        i_ias ************
                        ias      ************
                 */
                else if (ias->range_min > i_ias->range_min && ias->range_min <= i_ias->range_max)
                {
                    tmp = i_ias->range_max;
                    i_ias->range_max = ias->range_min - 1;
                    if (ias->range_max < tmp)
                    {
                        new_ias = (Network*)snort_calloc(sizeof(Network));
                        *new_ias = *i_ias;
                        new_ias->range_min = ias->range_max + 1;
                        new_ias->range_max = tmp;
                        sflist_add_tail(&reduced_networks, new_ias);
                        changed = true;
                    }
                }
                /*
                        i_ias      ************
                        ias   ************
                              or
                        i_ias ************
                        ias   ****
                 */
                else if (ias->range_max >= i_ias->range_min && ias->range_max <= i_ias->range_max)
                {
                    tmp = i_ias->range_min;
                    i_ias->range_min = ias->range_max + 1;
                    if (ias->range_min > tmp)
                    {
                        new_ias = (Network*)snort_calloc(sizeof(Network));
                        *new_ias = *i_ias;
                        new_ias->range_min = tmp;
                        new_ias->range_max = ias->range_min - 1;
                        sflist_add_tail(&reduced_networks, new_ias);
                        changed = true;
                    }
                }

                if (changed)
                    i_ias = (Network*)sflist_first(&reduced_networks, &iter);
                else
                    i_ias = (Network*)sflist_next(&iter);
            }

            snort_free(ias);
        }
        else
        {
            i_ias = (Network*)sflist_first(&reduced_networks, &iter);
            while (i_ias)
            {
                changed = false;
                if (ias->info.type == i_ias->info.type)
                {
                    /*
                            i_ias      ******
                            ias   ***************
                     */
                    if (ias->range_min <= i_ias->range_min && ias->range_max >= i_ias->range_max)
                    {
                        sflist_remove_node(&reduced_networks, iter);
                        changed = true;
                        snort_free(i_ias);
                        i_ias = nullptr;
                    }
                    /*
                            i_ias ***************
                            ias        ******
                     */
                    else if (i_ias->range_min <= ias->range_min && i_ias->range_max >=
                        ias->range_max)
                    {
                        ias->range_min = i_ias->range_min;
                        ias->range_max = i_ias->range_max;
                        sflist_remove_node(&reduced_networks, iter);
                        changed = true;
                        snort_free(i_ias);
                        i_ias = nullptr;
                    }
                    /*
                            i_ias ************
                            ias         ************
                     */
                    else if (ias->range_min > i_ias->range_min && ias->range_min <=
                        i_ias->range_max)
                    {
                        i_ias->range_max = ias->range_min - 1;
                    }
                    /*
                            i_ias      ************
                            ias   ************
                     */
                    else if (ias->range_max >= i_ias->range_min && ias->range_max <
                        i_ias->range_max)
                    {
                        i_ias->range_min = ias->range_max + 1;
                    }
                }
                else /* different types */
                {
                    /*
                            i_ias     ******
                            ias       ******
                     */
                    if (ias->range_min == i_ias->range_min && ias->range_max == i_ias->range_max)
                    {
                        i_ias->info.type = ias->info.type;
                        snort_free(ias);
                        ias = nullptr;
                        break;
                    }
                    /*
                            i_ias      ******
                            ias   ***************
                     */
                    else if (ias->range_min < i_ias->range_min && ias->range_max >=
                        i_ias->range_max)
                    {
                        sflist_remove_node(&reduced_networks, iter);
                        snort_free(i_ias);
                        i_ias = nullptr;
                        changed = true;
                    }
                    /*
                            i_ias ************
                            ias         ***
                                  or
                            i_ias ************
                            ias         ************
                                  or
                            i_ias ************
                            ias         ******
                     */
                    else if (ias->range_min > i_ias->range_min && ias->range_min <=
                        i_ias->range_max)
                    {
                        tmp = i_ias->range_max;
                        i_ias->range_max = ias->range_min - 1;
                        if (ias->range_max < tmp)
                        {
                            new_ias = (Network*)snort_calloc(sizeof(Network));
                            *new_ias = *i_ias;
                            new_ias->range_min = ias->range_max + 1;
                            new_ias->range_max = tmp;
                            sflist_add_tail(&reduced_networks, new_ias);
                            changed = true;
                        }
                    }
                    /*
                            i_ias      ************
                            ias   ************
                                  or
                            i_ias ************
                            ias   ****
                     */
                    else if (ias->range_max > i_ias->range_min && ias->range_max <
                        i_ias->range_max)
                    {
                        i_ias->range_min = ias->range_max + 1;
                    }
                }

                if (changed)
                    i_ias = (Network*)sflist_first(&reduced_networks, &iter);
                else
                    i_ias = (Network*)sflist_next(&iter);
            }

            if (ias)
                sflist_add_tail(&reduced_networks, ias);
        }
    }

    /* Minimize the ranges */
    SF_LNODE* outer_iter;
    ias = (Network*)sflist_first(&reduced_networks, &outer_iter);
    while (ias)
    {
        /* i_ias is lowest in the list, so it takes precedence */
        changed = false;
        SF_LNODE* inner_iter = outer_iter;

        i_ias = (Network*)sflist_next(&inner_iter);
        while ( i_ias )
        {
            if (ias->info.type == i_ias->info.type)
            {
                /*
                            i_ias ************
                            ias               ***
                 */
                if (ias->range_min && (i_ias->range_max+1) == ias->range_min)
                {
                    i_ias->range_max = ias->range_max;
                    sflist_remove_node(&reduced_networks, outer_iter);
                    snort_free(ias);
                    changed = true;
                    break;
                }
                /*
                            i_ias      ************
                            ias   *****
                 */
                else if (i_ias->range_min && (ias->range_max+1) == i_ias->range_min)
                {
                    i_ias->range_min = ias->range_min;
                    sflist_remove_node(&reduced_networks, outer_iter);
                    snort_free(ias);
                    changed = true;
                    break;
                }
            }

            i_ias = (Network*)sflist_next(&inner_iter);
        }

        if (changed)
            ias = (Network*)sflist_first(&reduced_networks, &outer_iter);
        else
            ias = (Network*)sflist_next(&outer_iter);
    }

    sflist_static_free_all(networks, &snort_free);
    while ((ias = (Network*)sflist_remove_head(&reduced_networks)))
    {
        sflist_add_tail(networks, ias);
    }
    return 0;
}

int NetworkSetManager::reduce_network_set6(SF_LIST* networks)
{
    Network6* ias;
    Network6* i_ias;
    Network6* new_ias;
    NSIPv6Addr tmp;
    NSIPv6Addr tmp2;
    bool changed;
    SF_LIST reduced_networks;

    if (!sflist_count(networks))
        return 0;

    sflist_init(&reduced_networks);
    while ((ias = (Network6*)sflist_remove_head(networks)))
    {
        SF_LNODE* iter = nullptr;

        /* ias is lowest in the list, so it takes precedence */
        if (ias->info.ip_not)
        {
            i_ias = (Network6*)sflist_first(&reduced_networks, &iter);
            while (i_ias)
            {
                changed = false;

                /*
                   i_ias      ******
                   ias   ***************
                */
                if (compare_ipv6_address(&ias->range_min, &i_ias->range_min) <= 0 &&
                    compare_ipv6_address(&ias->range_max, &i_ias->range_max) >= 0)
                {
                    sflist_remove_node(&reduced_networks, iter);
                    changed = true;
                }
                /*
                    i_ias ************
                    ias        ***
                          or
                    i_ias ************
                    ias      ************
                */
                else if (compare_ipv6_address(&ias->range_min, &i_ias->range_min) > 0 &&
                    compare_ipv6_address(&ias->range_min, &i_ias->range_max) <= 0)
                {
                    tmp = i_ias->range_max;
                    i_ias->range_max = ias->range_min;
                    decrement_ipv6_addr(&i_ias->range_max);
                    if (compare_ipv6_address(&ias->range_max, &tmp) < 0)
                    {
                        new_ias = (Network6*)snort_calloc(sizeof(Network6));
                        *new_ias = *i_ias;
                        new_ias->range_min = ias->range_max;
                        increment_ipv6_addr(&new_ias->range_min);
                        new_ias->range_max = tmp;
                        sflist_add_tail(&reduced_networks, new_ias);
                        changed = true;
                    }
                }
                /*
                    i_ias      ************
                    ias   ************
                          or
                    i_ias ************
                    ias   ****
                */
                else if (compare_ipv6_address(&ias->range_max, &i_ias->range_min) >= 0 &&
                    compare_ipv6_address(&ias->range_max, &i_ias->range_max) <= 0)
                {
                    tmp = i_ias->range_min;
                    i_ias->range_min = ias->range_max;
                    increment_ipv6_addr(&i_ias->range_min);
                    if (compare_ipv6_address(&ias->range_min, &tmp) > 0)
                    {
                        new_ias = (Network6*)snort_calloc(sizeof(Network6));
                        *new_ias = *i_ias;
                        new_ias->range_min = tmp;
                        new_ias->range_max = ias->range_min;
                        decrement_ipv6_addr(&new_ias->range_max);
                        sflist_add_tail(&reduced_networks, new_ias);
                        changed = true;
                    }
                }

                if (changed)
                    i_ias = (Network6*)sflist_first(&reduced_networks, &iter);
                else
                    i_ias = (Network6*)sflist_next(&iter);
            }
            snort_free(ias);
        }
        else
        {
            i_ias = (Network6*)sflist_first(&reduced_networks, &iter);
            while (i_ias)
            {
                changed = false;
                if (ias->info.type == i_ias->info.type)
                {
                    /*
                        i_ias      ******
                        ias   ***************
                    */
                    if (compare_ipv6_address(&ias->range_min, &i_ias->range_min) <= 0 &&
                        compare_ipv6_address(&ias->range_max, &i_ias->range_max) >= 0)
                    {
                        sflist_remove_node(&reduced_networks, iter);
                        changed = true;
                        snort_free(i_ias);
                        i_ias = nullptr;
                    }
                    /*
                        i_ias ***************
                        ias        ******
                    */
                    else if (compare_ipv6_address(&i_ias->range_min, &ias->range_min) <= 0 &&
                        compare_ipv6_address(&i_ias->range_max, &ias->range_max) >= 0)
                    {
                        ias->range_min = i_ias->range_min;
                        ias->range_max = i_ias->range_max;
                        sflist_remove_node(&reduced_networks, iter);
                        changed = true;
                        snort_free(i_ias);
                        i_ias = nullptr;
                    }
                    /*
                        i_ias ************
                        ias         ************
                    */
                    else if (compare_ipv6_address(&ias->range_min, &i_ias->range_min) > 0 &&
                        compare_ipv6_address(&ias->range_min, &i_ias->range_max) <= 0)
                    {
                        i_ias->range_max = ias->range_min;
                        decrement_ipv6_addr(&i_ias->range_max);
                    }
                    /*
                        i_ias      ************
                        ias   ************
                    */
                    else if (compare_ipv6_address(&ias->range_max, &i_ias->range_min) >= 0 &&
                        compare_ipv6_address(&ias->range_max, &i_ias->range_max) < 0)
                    {
                        i_ias->range_min = ias->range_max;
                        increment_ipv6_addr(&i_ias->range_min);
                    }
                }
                else     /* different types */
                {
                    /*
                        i_ias     ******
                        ias       ******
                    */
                    if (!compare_ipv6_address(&ias->range_min, &i_ias->range_min) &&
                        !compare_ipv6_address(&ias->range_max, &i_ias->range_max))
                    {
                        i_ias->info.type = ias->info.type;
                        snort_free(ias);
                        ias = nullptr;
                        break;
                    }
                    /*
                        i_ias      ******
                        ias   ***************
                    */
                    else if (compare_ipv6_address(&ias->range_min, &i_ias->range_min) < 0 &&
                        compare_ipv6_address(&ias->range_max, &i_ias->range_max) >= 0)
                    {
                        sflist_remove_node(&reduced_networks, iter);
                        snort_free(i_ias);
                        i_ias = nullptr;
                        changed = true;
                    }
                    /*
                        i_ias ************
                        ias         ***
                              or
                        i_ias ************
                        ias         ************
                              or
                        i_ias ************
                        ias         ******
                    */
                    else if (compare_ipv6_address(&ias->range_min, &i_ias->range_min) > 0 &&
                        compare_ipv6_address(&ias->range_min, &i_ias->range_max) <= 0)
                    {
                        tmp = i_ias->range_max;
                        i_ias->range_max = ias->range_min;
                        decrement_ipv6_addr(&i_ias->range_max);
                        if (compare_ipv6_address(&ias->range_max, &tmp) < 0)
                        {
                            new_ias = (Network6*)snort_calloc(sizeof(Network6));
                            *new_ias = *i_ias;
                            new_ias->range_min = ias->range_max;
                            increment_ipv6_addr(&new_ias->range_min);
                            new_ias->range_max = tmp;
                            sflist_add_tail(&reduced_networks, new_ias);
                            changed = true;
                        }
                    }
                    /*
                        i_ias      ************
                        ias   ************
                              or
                        i_ias ************
                        ias   ****
                    */
                    else if (compare_ipv6_address(&ias->range_max, &i_ias->range_min) > 0 &&
                        compare_ipv6_address(&ias->range_max, &i_ias->range_max) < 0)
                    {
                        i_ias->range_min = ias->range_max;
                        increment_ipv6_addr(&i_ias->range_min);
                    }
                }

                if (changed)
                    i_ias = (Network6*)sflist_first(&reduced_networks, &iter);
                else
                    i_ias = (Network6*)sflist_next(&iter);
            }

            if (ias)
                sflist_add_tail(&reduced_networks, ias);
        }
    }

    /* Minimize the ranges */
    SF_LNODE* outer_iter;
    ias = (Network6*)sflist_first(&reduced_networks, &outer_iter);
    while (ias)
    {
        /* i_ias is lowest in the list, so it takes precedence */
        changed = false;
        SF_LNODE* inner_iter = outer_iter;
        i_ias = (Network6*)sflist_next(&inner_iter);
        while ( i_ias )
        {
            if (ias->info.type == i_ias->info.type)
            {
                /*
                            i_ias ************
                            ias               ***
                 */
                tmp = i_ias->range_max;
                increment_ipv6_addr(&tmp);
                tmp2 = ias->range_max;
                increment_ipv6_addr(&tmp2);
                if ((ias->range_min.lo || ias->range_min.hi) &&
                    !compare_ipv6_address(&tmp, &ias->range_min))
                {
                    i_ias->range_max = ias->range_max;
                    sflist_remove_node(&reduced_networks, outer_iter);
                    snort_free(ias);
                    changed = true;
                    break;
                }
                /*
                            i_ias      ************
                            ias   *****
                 */
                else if ((i_ias->range_min.lo || i_ias->range_min.hi) &&
                    !compare_ipv6_address(&tmp2, &i_ias->range_min))
                {
                    i_ias->range_min = ias->range_min;
                    sflist_remove_node(&reduced_networks, outer_iter);
                    snort_free(ias);
                    changed = true;
                    break;
                }
            }

            i_ias = (Network6*)sflist_next(&inner_iter);
        }

        if (changed)
            ias = (Network6*)sflist_first(&reduced_networks, &outer_iter);
        else
            ias = (Network6*)sflist_next(&outer_iter);
    }

    sflist_static_free_all(networks, &snort_free);
    while ((ias = (Network6*)sflist_remove_head(&reduced_networks)))
    {
        sflist_add_tail(networks, ias);
    }
    return 0;
}

int NetworkSetManager::reduce(NetworkSet* network_set)
{
    int rval;
    SF_LIST ordered_networks;
    Network* network;
    Network6* network6;
    unsigned tmp;
    int count;

    if (!network_set)
        return -1;

    for (auto& id : network_set->ids)
    {
        if ((rval = order_by_netmask(&ordered_networks, &network_set->networks, id)) != 0)
        {
            sflist_free_all(&ordered_networks, &snort_free);
            return rval;
        }
        if ((rval = reduce_network_set(&ordered_networks)) != 0)
        {
            sflist_free_all(&ordered_networks, &snort_free);
            return rval;
        }
        if ((rval = add_network_list(&network_set->networks, &ordered_networks)) != 0)
        {
            sflist_free_all(&ordered_networks, &snort_free);
            return rval;
        }
    }
    if ((rval = reduce_network_set(&network_set->networks)) != 0)
    {
        sflist_free_all(&ordered_networks, &snort_free);
        return rval;
    }

    tmp = 0;
    if ((rval = count4(network_set, &tmp)) != 0)
        return rval;

    count = (int)tmp;
    if (count > 0)
    {
        network_set->count = count;
        if (network_set->pnetwork)
        {
            snort_free(network_set->pnetwork);
            network_set->pnetwork = nullptr;
        }
        network_set->pnetwork = (Network**)snort_calloc(count * sizeof(Network*));
        SF_LNODE* iter = nullptr;
        int i = 0;
        for (network = (Network*)sflist_first(&network_set->networks, &iter);
            network && i < count;
            network = (Network*)sflist_next(&iter))
        {
            network_set->pnetwork[i++] = network;
        }
        /* bubble sort this array */
        for (int i = (count - 1); i >= 0; i--)
        {
            for (int j = 1; j <= i; j++)
            {
                if (network_set->pnetwork[j - 1]->range_min > network_set->pnetwork[j]->range_min)
                {
                    network = network_set->pnetwork[j - 1];
                    network_set->pnetwork[j - 1] = network_set->pnetwork[j];
                    network_set->pnetwork[j] = network;
                }
            }
        }
    }

    for (auto& id : network_set->ids6)
    {
        if ((rval = order_by_netmask(&ordered_networks, &network_set->networks6, id)) != 0)
        {
            sflist_free_all(&ordered_networks, &snort_free);
            return rval;
        }

        if ((rval = reduce_network_set6(&ordered_networks)) != 0)
        {
            sflist_free_all(&ordered_networks, &snort_free);
            return rval;
        }

        if ((rval = add_network_list(&network_set->networks6, &ordered_networks)) != 0)
        {
            sflist_free_all(&ordered_networks, &snort_free);
            return rval;
        }
    }
    if ((rval = reduce_network_set6(&network_set->networks6)) != 0)
    {
        sflist_free_all(&ordered_networks, &snort_free);
        return rval;
    }

    tmp = 0;
    if ((rval = count6(network_set, &tmp)) != 0)
        return rval;

    count = (int)tmp;
    if (count > 0)
    {
        network_set->count6 = count;
        if (network_set->pnetwork6)
        {
            snort_free(network_set->pnetwork6);
            network_set->pnetwork6 = nullptr;
        }
        network_set->pnetwork6 = (Network6**)snort_calloc(count * sizeof(Network6*));
        SF_LNODE* iter = nullptr;
        int i = 0;
        for (network6 = (Network6*)sflist_first(&network_set->networks6, &iter);
            network6 && i < count;
            network6 = (Network6*)sflist_next(&iter))
        {
            network_set->pnetwork6[i++] = network6;
        }
        /* bubble sort this array */
        for (int i = (count - 1); i >= 0; i--)
        {
            for (int j = 1; j <= i; j++)
            {
                if (compare_ipv6_address(&network_set->pnetwork6[j - 1]->range_min,
                    &network_set->pnetwork6[j]->range_min) > 0)
                {
                    network6 = network_set->pnetwork6[j-1];
                    network_set->pnetwork6[j - 1] = network_set->pnetwork6[j];
                    network_set->pnetwork6[j] = network6;
                }
            }
        }
    }
    return 0;
}

NetworkSet* NetworkSetManager::copy(NetworkSet* network_set)
{
    NetworkSet* new_set;
    SF_LNODE* iter;

    if (!network_set)
        return nullptr;

    if (create(&new_set) != 0)
        return nullptr;

    for (Network* network = (Network*)sflist_first(&network_set->networks, &iter);
        network;
        network = (Network*)sflist_next(&iter))
    {
        if (add_network_range_ex(new_set, network->range_min, network->range_max,
            network->info.netmask, network->info.ip_not,
            network->info.id, network->info.type) != 0)
        {
            destroy(new_set);
            return nullptr;
        }
    }
    for (Network6* network6 = (Network6*)sflist_first(&network_set->networks6, &iter);
        network6;
        network6 = (Network6*)sflist_next(&iter))
    {
        if (add_network_range6(new_set, &network6->range_min, &network6->range_max,
            network6->info.netmask, network6->info.ip_not,
            network6->info.id, network6->info.type) != 0)
        {
            destroy(new_set);
            return nullptr;
        }
    }
    return new_set;
}

int NetworkSetManager::add_set(NetworkSet* dest_set, NetworkSet* src_set)
{
    SF_LNODE* iter;
    int rval;

    if (!src_set || !dest_set)
        return -1;

    for (Network* network = (Network*)sflist_first(&src_set->networks, &iter);
        network;
        network = (Network*)sflist_next(&iter))
    {
        if ((rval = add_network_range_ex(dest_set, network->range_min, network->range_max,
                network->info.netmask, network->info.ip_not,
                network->info.id, network->info.type)) != 0)
        {
            return rval;
        }
    }

    for (Network6* network6 = (Network6*)sflist_first(&src_set->networks6, &iter);
        network6;
        network6 = (Network6*)sflist_next(&iter))
    {
        if ((rval = add_network_range6(dest_set, &network6->range_min, &network6->range_max,
                network6->info.netmask, network6->info.ip_not,
                network6->info.id, network6->info.type)) != 0)
        {
            return rval;
        }
    }
    return 0;
}

#endif

