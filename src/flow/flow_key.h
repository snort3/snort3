/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include "snort_types.h"
#include "hash/sfhashfcn.h"
#include "sfip/ipv6_port.h"

struct FlowKey
{
    uint32_t   ip_l[4]; /* Low IP */
    uint32_t   ip_h[4]; /* High IP */
    uint16_t   port_l; /* Low Port - 0 if ICMP */
    uint16_t   port_h; /* High Port - 0 if ICMP */
    uint16_t   vlan_tag;
    uint8_t    protocol;
    char       pad;
    uint32_t   mplsLabel; /* MPLS label */
    uint16_t   addressSpaceId;
    uint16_t   addressSpaceIdPad1;

    void init(
        snort_ip_p srcIP, uint16_t srcPort,
        snort_ip_p dstIP, uint16_t dstPort,
        char proto, uint16_t vlan, uint32_t mplsId,
        uint16_t addrSpaceId);

    // XXX If this data structure changes size, compare must be updated!
    static uint32_t hash(SFHASHFCN *p, unsigned char *d, int);
    static int compare(const void *s1, const void *s2, size_t);

private:
    void init4(
        snort_ip_p srcIP, uint16_t srcPort,
        snort_ip_p dstIP, uint16_t dstPort,
        char proto, uint32_t mplsId);

    void init6(
        snort_ip_p srcIP, uint16_t srcPort,
        snort_ip_p dstIP, uint16_t dstPort,
        char proto, uint32_t mplsId);
};

#endif

