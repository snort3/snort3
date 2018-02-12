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
// linux_sll.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_LINUX_SLL_H
#define PROTOCOLS_LINUX_SLL_H

namespace linux_sll
{
/* 'Linux cooked captures' data
 * (taken from tcpdump source).
 */

const uint8_t SLL_HDR_LEN = 16;
const uint8_t SLL_ADDRLEN = 8;

struct SLLHdr
{
    uint16_t sll_pkttype;              /* packet type */
    uint16_t sll_hatype;               /* link-layer address type */
    uint16_t sll_halen;                /* link-layer address length */
    uint8_t sll_addr[SLL_ADDRLEN];             /* link-layer address */
    uint16_t sll_protocol;             /* protocol */
};

/*
 * ssl_pkttype values.
 */

#define LINUX_SLL_HOST          0
#define LINUX_SLL_BROADCAST     1
#define LINUX_SLL_MULTICAST     2
#define LINUX_SLL_OTHERHOST     3
#define LINUX_SLL_OUTGOING      4

/* ssl protocol values */

#define LINUX_SLL_P_802_3       0x0001  /* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_802_2       0x0004  /* 802.2 frames (not D/I/X Ethernet) */
} // namespace ssl

#endif /* LINUX_SLL_H */

