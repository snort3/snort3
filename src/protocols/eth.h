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
// eth.h author Josh Rosenbaum <jrosenba@cisco.com>


#ifndef PROTOCOLS_ETH_H
#define PROTOCOLS_ETH_H


#define ETHERNET_HEADER_LEN 14
#define ETHERNET_MTU                  1500

#define ETH_DSAP_SNA                  0x08    /* SNA */
#define ETH_SSAP_SNA                  0x00    /* SNA */
#define ETH_DSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP                   0xaa    /* IP */
#define ETH_SSAP_IP                   0xaa    /* IP */

#define ETH_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP               0x00000c    /* Cisco Discovery Proto */

namespace eth
{


constexpr uint16_t MTU_LEN = 1500;
constexpr uint16_t MAX_FRAME_LENGTH = 1500;
constexpr uint16_t MIN_ETHERTYPE = 1536;
constexpr uint16_t ETH_HEADER_LEN = 14;

struct EtherHdr
{
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;
};

} // namespace eth


#endif

