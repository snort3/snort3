
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
// arp.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_ARP_H
#define PROTOCOLS_ARP_H

namespace snort
{
namespace arp
{

struct ARPHdr
{
    uint16_t ar_hrd;       /* format of hardware address   */
    uint16_t ar_pro;       /* format of protocol address   */
    uint8_t ar_hln;        /* length of hardware address   */
    uint8_t ar_pln;        /* length of protocol address   */
    uint16_t ar_op;        /* ARP opcode (command)         */
};

struct EtherARP
{
    ARPHdr ea_hdr;      /* fixed-size header */
    uint8_t arp_sha[6];    /* sender hardware address */
    union
    {
        uint8_t arp_spa[4];    /* sender protocol address */
        uint32_t arp_spa32;
    };
    uint8_t arp_tha[6];    /* target hardware address */
    uint8_t arp_tpa[4];    /* target protocol address */
} __attribute__((__packed__));

constexpr uint16_t ETHERARP_HDR_LEN = 28; /*  sizeof EtherARP != 28 */

} // namespace arp
} // namespace snort

#ifndef ARPOP_REQUEST
constexpr uint16_t ARPOP_REQUEST = 1;  /* ARP request  */
#endif

#ifndef ARPOP_REPLY
constexpr uint16_t ARPOP_REPLY = 2;    /* ARP reply    */
#endif

#ifndef ARPOP_RREQUEST
constexpr uint16_t ARPOP_RREQUEST = 3; /* RARP request */
#endif

#ifndef ARPOP_RREPLY
constexpr uint16_t ARPOP_RREPLY = 4;   /* RARP reply   */
#endif

#endif

