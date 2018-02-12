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
// token_ring.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_TOKEN_RING_H
#define PROTOCOLS_TOKEN_RING_H

#include <arpa/inet.h>

#include "protocols/protocol_ids.h"

namespace token_ring
{
/* LLC structure */
struct Trh_llc
{
    uint8_t dsap;
    uint8_t ssap;
    uint8_t protid[3];
    uint16_t ether_type;

    /* return data in byte order */
    inline ProtocolId ethertype() const
    { return (ProtocolId)ntohs(ether_type); }

    /* return data in network order */
    inline uint16_t raw_ethertype() const
    { return ether_type; }

};

/* RIF structure
 * Linux/tcpdump patch defines tokenring header in dump way, since not
 * every tokenring header with have RIF data... we define it separately, and
 * a bit more split up
 */

/* These are macros to use the bitlevel accesses in the Trh_Mr header

   they haven't been tested and they aren't used much so here is a
   listing of what used to be there

   #if defined(WORDS_BIGENDIAN)
      uint16_t bcast:3, len:5, dir:1, lf:3, res:4;
   #else
      uint16_t len:5,         length of RIF field, including RC itself
      bcast:3,       broadcast indicator
      res:4,         reserved
      lf:3,      largest frame size
      dir:1;         direction
*/

#define TRH_MR_BCAST(trhmr)  ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0xe000) >> 13)
#define TRH_MR_LEN(trhmr)    ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x1F00) >> 8)
#define TRH_MR_DIR(trhmr)    ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x0080) >> 7)
#define TRH_MR_LF(trhmr)     ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x0070) >> 4)
#define TRH_MR_RES(trhmr)     ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x000F))

struct Trh_mr
{
    uint16_t bcast_len_dir_lf_res; /* broadcast/res/framesize/direction */
    uint16_t rseg[8];
};

#define TR_ALEN             6        /* octets in an Ethernet header */
#define FDDI_ALEN           6
#define IPARP_SAP           0xaa

struct Trh_hdr
{
    uint8_t ac;        /* access control field */
    uint8_t fc;        /* frame control field */
    uint8_t daddr[TR_ALEN];    /* src address */
    uint8_t saddr[TR_ALEN];    /* dst address */
};
/* End Token Ring Data Structures */

inline const Trh_mr* get_trhmr(const Trh_llc* llc)
{
    if (llc->dsap != IPARP_SAP && llc->ssap != IPARP_SAP)
        return reinterpret_cast<const Trh_mr*>(llc);

    return nullptr;
}
} // namespace token_ring

#endif

