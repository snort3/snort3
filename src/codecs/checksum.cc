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
// checksum.h author Josh Rosenbaum <jorosenba@cisco.com>



#include "protocols/checksum.h"

/************************************************************
 ***********  Checksum information  *************************
 ************************************************************/

namespace checksum
{

static inline void add_ipv4_pseudoheader(const uint16_t *h, uint32_t &cksum)
{
    /* ipv4 pseudo header must have 12 bytes */
    cksum += h[0];
    cksum += h[1];
    cksum += h[2];
    cksum += h[3];
    cksum += h[4];
    cksum += h[5];
}


static inline void add_ipv6_pseudoheader(const uint16_t *h, uint32_t &cksum)
{
   /* PseudoHeader must have 36 bytes */
   cksum += h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];
   cksum += h[6];
   cksum += h[7];
   cksum += h[8];
   cksum += h[9];
   cksum += h[10];
   cksum += h[11];
   cksum += h[12];
   cksum += h[13];
   cksum += h[14];
   cksum += h[15];
   cksum += h[16];
   cksum += h[17];
}


static inline void add_tcp_header(const uint16_t* &d,
                                    size_t &len,
                                    uint32_t &cksum)
{
    /* TCP hdr must have 20 hdr bytes */
    cksum += d[0];
    cksum += d[1];
    cksum += d[2];
    cksum += d[3];
    cksum += d[4];
    cksum += d[5];
    cksum += d[6];
    cksum += d[7];
    cksum += d[8];
    cksum += d[9];
    d += 10;
    len -= 20;
}

static inline void add_udp_header(const uint16_t* &d,
                                    size_t &len,
                                    uint32_t &cksum)
{
   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];
   len -= 8;
   d += 4;
}

static inline void add_ip_header(const uint16_t* &d,
                                    size_t &len,
                                    uint32_t &cksum)
{
    /* IP must be >= 20 bytes */
    cksum += d[0];
    cksum += d[1];
    cksum += d[2];
    cksum += d[3];
    cksum += d[4];
    cksum += d[5];
    cksum += d[6];
    cksum += d[7];
    cksum += d[8];
    cksum += d[9];
    d += 10;
    len -= 20;
}

 
uint16_t icmp_cksum(const uint16_t *buf, size_t len, Pseudoheader6* ph)
{
    uint32_t cksum = 0;

    add_ipv6_pseudoheader((uint16_t *)ph, cksum);
    return cksum_add(buf, len, cksum);
}

uint16_t tcp_cksum(const uint16_t *h, size_t len, Pseudoheader *ph )
{
    uint32_t cksum = 0;

    add_ipv4_pseudoheader((uint16_t *)ph, cksum);
    add_tcp_header(h, len, cksum);
    return cksum_add(h, len, cksum);
}


uint16_t tcp_cksum(const uint16_t *buf, size_t len, Pseudoheader6 *ph )
{
    uint32_t cksum = 0;

    add_ipv6_pseudoheader((uint16_t *)ph, cksum);
    add_tcp_header(buf, len, cksum);
    return cksum_add(buf, len, cksum);
}


uint16_t udp_cksum(const uint16_t *buf, size_t len, Pseudoheader *ph )
{
    uint32_t cksum = 0;

    add_ipv4_pseudoheader((uint16_t *)ph, cksum);
    add_udp_header(buf, len, cksum);
    return cksum_add(buf, len, cksum);
}


uint16_t udp_cksum(const uint16_t *buf, size_t len, Pseudoheader6 *ph )
{
    uint32_t cksum = 0;

    add_ipv6_pseudoheader((uint16_t *)ph, cksum);
    add_udp_header(buf, len, cksum);
    return cksum_add(buf, len, cksum);
}

uint16_t ip_cksum(const uint16_t *buf, size_t len)
{
    uint32_t cksum = 0;

    add_ip_header(buf, len, cksum);
    return cksum_add(buf, len, cksum);
}


// credit belong to dnet.h.  copied directrly from their source code
// src/ip-util.cc
uint16_t cksum_add(const uint16_t *buf, size_t len, uint32_t cksum)
{
    uint16_t *sp = (uint16_t *)buf;
    int n, sn;

    if (len > 1 )
    {
        sn = ((len / 2) & 0xF);  // len divided by two mod 16 == len/2 % 16
        n = (((len / 2) + 15) / 16) ;  // ceiling of (len / 2) / 16

        switch (sn) {
        case 0:
            sn = 16;
            cksum += sp[15];
        case 15:
            cksum += sp[14];
        case 14:
            cksum += sp[13];
        case 13:
            cksum += sp[12];
        case 12:
            cksum += sp[11];
        case 11:
            cksum += sp[10];
        case 10:
            cksum += sp[9];
        case 9:
            cksum += sp[8];
        case 8:
            cksum  += sp[7];
        case 7:
            cksum += sp[6];
        case 6:
            cksum += sp[5];
        case 5:
            cksum += sp[4];
        case 4:
            cksum += sp[3];
        case 3:
            cksum += sp[2];
        case 2:
            cksum += sp[1];
        case 1:
            cksum += sp[0];
        }
        sp += sn;


        /* XXX - unroll loop using Duff's device. */
        while (--n > 0) {
            cksum += sp[0];
            cksum += sp[1];
            cksum += sp[2];
            cksum += sp[3];
            cksum += sp[4];
            cksum += sp[5];
            cksum += sp[6];
            cksum += sp[7];
            cksum += sp[8];
            cksum += sp[9];
            cksum += sp[10];
            cksum += sp[11];
            cksum += sp[12];
            cksum += sp[13];
            cksum += sp[14];
            cksum += sp[15];
            sp += 16;
        };
    }
    
    if (len & 1)
        cksum += (*(unsigned char*)sp);
    
    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

} // namespace checksum
