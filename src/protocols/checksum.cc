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

static inline void add_ipv4_pseudoheader(const uint16_t *h, 
                                    uint32_t &cksum1, 
                                    uint32_t &cksum2)
{
    /* ipv4 pseudo header must have 12 bytes */
    cksum1  = h[0];
    cksum2 += h[1];
    cksum1 += h[2];
    cksum2 += h[3];
    cksum1 += h[4];
    cksum2 += h[5];
}


static inline void add_ipv6_pseudoheader(const uint16_t *h, 
                                    uint32_t &cksum1, 
                                    uint32_t &cksum2)
{
   /* PseudoHeader must have 36 bytes */
   cksum1 += h[0];
   cksum2 += h[1];
   cksum1 += h[2];
   cksum2 += h[3];
   cksum1 += h[4];
   cksum2 += h[5];
   cksum1 += h[6];
   cksum2 += h[7];
   cksum1 += h[8];
   cksum2 += h[9];
   cksum1 += h[10];
   cksum2 += h[11];
   cksum1 += h[12];
   cksum2 += h[13];
   cksum1 += h[14];
   cksum2 += h[15];
   cksum1 += h[16];
   cksum2 += h[17];
}


static inline void add_tcp_header(const uint16_t* &d,
                                    size_t &len,
                                    uint32_t &cksum1, 
                                    uint32_t &cksum2)
{

    /* TCP hdr must have 20 hdr bytes */
    cksum1 += d[9];
    cksum2 += d[8];
    cksum1 += d[7];
    cksum2 += d[6];
    cksum1 += d[5];
    cksum2 += d[4];
    cksum1 += d[3];
    cksum2 += d[2];
    cksum1 += d[1];
    cksum2 += d[0];
    d += 10;
    len -= 20;
}

static inline void add_udp_header(const uint16_t* &d,
                                    size_t &len,    
                                    uint32_t &cksum1, 
                                    uint32_t &cksum2)
{
   /* UDP must have 8 hdr bytes */
   cksum1 += d[0];
   cksum2 += d[1];
   cksum1 += d[2];
   cksum2 += d[3];
   len -= 8;
   d += 4;
}

 
uint16_t icmp_cksum(const uint16_t *buf, size_t len, Pseudoheader6* ph)
{
    uint32_t cksum1 = 0;
    uint32_t cksum2 = 0;


    add_ipv6_pseudoheader((uint16_t *)ph, cksum1, cksum2);
    return cksum_add(buf, len, cksum1 + cksum2);
}

uint16_t tcp_cksum(const uint16_t *h, size_t len, Pseudoheader *ph )
{
    uint32_t cksum1 = 0;
    uint32_t cksum2 = 0;

    add_ipv4_pseudoheader((uint16_t *)ph, cksum1, cksum2);
    add_tcp_header(h, len, cksum1, cksum2);
    return cksum_add(h, len, cksum1 + cksum2);
}


uint16_t tcp_cksum(const uint16_t *buf, size_t len, Pseudoheader6 *ph )
{
    uint32_t cksum1 = 0;
    uint32_t cksum2 = 0;

    add_ipv6_pseudoheader((uint16_t *)ph, cksum1, cksum2);
    add_tcp_header(buf, len, cksum1, cksum2);
    return cksum_add(buf, len, cksum1 + cksum2);
}


uint16_t udp_cksum(const uint16_t *buf, size_t len, Pseudoheader *ph )
{
    uint32_t cksum1 = 0;
    uint32_t cksum2 = 0;

    add_ipv4_pseudoheader((uint16_t *)ph, cksum1, cksum2);
    add_udp_header(buf, len, cksum1, cksum2);
    return cksum_add(buf, len, cksum1 + cksum2); 
}


uint16_t udp_cksum(const uint16_t *buf, size_t len, Pseudoheader6 *ph )
{
    uint32_t cksum1 = 0;
    uint32_t cksum2 = 0;

    add_ipv6_pseudoheader((uint16_t *)ph, cksum1, cksum2);
    add_udp_header(buf, len, cksum1, cksum2);
    return cksum_add(buf, len, cksum1 + cksum2);
}



// credit belong to dnet.h.  copied directrly from their source code
// src/ip-util.cc
uint16_t cksum_add(const uint16_t *buf, size_t len, uint32_t cksum1)
{
    uint16_t *sp = (uint16_t *)buf;
    int n, sn;
    uint32_t cksum2 = 0;
    uint32_t cksum3 = 0;
    uint32_t cksum4 = 0;

    if (len > 1 )
    {
        sn = ((len / 2) & 0xF);  // len divided by two mod 16 == len/2 % 16
        n = (((len / 2) + 15) / 16) ;  // ceiling of (len / 2) / 16

        switch (sn) {
        case 0:
            sn = 16;
            cksum1 += sp[15];
        case 15:
            cksum2 += sp[14];
        case 14:
            cksum3 += sp[13];
        case 13:
            cksum4 += sp[12];
        case 12:
            cksum1 += sp[11];
        case 11:
            cksum2 += sp[10];
        case 10:
            cksum3 += sp[9];
        case 9:
            cksum4 += sp[8];
        case 8:
            cksum1  += sp[7];
        case 7:
            cksum2 += sp[6];
        case 6:
            cksum3 += sp[5];
        case 5:
            cksum4 += sp[4];
        case 4:
            cksum1 += sp[3];
        case 3:
            cksum2 += sp[2];
        case 2:
            cksum3 += sp[1];
        case 1:
            cksum4 += sp[0];
        }
        sp += sn;


        /* XXX - unroll loop using Duff's device. */
        while (--n > 0) {
            cksum1 += sp[15];
            cksum2 += sp[14];
            cksum3 += sp[13];
            cksum4 += sp[12];
            cksum1 += sp[11];
            cksum2 += sp[10];
            cksum3 += sp[9];
            cksum4 += sp[8];
            cksum1 += sp[7];
            cksum2 += sp[6];
            cksum3 += sp[5];
            cksum4 += sp[4];
            cksum1 += sp[3];
            cksum2 += sp[2];
            cksum3 += sp[1];
            cksum4 += sp[0];
            sp += 16;
        };

        cksum1 += cksum2;
        cksum3 += cksum4;
        cksum1 += cksum3;
    }
    
    if (len & 1)
        cksum1 += (*(unsigned char*)sp);
    
    cksum1  = (cksum1 >> 16) + (cksum1 & 0x0000ffff);
    cksum1 += (cksum1 >> 16);

    return (uint16_t)(~cksum1);
}

} // namespace checksum
