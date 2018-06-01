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
// checksum.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef CODECS_CHECKSUM_H
#define CODECS_CHECKSUM_H

#include <cstddef>

#include <protocols/protocol_ids.h>

namespace checksum
{
struct Pseudoheader6
{
    uint32_t sip[4];
    uint32_t dip[4];
    uint8_t zero;
    IpProtocol protocol;
    uint16_t len;
};

struct Pseudoheader
{
    uint32_t sip;
    uint32_t dip;
    uint8_t zero;
    IpProtocol protocol;
    uint16_t len;
};

//  calculate the checksum for this general case.
static uint16_t cksum_add(const uint16_t* buf, std::size_t buf_len);
inline uint16_t tcp_cksum(const uint16_t* buf, std::size_t len, const Pseudoheader* const);
inline uint16_t tcp_cksum(const uint16_t* buf, std::size_t len, const Pseudoheader6* const);
inline uint16_t udp_cksum(const uint16_t* buf, std::size_t len, const Pseudoheader* const);
inline uint16_t udp_cksum(const uint16_t* buf, std::size_t len, const Pseudoheader6* const);
inline uint16_t icmp_cksum(const uint16_t* buf, std::size_t len, const Pseudoheader6* const);
inline uint16_t icmp_cksum(const uint16_t* buf, std::size_t len);
inline uint16_t ip_cksum(const uint16_t* buf, std::size_t len);

/*
 *  NOTE: Since multiple dynamic libraries use checksums, the choice
 *          is to either include all of the checksum details in a header,
 *          or ensure I include these symbols for every linker which
 *          can be used. Obviously, setting correct linker flags is
 *          significantly more difficult, so these functions will all
 *          stay in a header file
 */

/*
 *  IT IS HIGHLY RECOMMENDED to use the above API. Rathern than calling
 *  any of of the following recommendations directly
 */
namespace detail
{
struct PsuedoheaderUnion
{
    union
    {
        Pseudoheader ph4;
        uint16_t ph4_arr[12];
    };
};

struct Psuedoheader6Union
{
    union
    {
        Pseudoheader ph6;
        uint16_t ph6_arr[18];
    };
};

inline uint16_t cksum_add(const uint16_t* buf, std::size_t len, uint32_t cksum)
{
    const uint16_t* sp = buf;

    // if pointer is 16 bit aligned calculate checksum in tight loop...
    // gcc 5.4 -O3 generates unaligned quadword instructions that crash; fixed in gcc 8.0.1
    if ( !( reinterpret_cast<std::uintptr_t>(sp) & 0x01 ) )
    {
        while ( len > 1 )
        {
            cksum += *sp++;
            len -= 2;
        }
        // if len was odd, sum in the last byte...
        if ( len )
            cksum += (uint16_t) *(const uint8_t *)sp;
    }
    else if ( len > 1 )
    {
        std::size_t sn = ((len / 2) & 0xF);  // == len/2 % 16
        std::size_t n = (((len / 2) + 15) / 16);   // ceiling of (len / 2) / 16

        switch (sn)
        {
        case 0:
            sn = 16;
            cksum += sp[15];    // fallthrough
        case 15:
            cksum += sp[14];    // fallthrough
        case 14:
            cksum += sp[13];    // fallthrough
        case 13:
            cksum += sp[12];    // fallthrough
        case 12:
            cksum += sp[11];    // fallthrough
        case 11:
            cksum += sp[10];    // fallthrough
        case 10:
            cksum += sp[9];     // fallthrough
        case 9:
            cksum += sp[8];     // fallthrough
        case 8:
            cksum  += sp[7];    // fallthrough
        case 7:
            cksum += sp[6];     // fallthrough
        case 6:
            cksum += sp[5];     // fallthrough
        case 5:
            cksum += sp[4];     // fallthrough
        case 4:
            cksum += sp[3];     // fallthrough
        case 3:
            cksum += sp[2];     // fallthrough
        case 2:
            cksum += sp[1];     // fallthrough
        case 1:
            cksum += sp[0];
        }
        sp += sn;

        /* XXX - unroll loop using Duff's device. */
        while (--n > 0)
        {
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
        }
        // if len is odd, sum in the last byte...
        if ( len & 0x01)
            cksum += (uint16_t) *(const uint8_t *)sp;
    }

    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

inline void add_ipv4_pseudoheader(const Pseudoheader* const ph4,
    uint32_t& cksum)
{
    /*
     * This mess is necessary to make static analyzers happy.
     * Otherwise they assume we are reading garbage values
     */
    const PsuedoheaderUnion* const ph4_u = reinterpret_cast
        <const PsuedoheaderUnion*>(ph4);
    const uint16_t* const h = ph4_u->ph4_arr;

    /* ipv4 pseudo header must have 12 bytes */
    cksum += h[0];
    cksum += h[1];
    cksum += h[2];
    cksum += h[3];
    cksum += h[4];
    cksum += h[5];
}

inline void add_ipv6_pseudoheader(const Pseudoheader6* const ph6,
    uint32_t& cksum)
{
    /*
     * This mess is necessary to make static analyzers happy.
     * Otherwise they assume we are reading garbage values
     */
    const Psuedoheader6Union* const ph6_u = reinterpret_cast
        <const Psuedoheader6Union*>(ph6);
    const uint16_t* const h = ph6_u->ph6_arr;

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

inline void add_tcp_header(const uint16_t*& d,
    std::size_t& len,
    uint32_t& cksum)
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

inline void add_udp_header(const uint16_t*& d,
    size_t& len,
    uint32_t& cksum)
{
    /* UDP must have 8 hdr bytes */
    cksum += d[0];
    cksum += d[1];
    cksum += d[2];
    cksum += d[3];
    len -= 8;
    d += 4;
}

inline void add_ip_header(const uint16_t*& d,
    std::size_t& len,
    uint32_t& cksum)
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
} // namespace detail

inline uint16_t icmp_cksum(const uint16_t* buf,
    std::size_t len,
    const Pseudoheader6* const ph)
{
    uint32_t cksum = 0;

    detail::add_ipv6_pseudoheader(ph, cksum);
    return detail::cksum_add(buf, len, cksum);
}

inline uint16_t icmp_cksum(const uint16_t* buf, size_t len)
{
    return detail::cksum_add(buf, len, 0);
}

inline uint16_t tcp_cksum(const uint16_t* h,
    std::size_t len,
    const Pseudoheader* const ph)
{
    uint32_t cksum = 0;

    detail::add_ipv4_pseudoheader(ph, cksum);
    detail::add_tcp_header(h, len, cksum);
    return detail::cksum_add(h, len, cksum);
}

inline uint16_t tcp_cksum(const uint16_t* buf,
    std::size_t len,
    const Pseudoheader6* const ph)
{
    uint32_t cksum = 0;

    detail::add_ipv6_pseudoheader(ph, cksum);
    detail::add_tcp_header(buf, len, cksum);
    return detail::cksum_add(buf, len, cksum);
}

inline uint16_t udp_cksum(const uint16_t* buf,
    std::size_t len,
    const Pseudoheader* const ph)
{
    uint32_t cksum = 0;

    detail::add_ipv4_pseudoheader(ph, cksum);
    detail::add_udp_header(buf, len, cksum);
    return detail::cksum_add(buf, len, cksum);
}

inline uint16_t udp_cksum(const uint16_t* buf,
    std::size_t len,
    const Pseudoheader6* const ph)
{
    uint32_t cksum = 0;

    detail::add_ipv6_pseudoheader(ph, cksum);
    detail::add_udp_header(buf, len, cksum);
    return detail::cksum_add(buf, len, cksum);
}

inline uint16_t ip_cksum(const uint16_t* buf, std::size_t len)
{
    uint32_t cksum = 0;

    detail::add_ip_header(buf, len, cksum);
    return detail::cksum_add(buf, len, cksum);
}

inline uint16_t cksum_add(const uint16_t* buf, std::size_t len)
{ return detail::cksum_add(buf, len, 0); }
} // namespace checksum

#endif  /* CODECS_CHECKSUM_H */

