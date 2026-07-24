//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
#include <cstring>

#include <protocols/protocol_ids.h>

namespace checksum
{
union Pseudoheader
{
    struct
    {
        uint32_t sip;
        uint32_t dip;
        uint8_t zero;
        IpProtocol protocol;
        uint16_t len;
    } hdr;
    uint16_t arr[6];
    static_assert(sizeof(hdr) == sizeof(arr), "IPv4 pseudoheader must be 12 bytes");
};

union Pseudoheader6
{
    struct
    {
        uint32_t sip[4];
        uint32_t dip[4];
        uint8_t zero;
        IpProtocol protocol;
        uint16_t len;
    } hdr;
    uint16_t arr[18];
    static_assert(sizeof(hdr) == sizeof(arr), "IPv6 pseudoheader must be 36 bytes");
};

//  calculate the checksum for this general case.
static uint16_t cksum_add(const void* buf, std::size_t buf_len);
inline uint16_t tcp_cksum(const void* buf, std::size_t len, const Pseudoheader&);
inline uint16_t tcp_cksum(const void* buf, std::size_t len, const Pseudoheader6&);
inline uint16_t udp_cksum(const void* buf, std::size_t len, const Pseudoheader&);
inline uint16_t udp_cksum(const void* buf, std::size_t len, const Pseudoheader6&);
inline uint16_t icmp_cksum(const void* buf, std::size_t len, const Pseudoheader6&);
inline uint16_t icmp_cksum(const void* buf, std::size_t len);
inline uint16_t ip_cksum(const void* buf, std::size_t len);

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
inline uint16_t read_word(const uint8_t* data)
{
    uint16_t word;
    std::memcpy(&word, data, sizeof(word));
    return word;
}

inline uint16_t cksum_add(const void* buf, std::size_t len, uint32_t cksum)
{
    const uint8_t* data = static_cast<const uint8_t*>(buf);

    while ( len > 1 )
    {
        cksum += read_word(data);
        data += sizeof(uint16_t);
        len -= sizeof(uint16_t);
    }

    // if len is odd, sum in the last byte...
    if ( len & 0x01 )
        cksum += *data;

    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

inline void add_ipv4_pseudoheader(const Pseudoheader& ph4, uint32_t& cksum)
{
    const uint16_t* h = ph4.arr;

    /* ipv4 pseudo header must have 12 bytes */
    cksum += h[0];
    cksum += h[1];
    cksum += h[2];
    cksum += h[3];
    cksum += h[4];
    cksum += h[5];
}

inline void add_ipv6_pseudoheader(const Pseudoheader6& ph6, uint32_t& cksum)
{
    const uint16_t* h = ph6.arr;

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

inline void add_tcp_header(const uint8_t*& d,
    std::size_t& len,
    uint32_t& cksum)
{
    /* TCP hdr must have 20 hdr bytes */
    for (unsigned i = 0; i < 20; i += sizeof(uint16_t))
        cksum += read_word(d + i);
    d += 20;
    len -= 20;
}

inline void add_udp_header(const uint8_t*& d,
    size_t& len,
    uint32_t& cksum)
{
    /* UDP must have 8 hdr bytes */
    for (unsigned i = 0; i < 8; i += sizeof(uint16_t))
        cksum += read_word(d + i);
    len -= 8;
    d += 8;
}

inline void add_ip_header(const uint8_t*& d,
    std::size_t& len,
    uint32_t& cksum)
{
    /* IP must be >= 20 bytes */
    for (unsigned i = 0; i < 20; i += sizeof(uint16_t))
        cksum += read_word(d + i);
    d += 20;
    len -= 20;
}
} // namespace detail

inline uint16_t icmp_cksum(const void* buf,
    std::size_t len,
    const Pseudoheader6& ph)
{
    uint32_t cksum = 0;

    detail::add_ipv6_pseudoheader(ph, cksum);
    return detail::cksum_add(buf, len, cksum);
}

inline uint16_t icmp_cksum(const void* buf, size_t len)
{
    return detail::cksum_add(buf, len, 0);
}

inline uint16_t tcp_cksum(const void* buf,
    std::size_t len,
    const Pseudoheader& ph)
{
    uint32_t cksum = 0;

    detail::add_ipv4_pseudoheader(ph, cksum);
    const uint8_t* data = static_cast<const uint8_t*>(buf);
    detail::add_tcp_header(data, len, cksum);
    return detail::cksum_add(data, len, cksum);
}

inline uint16_t tcp_cksum(const void* buf,
    std::size_t len,
    const Pseudoheader6& ph)
{
    uint32_t cksum = 0;

    detail::add_ipv6_pseudoheader(ph, cksum);
    const uint8_t* data = static_cast<const uint8_t*>(buf);
    detail::add_tcp_header(data, len, cksum);
    return detail::cksum_add(data, len, cksum);
}

inline uint16_t udp_cksum(const void* buf,
    std::size_t len,
    const Pseudoheader& ph)
{
    uint32_t cksum = 0;

    detail::add_ipv4_pseudoheader(ph, cksum);
    const uint8_t* data = static_cast<const uint8_t*>(buf);
    detail::add_udp_header(data, len, cksum);
    return detail::cksum_add(data, len, cksum);
}

inline uint16_t udp_cksum(const void* buf,
    std::size_t len,
    const Pseudoheader6& ph)
{
    uint32_t cksum = 0;

    detail::add_ipv6_pseudoheader(ph, cksum);
    const uint8_t* data = static_cast<const uint8_t*>(buf);
    detail::add_udp_header(data, len, cksum);
    return detail::cksum_add(data, len, cksum);
}

inline uint16_t ip_cksum(const void* buf, std::size_t len)
{
    uint32_t cksum = 0;

    const uint8_t* data = static_cast<const uint8_t*>(buf);
    detail::add_ip_header(data, len, cksum);
    return detail::cksum_add(data, len, cksum);
}

inline uint16_t cksum_add(const void* buf, std::size_t len)
{ return detail::cksum_add(buf, len, 0); }
} // namespace checksum

#endif  /* CODECS_CHECKSUM_H */
