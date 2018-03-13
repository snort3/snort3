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
// udp.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_UDP_H
#define PROTOCOLS_UDP_H

#include <arpa/inet.h>

namespace snort
{
namespace udp
{
constexpr uint8_t UDP_HEADER_LEN = 8;

struct UDPHdr
{
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_len;
    uint16_t uh_chk;

    /*  formatted access to fields */
    inline uint16_t src_port() const
    { return ntohs(uh_sport); }

    inline uint16_t dst_port() const
    { return ntohs(uh_dport); }

    inline uint16_t len() const
    { return ntohs(uh_len); }

    inline uint16_t cksum() const
    { return ntohs(uh_chk); }

    /*  Raw access to fields */
    inline uint16_t raw_src_port() const
    { return uh_sport; }

    inline uint16_t raw_dst_port() const
    { return uh_dport; }

    inline uint16_t raw_len() const
    { return uh_len; }

    inline uint16_t raw_cksum() const
    { return uh_chk; }
};
} // namespace udp
} // namespace snort

#endif

