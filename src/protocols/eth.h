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


#ifndef ETH_H
#define ETH_H


#define ETHERNET_HEADER_LEN 14
#define ETHERNET_MTU                  1500

namespace eth
{



namespace detail
{
const uint16_t HEADER_LEN = 14;
const uint16_t MTU_LEN = 1500;
const uint16_t MAX_FRAME_LENGTH = 1500;
const uint16_t MIN_ETHERTYPE = 1536;
} // namespace detail

struct EtherHdr
{
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;

};

inline uint16_t hdr_len()
{
    return detail::HEADER_LEN;
} 

inline uint16_t mtu_len()
{
    return detail::MTU_LEN;
}

inline uint16_t min_ethertype()
{
    return detail::MIN_ETHERTYPE;
}

inline uint16_t max_frame_length()
{   
    return detail::MAX_FRAME_LENGTH;
}

} // namespace eth


#endif

