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


#ifndef PROTOCOLS_UDP_H
#define PROTOCOLS_UDP_H

#include <cstdint>


/* otherwise defined in /usr/include/ppp_defs.h */
// FIXIT udph should not be set for udp tunnel
// (only if innermost layer == udp)
#define IsUDP(p) (IsIP(p) && !IsTCP(p) && p->udph)


namespace udp
{

constexpr uint8_t UDP_HEADER_LEN = 8;

struct UDPHdr
{
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_len;
    uint16_t uh_chk;
};


} // namespace

#endif
