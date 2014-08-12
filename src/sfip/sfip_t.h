/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 1998-2013 Sourcefire, Inc.
** Adam Keeton
** Kevin Liu <kliu@sourcefire.com>
*
** $ID: $
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

/*
 * Adam Keeton
 * sfip_t.h
 * 11/17/06
*/

#ifndef SFIP_T_H
#define SFIP_T_H

#include <stdint.h>

#ifndef WIN32
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

/* factored out for attribute table */

struct sfip_t {
    int16_t family;
    int16_t bits;

    /* see sfip_size(): these address bytes
     * must be the last field in this struct */
    union
    {
        uint8_t  u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
/*      uint64_t    u6_addr64[2]; */
    } ip;
    #define ip8  ip.u6_addr8
    #define ip16 ip.u6_addr16
    #define ip32 ip.u6_addr32
/*    #define ip64 ip.u6_addr64 */

    inline bool is_ip6() const
    { return family == AF_INET6; }

    inline bool is_ip4() const
    { return family == AF_INET; }


};

inline bool operator==(const sfip_t& lhs, const sfip_t& rhs)
{
    if (lhs.is_ip4())
    {
        return  (rhs.is_ip4()) &&
                (lhs.ip.u6_addr32[0] == rhs.ip.u6_addr32[0]);
    }
    else if (lhs.is_ip6())
    {
        return  (rhs.is_ip6()) &&
                (lhs.ip.u6_addr32[0] == rhs.ip.u6_addr32[0]) &&
                (lhs.ip.u6_addr32[1] == rhs.ip.u6_addr32[1]) &&
                (lhs.ip.u6_addr32[2] == rhs.ip.u6_addr32[2]) &&
                (lhs.ip.u6_addr32[3] == rhs.ip.u6_addr32[3]);
    }
    else
    {
        return false;
    }
}

inline bool operator!=(const sfip_t& lhs, const sfip_t& rhs)
{ return !(lhs == rhs); }


#endif

