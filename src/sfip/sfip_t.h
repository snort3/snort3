//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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

/*
 * Adam Keeton
 * sfip_t.h
 * 11/17/06
*/

#ifndef SFIP_SFIP_T_H
#define SFIP_SFIP_T_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstddef>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "main/snort_types.h"

/* factored out for attribute table */

struct sfip_t
{
    int16_t family;
    int16_t bits;

    /* see sfip_size(): these address bytes
     * must be the last field in this struct */
    union
    {
        uint8_t ip8[16];
        uint16_t ip16[8];
        uint32_t ip32[4];
/*      uint64_t    ip64[2]; */
    };

    inline void clear()
    {
        family = bits = 0;
        ip32[0] = ip32[1] = ip32[2] = ip32[3] = 0;
    }

    inline bool is_ip6() const
    { return family == AF_INET6; }

    inline bool is_ip4() const
    { return family == AF_INET; }

    // the '+ 4' is the int32_t IPv4 address
    inline std::size_t sfip_size() const
    { return is_ip6() ? sizeof(sfip_t) : offsetof(sfip_t, ip8) + 4; }
};

// This is leftover from Snort which we're stuck with
#ifdef inet_ntoa
#undef inet_ntoa
#endif
// FIXIT-H replace all inet_ntoa() with sfip_to_str() and delete redef
SO_PUBLIC char* sfip_to_str(const sfip_t*);
#define sfip_ntoa(x) sfip_to_str(x)
#define inet_ntoa sfip_ntoa

#endif

