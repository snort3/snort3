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

#ifndef SFIP_SFIP_T_H
#define SFIP_SFIP_T_H

#include <cstddef>
#include <stdint.h>
#include <arpa/inet.h>

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
        uint8_t  ip8[16];
        uint16_t ip16[8];
        uint32_t ip32[4];
/*      uint64_t    ip64[2]; */
    };

    inline bool is_ip6() const
    { return family == AF_INET6; }

    inline bool is_ip4() const
    { return family == AF_INET; }

    // the '+ 4' is the int32_t IPv4 address
    inline std::size_t sfip_size() const
    { return is_ip6() ? sizeof(sfip_t) : offsetof(sfip_t, ip8) + 4; }

};

/*
 * Implementing these functions rather than implenting opeators since
 * the Google style guide recomends staying away from
 * operators.  Most of these are a copy and paste from sf_ip.h
 */
static inline int sfip_is_set(const sfip_t& ip);
static inline int sfip_is_set(const sfip_t* const ip);
static inline bool sfip_equals(const sfip_t* const lhs, const sfip_t* const rhs);
static inline bool sfip_unset_equals(const sfip_t* const lhs, const sfip_t* const rhs);
static inline bool sfip_not_equals(const sfip_t* const lhs, const sfip_t* const rhs);
static inline bool sfip_lesser(const sfip_t* const lhs, const sfip_t* const rhs);
static inline bool sfip_greater(const sfip_t* const lhs, const sfip_t* const rhs);
static inline void sfip_clear(sfip_t& x);
static inline void sfip_copy(sfip_t& lhs, const sfip_t* const rhs);



// because we can --- and this is leftover from Snort which we're stuck with
#ifdef inet_ntoa
#undef inet_ntoa
#endif

char *sfip_to_str(const sfip_t *ip);
#define sfip_ntoa(x) sfip_to_str(x)
#define inet_ntoa sfip_ntoa


/* Returns 1 if the IP is non-zero. 0 otherwise *
 * XXX This is a performance critical function,
 *  need to determine if it's safe to not check these pointers
 *
 * SNORT RELIC
 */
static inline int sfip_is_set(const sfip_t* const ip) {
//    ARG_CHECK1(ip, -1);
    return ip->ip32[0] ||
            ( (ip->family == AF_INET6) &&
              (ip->ip32[1] ||
              ip->ip32[2] ||
              ip->ip32[3] || ip->bits != 128)) || ((ip->family == AF_INET) && ip->bits != 32)  ;
}

static inline int sfip_is_set(const sfip_t& ip) {
//    ARG_CHECK1(ip, -1);
    return ip.ip32[0] ||
            ( (ip.family == AF_INET6) &&
              (ip.ip32[1] ||
              ip.ip32[2] ||
              ip.ip32[3] || ip.bits != 128)) || ((ip.family == AF_INET) && ip.bits != 32)  ;
}



static inline bool _is_sfip_equals(const sfip_t* const lhs, const sfip_t* const rhs)
{
    if (lhs->is_ip4())
    {
        return  (rhs->is_ip4()) &&
                (lhs->ip32[0] == rhs->ip32[0]);
    }
    else if (lhs->is_ip6())
    {
        return  (rhs->is_ip6()) &&
                (lhs->ip32[0] == rhs->ip32[0]) &&
                (lhs->ip32[1] == rhs->ip32[1]) &&
                (lhs->ip32[2] == rhs->ip32[2]) &&
                (lhs->ip32[3] == rhs->ip32[3]);
    }
    else
    {
        return false;
    }
}


static inline bool _is_sfip_lesser(const sfip_t* const lhs, const sfip_t* const rhs)
{
    if (lhs->is_ip4())
    {
        return (rhs->is_ip4() &&
               (htonl(lhs->ip32[0]) < htonl(rhs->ip32[0])));
    }
    else if (lhs->is_ip6())
    {
        return (rhs->is_ip6() &&
               (htonl(lhs->ip32[0]) < htonl(rhs->ip32[0])) &&
               (htonl(lhs->ip32[1]) < htonl(rhs->ip32[1])) &&
               (htonl(lhs->ip32[2]) < htonl(rhs->ip32[2])) &&
               (htonl(lhs->ip32[3]) < htonl(rhs->ip32[3])));
    }
    else
    {
        return false;
    }
}


static inline bool sfip_equals(const sfip_t* const lhs, const sfip_t* const rhs)
{
    if(!sfip_is_set(lhs) || !sfip_is_set(rhs))
        return true;

    return _is_sfip_equals(lhs, rhs);
}


static inline bool sfip_not_equals(const sfip_t* const lhs, const sfip_t* const rhs)
{ return !sfip_equals(lhs,rhs); }


static inline bool sfip_unset_equals(const sfip_t* const lhs, const sfip_t* const rhs)
{
    if(!sfip_is_set(lhs) || !sfip_is_set(rhs))
        return false;

    return _is_sfip_equals(lhs, rhs);
}


static inline bool sfip_lesser(const sfip_t* const lhs, const sfip_t* const rhs)
{
    // I'm copying and pasting.  Don't ask me why this is different then sfip_equals
    if(!sfip_is_set(lhs) || !sfip_is_set(rhs))
        return false;

    return _is_sfip_lesser(lhs, rhs);
}


static inline bool sfip_greater(const sfip_t* const lhs, const sfip_t* const rhs)
{
    // I'm copying and pasting.  Don't ask me why this is different then sfip_equals
    if(!sfip_is_set(lhs) || !sfip_is_set(rhs))
        return false;

    return _is_sfip_lesser(rhs, lhs);
}


static inline void sfip_clear(sfip_t& x)
{
    x.family = 0;
    x.bits = 0;
    x.ip32[0] = 0;
    x.ip32[1] = 0;
    x.ip32[2] = 0;
    x.ip32[3] = 0;
}

/*
 * This is the former macro IP_COPY_VALUE(x, y).  No need to assign
 * specific operator since the default equals operator will
 * correctly assign values
 */
static inline void sfip_copy(sfip_t& lhs, const sfip_t* const rhs)
{ lhs = *rhs; }

#endif

