/*  
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2007-2013 Sourcefire, Inc.
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
** along with this program; if nto, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
** USA
*/

#ifndef SF_IPH_H
#define SF_IPH_H

#include "sfip_t.h"

struct Packet;

typedef struct _IPH_API
{
    sfip_t *   (*iph_ret_src)(const Packet*);
    sfip_t *   (*iph_ret_dst)(const Packet*);
    uint16_t   (*iph_ret_tos)(const Packet*);
    uint8_t    (*iph_ret_ttl)(const Packet*);
    uint16_t   (*iph_ret_len)(const Packet*);
    uint32_t   (*iph_ret_id)(const Packet*);
    uint8_t    (*iph_ret_proto)(const Packet*);
    uint16_t   (*iph_ret_off)(const Packet*);
    uint8_t    (*iph_ret_ver)(const Packet*);
    uint8_t    (*iph_ret_hlen)(const Packet*);

    sfip_t *   (*orig_iph_ret_src)(const Packet*);
    sfip_t *   (*orig_iph_ret_dst)(const Packet*);
    uint16_t   (*orig_iph_ret_tos)(const Packet*);
    uint8_t    (*orig_iph_ret_ttl)(const Packet*);
    uint16_t   (*orig_iph_ret_len)(const Packet*);
    uint32_t   (*orig_iph_ret_id)(const Packet*);
    uint8_t    (*orig_iph_ret_proto)(const Packet*);
    uint16_t   (*orig_iph_ret_off)(const Packet*);
    uint8_t    (*orig_iph_ret_ver)(const Packet*);
    uint8_t    (*orig_iph_ret_hlen)(const Packet*);

    char ver;
} IPH_API;

extern IPH_API ip4;
extern IPH_API ip6;

#define IPH_API_V4 4
#define IPH_API_V6 6

#define iph_is_valid(p) ((p)->family != NO_IP)
#define NO_IP 0

void sfiph_build(Packet*, const void *hdr, int family);
void sfiph_orig_build(Packet*, const void *hdr, int family);

/* Sets the callbacks to point at the family selected by
 *  * "family".  "family" is either AF_INET or AF_INET6 */
#define CALLBACK_IP 0
#define CALLBACK_ICMP_ORIG 1

void set_callbacks(Packet*, int family, char orig);

#endif
