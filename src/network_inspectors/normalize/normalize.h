/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2010-2013 Sourcefire, Inc.
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

#ifndef NORMALIZE_H
#define NORMALIZE_H

#include <stdint.h>
#include "main/policy.h"

// these control protocol specific normalizations all are enables except
// tcp_urp which is enabled with tcp core and disabled explicitly.

typedef enum {
    NORM_IP4             = 0x00000001, // core ip4 norms
  //NORM_IP4_ID          = 0x00000002, // tbd:  encrypt ip id
    NORM_IP4_DF          = 0x00000004, // clear df
    NORM_IP4_RF          = 0x00000008, // clear rf
    NORM_IP4_TTL         = 0x00000010, // ensure min ttl
    NORM_ICMP4           = 0x00000020, // core icmp4 norms
    NORM_IP6             = 0x00000040, // core ip6 norms
    NORM_IP6_TTL         = 0x00000080, // ensure min hop limit
    NORM_ICMP6           = 0x00000100, // core icmp6 norms
    NORM_TCP             = 0x00000200, // core tcp norms
    NORM_TCP_ECN_PKT     = 0x00000400, // clear ece and cwr
    NORM_TCP_ECN_STR     = 0x00000800, // clear if not negotiated (stream)
    NORM_TCP_URP         = 0x00001000, // trim urp to dsize
    NORM_TCP_OPT         = 0x00002000, // nop over non-essential options
    NORM_TCP_IPS         = 0x00004000, // enable stream normalization/pre-ack flushing
    NORM_IP4_TOS         = 0x00008000, // clear tos/diff-serv
    NORM_IP4_TRIM        = 0x00010000, // enforce min frame
    NORM_TCP_TRIM        = 0x00020000, // enforce min frame
    NORM_ALL             = 0x0003FFFF  // all normalizations on
} NormFlags;

static inline int Normalize_IsEnabled(NormFlags nf)
{
    InspectionPolicy* pi = get_inspection_policy();
    return ( (pi->normal_mask & nf) != 0 );
}

#endif

