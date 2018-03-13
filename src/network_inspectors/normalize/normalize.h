//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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

#ifndef NORMALIZE_H
#define NORMALIZE_H

#include "framework/counts.h"

// these control protocol specific normalizations
enum NormFlags
{
    NORM_IP4_BASE        = 0x00000001, // core ip4 norms
    //NORM_IP4_ID          = 0x00000002, // tbd:  encrypt ip id
    NORM_IP4_DF          = 0x00000004, // clear df
    NORM_IP4_RF          = 0x00000008, // clear rf
    NORM_IP4_TTL         = 0x00000010, // ensure min ttl
    NORM_IP4_TOS         = 0x00000020, // clear tos/diff-serv
    NORM_IP4_TRIM        = 0x00000040, // enforce min frame

    NORM_IP6_BASE        = 0x00000100, // core ip6 norms
    NORM_IP6_TTL         = 0x00000200, // ensure min hop limit
    NORM_ICMP4           = 0x00000400, // core icmp4 norms
    NORM_ICMP6           = 0x00000800, // core icmp6 norms

    NORM_TCP_ECN_PKT     = 0x00001000, // clear ece and cwr
    NORM_TCP_ECN_STR     = 0x00002000, // clear if not negotiated (stream)
    NORM_TCP_URP         = 0x00004000, // trim urp to dsize
    NORM_TCP_OPT         = 0x00008000, // nop over non-essential options
    NORM_TCP_IPS         = 0x00010000, // enable stream normalization/pre-ack flushing

    NORM_TCP_TRIM_SYN    = 0x00020000, // strip data from syn
    NORM_TCP_TRIM_RST    = 0x00040000, // strip data from rst
    NORM_TCP_TRIM_WIN    = 0x00080000, // trim to window
    NORM_TCP_TRIM_MSS    = 0x00100000, // trim to mss

    NORM_TCP_BLOCK       = 0x00200000, // enable tcp norms (used for normalizer indexing)
    NORM_TCP_RSV         = 0x00400000, // clear reserved bits
    NORM_TCP_PAD         = 0x00800000, // clear option padding bytes
    NORM_TCP_REQ_URG     = 0x01000000, // clear URP if URG = 0
    NORM_TCP_REQ_PAY     = 0x02000000, // clear URP/URG on no payload
    NORM_TCP_REQ_URP     = 0x04000000, // clear URG if URP is not set
    NORM_ALL             = 0xFFFFFFFF,  // all normalizations on
};

enum NormMode : int8_t
{
    NORM_MODE_TEST,
    NORM_MODE_ON,
    NORM_MODE_MAX
};

typedef PegCount (* NormPegs)[NORM_MODE_MAX];

bool Normalize_IsEnabled(NormFlags);
NormMode Normalize_GetMode(NormFlags);

#define NORM_IP4_ANY (0xFF)
#define NORM_IP6_ANY (NORM_IP6_BASE|NORM_IP6_TTL)
#define NORM_TCP_ANY (0xFF000)

#endif

