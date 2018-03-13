//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// file stream_ip.h author Russ Combs <rcombs@sourcefire.com>

#ifndef STREAM_IP_H
#define STREAM_IP_H

#include "framework/inspector.h"

/* engine-based defragmentation policy enums */
// must update stream.h::IP_POLICIES if this changes
enum
{
    FRAG_POLICY_FIRST = 1,
    FRAG_POLICY_LINUX,
    FRAG_POLICY_BSD,
    FRAG_POLICY_BSD_RIGHT,
    FRAG_POLICY_LAST,
/* Combo of FIRST & LAST, depending on overlap situation. */
    FRAG_POLICY_WINDOWS,
/* Combo of FIRST & LAST, depending on overlap situation. */
    FRAG_POLICY_SOLARIS
};

#define FRAG_POLICY_DEFAULT FRAG_POLICY_LINUX

struct FragEngine
{
    uint32_t max_frags;
    uint32_t max_overlaps;
    uint32_t min_fragment_length;

    uint32_t frag_timeout; /* timeout for frags in this policy */
    uint16_t frag_policy;  /* policy to use for engine-based reassembly */

    uint8_t min_ttl;       /* Minimum TTL to accept */

    FragEngine();
};

struct StreamIpConfig
{
    FragEngine frag_engine;
    uint32_t session_timeout;

    StreamIpConfig();
};

StreamIpConfig* get_ip_cfg(snort::Inspector*);
class Defrag* get_defrag(snort::Inspector*);

#endif

