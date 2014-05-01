/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2004-2013 Sourcefire, Inc.
** Copyright (C) 1998-2004 Martin Roesch <roesch@sourcefire.com>
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

// defrag_module.h author Russ Combs <rucombs@cisco.com>

#ifndef DEFRAG_MODULE_H
#define DEFRAG_MODULE_H

#include <stdint.h>
#include "framework/module.h"

#define GLOBAL_KEYWORD "defrag"
#define ENGINE_KEYWORD "defrag_engine"

#define GID_DEFRAG     123

#define DEFRAG_IPOPTIONS           1
#define DEFRAG_TEARDROP            2
#define DEFRAG_SHORT_FRAG          3
#define DEFRAG_ANOMALY_OVERSIZE    4
#define DEFRAG_ANOMALY_ZERO        5
#define DEFRAG_ANOMALY_BADSIZE_SM  6
#define DEFRAG_ANOMALY_BADSIZE_LG  7
#define DEFRAG_ANOMALY_OVLP        8

/* 123:9, 123:10 are OBE w/ addition of 116:458
 * (aka DECODE_IPV6_BAD_FRAG_PKT).
 * Leave these here so they are not reused.
 * ------
#define DEFRAG_IPV6_BSD_ICMP_FRAG  9
#define DEFRAG_IPV6_BAD_FRAG_PKT  10
 * ------
*/
#define DEFRAG_MIN_TTL_EVASION    11
#define DEFRAG_EXCESSIVE_OVERLAP  12
#define DEFRAG_TINY_FRAGMENT      13

struct FragCommon
{
    uint32_t max_frags;
    uint32_t static_frags;
    unsigned long memcap;

    bool use_prealloc;
    bool use_prealloc_frags;

    int ten_percent;                 /* holder for self preservation data */

    FragCommon();
};

/* specific instance of an engine */
struct FragEngine
{
    // max fragments before excessive fragmentation event is generated.
    uint32_t overlap_limit;

    // Fragment that is too small to be legal
    uint32_t min_fragment_length;

    uint32_t frag_timeout; /* timeout for frags in this policy */
    uint16_t frag_policy;  /* policy to use for engine-based reassembly */

    uint8_t min_ttl;       /* Minimum TTL to accept */
    bool detect;      /* Whether or not alerts are enabled */

    FragEngine();
};

class DefragModule : public Module
{
public:
    DefragModule();
    ~DefragModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

    FragCommon* get_data();

private:
    FragCommon* common;
};

class DefragEngineModule : public Module
{
public:
    DefragEngineModule();
    ~DefragEngineModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

    unsigned get_gid() const
    { return GID_DEFRAG; };

    FragEngine* get_data();

private:
    FragEngine* engine;
};

#endif

