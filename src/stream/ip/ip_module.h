/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// ip_module.h author Russ Combs <rucombs@cisco.com>

#ifndef IP_MODULE_H
#define IP_MODULE_H

#include "snort_types.h"
#include "framework/module.h"
#include "main/thread.h"

struct SnortConfig;

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

extern THREAD_LOCAL ProfileStats ip_perf_stats;
extern THREAD_LOCAL ProfileStats fragPerfStats;
extern THREAD_LOCAL ProfileStats fragInsertPerfStats;
extern THREAD_LOCAL ProfileStats fragRebuildPerfStats;

//-------------------------------------------------------------------------
// stream_ip module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_ip"

struct StreamIpConfig;

class StreamIpModule : public Module
{
public:
    StreamIpModule();
    ~StreamIpModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

    const RuleMap* get_rules() const;
    ProfileStats* get_profile(unsigned, const char*&, const char*&) const;
    StreamIpConfig* get_data();

private:
    StreamIpConfig* config;
};

#endif

