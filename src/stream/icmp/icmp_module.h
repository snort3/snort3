//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// icmp_module.h author Russ Combs <rucombs@cisco.com>

#ifndef ICMP_MODULE_H
#define ICMP_MODULE_H

#include "flow/session.h"
#include "framework/module.h"

extern const PegInfo icmp_pegs[];
extern THREAD_LOCAL struct IcmpStats icmpStats;
extern THREAD_LOCAL ProfileStats icmp_perf_stats;

struct SnortConfig;

struct IcmpStats
{
    SESSION_STATS;
};

struct IcmpStatTypes
{
    SESSION_STAT_TYPES;

    IcmpStatTypes() {}
};

//-------------------------------------------------------------------------
// stream_icmp module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_icmp"
#define MOD_HELP "stream inspector for ICMP flow tracking"

struct StreamIcmpConfig;

class StreamIcmpModule : public Module
{
public:
    StreamIcmpModule();
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    void sum_stats(bool) override;

    StreamIcmpConfig* get_data();

private:
    StreamIcmpConfig* config;
};

#endif

