//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// dns_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef DNS_MODULE_H
#define DNS_MODULE_H
//Interface to the DNS service inspector

#include "framework/bits.h"
#include "framework/module.h"
#include "main/thread.h"

namespace snort
{
struct SnortConfig;
}

#define GID_DNS 131

#define DNS_EVENT_OBSOLETE_TYPES            1
#define DNS_EVENT_EXPERIMENTAL_TYPES        2
#define DNS_EVENT_RDATA_OVERFLOW            3

#define DNS_NAME "dns"
#define DNS_HELP "dns inspection"


struct DnsStats
{
    PegCount packets;
    PegCount requests;
    PegCount responses;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

extern const PegInfo dns_peg_names[];
extern THREAD_LOCAL DnsStats dnsstats;
extern THREAD_LOCAL snort::ProfileStats dnsPerfStats;

class DnsModule : public snort::Module
{
public:
    DnsModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override
    { return false; }

    unsigned get_gid() const override
    { return GID_DNS; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }
};

#endif
