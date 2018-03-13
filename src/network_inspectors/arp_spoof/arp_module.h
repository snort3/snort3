//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// arp_module.h author Russ Combs <rucombs@cisco.com>

#ifndef ARP_SPOOF_MODULE_H
#define ARP_SPOOF_MODULE_H

#include "framework/module.h"

#define MOD_NAME "arp_spoof"
#define MOD_HELP "detect ARP attacks and anomalies"

#define GID_ARP_SPOOF 112

#define ARPSPOOF_UNICAST_ARP_REQUEST          1
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC  2
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST  3
#define ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK   4

extern THREAD_LOCAL SimpleStats asstats;
extern THREAD_LOCAL snort::ProfileStats arpPerfStats;

struct IPMacEntry
{
    uint32_t ipv4_addr;
    uint8_t mac_addr[6];
};

typedef std::vector<IPMacEntry> IPMacEntryList;

struct ArpSpoofConfig
{
    bool check_overwrite;

    IPMacEntryList ipmel;
};

class ArpSpoofModule : public snort::Module
{
public:
    ArpSpoofModule();
    ~ArpSpoofModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    ArpSpoofConfig* get_config();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    unsigned get_gid() const override
    { return GID_ARP_SPOOF; }

    const snort::RuleMap* get_rules() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return INSPECT; }

private:
    ArpSpoofConfig* config;
    IPMacEntry host;
};

#endif

