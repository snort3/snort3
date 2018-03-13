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

// ps_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PS_MODULE_H
#define PS_MODULE_H

#include "framework/module.h"
#include "ps_detect.h"

#define PS_NAME "port_scan"
#define PS_HELP "detect various ip, icmp, tcp, and udp port or protocol scans"

//-------------------------------------------------------------------------
// gid - sids
//-------------------------------------------------------------------------

#define GID_PORT_SCAN 122

#define PSNG_TCP_PORTSCAN                      1
#define PSNG_TCP_DECOY_PORTSCAN                2
#define PSNG_TCP_PORTSWEEP                     3
#define PSNG_TCP_DISTRIBUTED_PORTSCAN          4
#define PSNG_TCP_FILTERED_PORTSCAN             5
#define PSNG_TCP_FILTERED_DECOY_PORTSCAN       6
#define PSNG_TCP_PORTSWEEP_FILTERED            7
#define PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN 8

#define PSNG_IP_PORTSCAN                       9
#define PSNG_IP_DECOY_PORTSCAN                 10
#define PSNG_IP_PORTSWEEP                      11
#define PSNG_IP_DISTRIBUTED_PORTSCAN           12
#define PSNG_IP_FILTERED_PORTSCAN              13
#define PSNG_IP_FILTERED_DECOY_PORTSCAN        14
#define PSNG_IP_PORTSWEEP_FILTERED             15
#define PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN  16

#define PSNG_UDP_PORTSCAN                      17
#define PSNG_UDP_DECOY_PORTSCAN                18
#define PSNG_UDP_PORTSWEEP                     19
#define PSNG_UDP_DISTRIBUTED_PORTSCAN          20
#define PSNG_UDP_FILTERED_PORTSCAN             21
#define PSNG_UDP_FILTERED_DECOY_PORTSCAN       22
#define PSNG_UDP_PORTSWEEP_FILTERED            23
#define PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN 24

#define PSNG_ICMP_PORTSWEEP                    25
#define PSNG_ICMP_PORTSWEEP_FILTERED           26

#define PSNG_OPEN_PORT                         27

//-------------------------------------------------------------------------
// rule msgs
//-------------------------------------------------------------------------

#define PSNG_TCP_PORTSCAN_STR \
    "TCP portscan"
#define PSNG_TCP_DECOY_PORTSCAN_STR \
    "TCP decoy portscan"
#define PSNG_TCP_PORTSWEEP_STR \
    "TCP portsweep"
#define PSNG_TCP_DISTRIBUTED_PORTSCAN_STR \
    "TCP distributed portscan"
#define PSNG_TCP_FILTERED_PORTSCAN_STR \
    "TCP filtered portscan"
#define PSNG_TCP_FILTERED_DECOY_PORTSCAN_STR \
    "TCP filtered decoy portscan"
#define PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN_STR \
    "TCP filtered distributed portscan"
#define PSNG_TCP_PORTSWEEP_FILTERED_STR \
    "TCP filtered portsweep"

#define PSNG_IP_PORTSCAN_STR \
    "IP protocol scan"
#define PSNG_IP_DECOY_PORTSCAN_STR \
    "IP decoy protocol scan"
#define PSNG_IP_PORTSWEEP_STR \
    "IP protocol sweep"
#define PSNG_IP_DISTRIBUTED_PORTSCAN_STR \
    "IP distributed protocol scan"
#define PSNG_IP_FILTERED_PORTSCAN_STR \
    "IP filtered protocol scan"
#define PSNG_IP_FILTERED_DECOY_PORTSCAN_STR \
    "IP filtered decoy protocol scan"
#define PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN_STR \
    "IP filtered distributed protocol scan"
#define PSNG_IP_PORTSWEEP_FILTERED_STR \
    "IP filtered protocol sweep"

#define PSNG_UDP_PORTSCAN_STR \
    "UDP portscan"
#define PSNG_UDP_DECOY_PORTSCAN_STR \
    "UDP decoy portscan"
#define PSNG_UDP_PORTSWEEP_STR \
    "UDP portsweep"
#define PSNG_UDP_DISTRIBUTED_PORTSCAN_STR \
    "UDP distributed portscan"
#define PSNG_UDP_FILTERED_PORTSCAN_STR \
    "UDP filtered portscan"
#define PSNG_UDP_FILTERED_DECOY_PORTSCAN_STR \
    "UDP filtered decoy portscan"
#define PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN_STR \
    "UDP filtered distributed portscan"
#define PSNG_UDP_PORTSWEEP_FILTERED_STR \
    "UDP filtered portsweep"

#define PSNG_ICMP_PORTSWEEP_STR \
    "ICMP sweep"
#define PSNG_ICMP_PORTSWEEP_FILTERED_STR \
    "ICMP filtered sweep"

#define PSNG_OPEN_PORT_STR \
    "open port"

//-------------------------------------------------------------------------

extern THREAD_LOCAL SimpleStats spstats;
extern THREAD_LOCAL snort::ProfileStats psPerfStats;

struct PortscanConfig;

class PortScanModule : public snort::Module
{
public:
    PortScanModule();
    ~PortScanModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    const snort::RuleMap* get_rules() const override;

    unsigned get_gid() const override
    { return GID_PORT_SCAN; }

    PortscanConfig* get_data();

    Usage get_usage() const override
    { return GLOBAL; } // FIXIT-M this should eventually be CONTEXT.
                       // Set to GLOBAL so this isn't selected away when inspection policy switches

private:
    PS_ALERT_CONF* get_alert_conf(const char* fqn);

private:
    PortscanConfig* config;
};

#endif

