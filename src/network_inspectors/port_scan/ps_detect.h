//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

#ifndef PS_DETECT_H
#define PS_DETECT_H

#include <time.h>
#include <sys/time.h>

#include "ipobj.h"
#include "sfip/sfip_t.h"

#define PS_OPEN_PORTS 8

struct PsCommon
{
    unsigned long memcap;

    PsCommon() { memcap = 0; }
};

struct PortscanConfig
{
    int disabled;
    int detect_scans;
    int detect_scan_type;
    int sense_level;
    int proto_cnt;
    int include_midstream;
    int print_tracker;
    bool logfile;

    IPSET* ignore_scanners;
    IPSET* ignore_scanned;
    IPSET* watch_ip;

    PsCommon* common;

    PortscanConfig();
    ~PortscanConfig();
};

struct PS_PROTO
{
    int connection_count;
    int priority_count;
    int u_ip_count;
    int u_port_count;

    unsigned short high_p;
    unsigned short low_p;
    unsigned short u_ports;

    sfip_t high_ip;
    sfip_t low_ip;
    sfip_t u_ips;

    unsigned short open_ports[PS_OPEN_PORTS];
    unsigned char open_ports_cnt;

    struct timeval event_time;
    unsigned int event_ref;

    unsigned char alerts;

    time_t window;
};

struct PS_TRACKER
{
    int priority_node;
    int protocol;
    PS_PROTO proto;
};

struct PS_PKT
{
    void* pkt;
    int proto;
    int reverse_pkt;
    PS_TRACKER* scanner;
    PS_TRACKER* scanned;
};

//-------------------------------------------------------------------------

#define PS_PROTO_NONE        0x00
#define PS_PROTO_TCP         0x01
#define PS_PROTO_UDP         0x02
#define PS_PROTO_ICMP        0x04
#define PS_PROTO_IP          0x08
#define PS_PROTO_ALL         0x0f

#define PS_PROTO_OPEN_PORT   0x80

#define PS_TYPE_PORTSCAN     0x01
#define PS_TYPE_PORTSWEEP    0x02
#define PS_TYPE_DECOYSCAN    0x04
#define PS_TYPE_DISTPORTSCAN 0x08
#define PS_TYPE_ALL          0x0f

#define PS_SENSE_HIGH        3
#define PS_SENSE_MEDIUM      2
#define PS_SENSE_LOW         1

#define PS_ALERT_ONE_TO_ONE                1
#define PS_ALERT_ONE_TO_ONE_DECOY          2
#define PS_ALERT_PORTSWEEP                 3
#define PS_ALERT_DISTRIBUTED               4
#define PS_ALERT_ONE_TO_ONE_FILTERED       5
#define PS_ALERT_ONE_TO_ONE_DECOY_FILTERED 6
#define PS_ALERT_DISTRIBUTED_FILTERED      7
#define PS_ALERT_PORTSWEEP_FILTERED        8
#define PS_ALERT_OPEN_PORT                 9

#define PS_ALERT_GENERATED                 255

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

#endif

