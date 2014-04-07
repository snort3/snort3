/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef PS_DETECT_H
#define PS_DETECT_H

#include <time.h>
#include <sys/time.h>

#include "ipobj.h"
#include "ipv6_port.h"

#define PS_OPEN_PORTS 8

struct PsCommon
{
    unsigned long memcap;

    PsCommon() { memcap = 0; };
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
    char *logfile;

    IPSET *ignore_scanners;
    IPSET *ignore_scanned;
    IPSET *watch_ip;

    PsCommon* common;

    PortscanConfig();
    ~PortscanConfig();
};

typedef struct s_PS_PROTO
{
    short          connection_count;
    short          priority_count;
    short          u_ip_count;
    short          u_port_count;

    unsigned short high_p;
    unsigned short low_p;
    unsigned short u_ports;

    snort_ip           high_ip;
    snort_ip           low_ip;
    snort_ip           u_ips;

    unsigned short open_ports[PS_OPEN_PORTS];
    unsigned char  open_ports_cnt;

    struct timeval event_time;
    unsigned int   event_ref;

    unsigned char  alerts;

    time_t         window;

} PS_PROTO;

typedef struct s_PS_TRACKER
{
    int priority_node;
    int protocol;
    PS_PROTO proto;

} PS_TRACKER;

typedef struct s_PS_PKT
{
    void *pkt;
    int proto;
    int reverse_pkt;
    PS_TRACKER *scanner;
    PS_TRACKER *scanned;

} PS_PKT;

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

#define PS_SENSE_HIGH        1
#define PS_SENSE_MEDIUM      2
#define PS_SENSE_LOW         3

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
    "(port_scan) TCP Portscan"
#define PSNG_TCP_DECOY_PORTSCAN_STR \
    "(port_scan) TCP Decoy Portscan"
#define PSNG_TCP_PORTSWEEP_STR \
    "(port_scan) TCP Portsweep"
#define PSNG_TCP_DISTRIBUTED_PORTSCAN_STR \
    "(port_scan) TCP Distributed Portscan"
#define PSNG_TCP_FILTERED_PORTSCAN_STR \
    "(port_scan) TCP Filtered Portscan"
#define PSNG_TCP_FILTERED_DECOY_PORTSCAN_STR \
    "(port_scan) TCP Filtered Decoy Portscan"
#define PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN_STR \
    "(port_scan) TCP Filtered Distributed Portscan"
#define PSNG_TCP_PORTSWEEP_FILTERED_STR \
    "(port_scan) TCP Filtered Portsweep"

#define PSNG_IP_PORTSCAN_STR \
    "(port_scan) IP Protocol Scan"
#define PSNG_IP_DECOY_PORTSCAN_STR \
     "(port_scan) IP Decoy Protocol Scan"
#define PSNG_IP_PORTSWEEP_STR \
    "(port_scan) IP Protocol Sweep"
#define PSNG_IP_DISTRIBUTED_PORTSCAN_STR \
    "(port_scan) IP Distributed Protocol Scan"
#define PSNG_IP_FILTERED_PORTSCAN_STR \
    "(port_scan) IP Filtered Protocol Scan"
#define PSNG_IP_FILTERED_DECOY_PORTSCAN_STR \
    "(port_scan) IP Filtered Decoy Protocol Scan"
#define PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN_STR \
    "(port_scan) IP Filtered Distributed Protocol Scan"
#define PSNG_IP_PORTSWEEP_FILTERED_STR \
    "(port_scan) IP Filtered Protocol Sweep"

#define PSNG_UDP_PORTSCAN_STR \
    "(port_scan) UDP Portscan"
#define PSNG_UDP_DECOY_PORTSCAN_STR \
    "(port_scan) UDP Decoy Portscan"
#define PSNG_UDP_PORTSWEEP_STR \
    "(port_scan) UDP Portsweep"
#define PSNG_UDP_DISTRIBUTED_PORTSCAN_STR \
    "(port_scan) UDP Distributed Portscan"
#define PSNG_UDP_FILTERED_PORTSCAN_STR \
    "(port_scan) UDP Filtered Portscan"
#define PSNG_UDP_FILTERED_DECOY_PORTSCAN_STR \
    "(port_scan) UDP Filtered Decoy Portscan"
#define PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN_STR \
    "(port_scan) UDP Filtered Distributed Portscan"
#define PSNG_UDP_PORTSWEEP_FILTERED_STR \
    "(port_scan) UDP Filtered Portsweep"

#define PSNG_ICMP_PORTSWEEP_STR \
    "(port_scan) ICMP Sweep"
#define PSNG_ICMP_PORTSWEEP_FILTERED_STR \
    "(port_scan) ICMP Filtered Sweep"

#define PSNG_OPEN_PORT_STR \
    "(port_scan) Open Port"

#endif

