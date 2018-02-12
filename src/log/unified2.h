//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef UNIFIED2_H
#define UNIFIED2_H

// Unified logging (events and packets) shared header.

#include <netinet/in.h>

#include "protocols/protocol_ids.h"

// OBSOLETE (no longer generated):
// #define UNIFIED2_EVENT                 1
// #define UNIFIED2_IDS_EVENT             7
// #define UNIFIED2_IDS_EVENT_IPV6       72
// #define UNIFIED2_IDS_EVENT_MPLS       99
// #define UNIFIED2_IDS_EVENT_IPV6_MPLS 100

// CURRENT
#define UNIFIED2_PACKET                2
#define UNIFIED2_BUFFER                3  // !legacy_events
#define UNIFIED2_IDS_EVENT_VLAN      104  // legacy_events
#define UNIFIED2_IDS_EVENT_IPV6_VLAN 105  // legacy_events
#define UNIFIED2_EXTRA_DATA          110
#define UNIFIED2_IDS_EVENT_APPSTAT   113  // FIXIT-L owned by appid (should have own # space)
#define UNIFIED2_EVENT3              114

#define MAX_EVENT_APPNAME_LEN         64

/* Data structure used for serialization of Unified2 Records */
struct Serial_Unified2_Header
{
    uint32_t type;
    uint32_t length;
};

// UNIFIED2_EVENT3 = type 114
struct Unified2Event
{
    uint32_t snort_id;

    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;

    uint32_t rule_gid;
    uint32_t rule_sid;
    uint32_t rule_rev;
    uint32_t rule_class;
    uint32_t rule_priority;

    // everything above this point is common to all prior event records
    // try to keep the same for things like barnyard2

    uint32_t policy_id_context;
    uint32_t policy_id_inspect;
    uint32_t policy_id_detect;

    uint32_t pkt_src_ip[4];
    uint32_t pkt_dst_ip[4];
    uint32_t pkt_mpls_label;

    uint16_t pkt_src_port_itype;
    uint16_t pkt_dst_port_icode;
    uint16_t pkt_vlan_id;
    uint16_t unused;

    uint8_t pkt_ip_ver;  // 0x4 or 0x6, high nybble is src, low is dst
    uint8_t pkt_ip_proto;

    uint8_t snort_status;  // allow=0, can't, would, force
    uint8_t snort_action;  // pass=0, drop, block, reset

    char app_name[MAX_EVENT_APPNAME_LEN];
};

// UNIFIED2_IDS_EVENT_VLAN = type 104
struct Unified2IDSEvent
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    IpProtocol ip_proto;
    uint8_t impact_flag; // overloads packet_action
    uint8_t impact;
    uint8_t blocked;
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t pad2; // Policy ID
    char app_name[MAX_EVENT_APPNAME_LEN];
};

// UNIFIED2_IDS_EVENT_IPV6_VLAN = type 105
struct Unified2IDSEventIPv6
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    IpProtocol ip_proto;
    uint8_t impact_flag;
    uint8_t impact;
    uint8_t blocked;
    uint32_t mpls_label;
    uint16_t vlanId;
    uint16_t pad2; /*could be IPS Policy local id to support local sensor alerts*/
    char app_name[MAX_EVENT_APPNAME_LEN];
};

// UNIFIED2_PACKET = type 2
struct Serial_Unified2Packet
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];
};

struct Unified2ExtraDataHdr
{
    uint32_t event_type;
    uint32_t event_length;
};

// UNIFIED2_EXTRA_DATA - type 110
struct SerialUnified2ExtraData
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type;         // EventInfo
    uint32_t data_type;    // EventDataType
    uint32_t blob_length;  // Length of the data + sizeof(blob_length) + sizeof(data_type)
};

struct Data_Blob
{
    uint32_t length;
    const uint8_t* data;
};

enum EventInfoEnum
{
    EVENT_INFO_XFF_IPV4 = 1,
    EVENT_INFO_XFF_IPV6,
    EVENT_INFO_REVIEWED_BY,
    EVENT_INFO_GZIP_DATA,
    EVENT_INFO_SMTP_FILENAME,
    EVENT_INFO_SMTP_MAILFROM,
    EVENT_INFO_SMTP_RCPTTO,
    EVENT_INFO_SMTP_EMAIL_HDRS,
    EVENT_INFO_HTTP_URI,
    EVENT_INFO_HTTP_HOSTNAME,
    EVENT_INFO_IPV6_SRC,  // deprecated
    EVENT_INFO_IPV6_DST,  // deprecated
    EVENT_INFO_JSNORM_DATA
};

enum EventDataType
{
    EVENT_DATA_TYPE_BLOB = 1,
    EVENT_DATA_TYPE_MAX
};

#define EVENT_TYPE_EXTRA_DATA   4

#define MAX_XFF_WRITE_BUF_LENGTH \
    (sizeof(Serial_Unified2_Header) + \
    sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData) \
    + sizeof(struct in6_addr))

#endif

