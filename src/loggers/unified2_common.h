//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#ifndef UNIFIED2_COMMON_H
#define UNIFIED2_COMMON_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#ifdef LINUX
#include <stdint.h>
#endif
#include <netinet/in.h>

#include <protocols/protocol_ids.h>

// SNORT DEFINES
// Long time ago...
#define UNIFIED2_EVENT               1

// CURRENT
#define UNIFIED2_PACKET              2
#define UNIFIED2_IDS_EVENT           7
#define UNIFIED2_IDS_EVENT_IPV6      72
#define UNIFIED2_IDS_EVENT_MPLS      99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS 100
#define UNIFIED2_IDS_EVENT_VLAN      104
#define UNIFIED2_IDS_EVENT_IPV6_VLAN 105
#define UNIFIED2_EXTRA_DATA          110

/* Data structure used for serialization of Unified2 Records */
typedef struct _Serial_Unified2_Header
{
    uint32_t type;
    uint32_t length;
} Serial_Unified2_Header;

// UNIFIED2_IDS_EVENT_VLAN = type 104
// comes from SFDC to EStreamer archive in serialized form with the extended header
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
};

// UNIFIED2_IDS_EVENT_IPV6_VLAN = type 105
typedef struct _Unified2IDSEventIPv6
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
} Unified2IDSEventIPv6;

// UNIFIED2_PACKET = type 2
typedef struct _Serial_Unified2Packet
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];
} Serial_Unified2Packet;

typedef struct _Unified2ExtraDataHdr
{
    uint32_t event_type;
    uint32_t event_length;
}Unified2ExtraDataHdr;

// UNIFIED2_EXTRA_DATA - type 110
typedef struct _SerialUnified2ExtraData
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type;              /* EventInfo */
    uint32_t data_type;         /*EventDataType */
    uint32_t blob_length;       /* Length of the data + sizeof(blob_length) + sizeof(data_type)*/
} SerialUnified2ExtraData;

typedef struct _Data_Blob
{
    uint32_t length;
    const uint8_t* data;
} Data_Blob;

// UNIFIED2_EXTRA_DATA - type 110
typedef struct _Serial_Unified2ExtraData
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type;
    Data_Blob data;
} Unified2ExtraData;

typedef enum _EventInfoEnum
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
    EVENT_INFO_IPV6_SRC,
    EVENT_INFO_IPV6_DST,
    EVENT_INFO_JSNORM_DATA
}EventInfoEnum;

typedef enum _EventDataType
{
    EVENT_DATA_TYPE_BLOB = 1,
    EVENT_DATA_TYPE_MAX
}EventDataType;

#define EVENT_TYPE_EXTRA_DATA   4

#define MAX_XFF_WRITE_BUF_LENGTH \
    (sizeof(Serial_Unified2_Header) + \
    sizeof(Unified2ExtraDataHdr) + sizeof(SerialUnified2ExtraData) \
    + sizeof(struct in6_addr))

#define Serial_Unified2IDSEvent Unified2IDSEvent
#define Serial_Unified2IDSEventIPv6 Unified2IDSEventIPv6

//---------------LEGACY, type '7'
// These structures are not used anymore in the product
typedef struct _Serial_Unified2IDSEvent_legacy
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
    uint8_t impact_flag; // sets packet_action
    uint8_t impact;
    uint8_t blocked;
} Serial_Unified2IDSEvent_legacy;

//----------LEGACY, type '72'
typedef struct _Serial_Unified2IDSEventIPv6_legacy
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
} Serial_Unified2IDSEventIPv6_legacy;

////////////////////-->LEGACY

#endif

