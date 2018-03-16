//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

// sftarget_data.c author Steven Sturges

#ifndef SFTARGET_DATA_H
#define SFTARGET_DATA_H

#include "sfip/sf_cidr.h"
#include "target_based/snort_protocols.h"

#define SFAT_OK 0
#define SFAT_ERROR (-1)
#define SFAT_BUFSZ 1024

enum ServiceClient
{
    ATTRIBUTE_SERVICE,
    ATTRIBUTE_CLIENT
};

#define APPLICATION_ENTRY_PORT 0x01
#define APPLICATION_ENTRY_IPPROTO 0x02
#define APPLICATION_ENTRY_PROTO 0x04
#define APPLICATION_ENTRY_APPLICATION 0x08
#define APPLICATION_ENTRY_VERSION 0x10

struct ApplicationEntry
{
    ApplicationEntry* next;

    uint16_t port;
    uint16_t ipproto;
    SnortProtocolId snort_protocol_id;

    uint8_t fields;
};

#define HOST_INFO_OS 1
#define HOST_INFO_VENDOR 2
#define HOST_INFO_VERSION 3
#define HOST_INFO_FRAG_POLICY 4
#define HOST_INFO_STREAM_POLICY 5

struct HostInfo
{
    uint8_t streamPolicy;
    uint8_t fragPolicy;
};

#define SFAT_SERVICE 1
#define SFAT_CLIENT 2

struct HostAttributeEntry
{
    snort::SfCidr ipAddr;
    HostInfo hostInfo;
    ApplicationEntry* services;
    ApplicationEntry* clients;
};

int SFAT_AddHost(HostAttributeEntry*);
int SFAT_AddService(HostAttributeEntry*, ApplicationEntry*);
int SFAT_AddHostEntryToMap(HostAttributeEntry*);

HostAttributeEntry* SFAT_CreateHostEntry();
ApplicationEntry* SFAT_CreateApplicationEntry();

#endif

