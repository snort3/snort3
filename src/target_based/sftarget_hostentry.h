//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// sftarget_hostentry.h author Steven Sturges

#ifndef SFTARGET_HOSTENTRY_H
#define SFTARGET_HOSTENTRY_H

#include "target_based/sftarget_reader.h"
#include "target_based/sftarget_data.h"

#define SFTARGET_MATCH 1
#define SFTARGET_NOMATCH 0

/* API for HostAttributeEntry 'class' */

// FIXIT-L used locally only
int hasService(const HostAttributeEntry* hostEntry,
    int ipprotocol,
    int protocol,
    int application);

// FIXIT-L used locally only
int hasClient(const HostAttributeEntry* hostEntry,
    int ipprotocol,
    int protocol,
    int application);

// FIXIT-L not used anywhere
int hasProtocol(const HostAttributeEntry* hostEntry,
    int ipprotocol,
    int protocol,
    int application);

// FIXIT-L not used anywhere
int getProtocol(const HostAttributeEntry* hostEntry,
    int ipprotocol,
    uint16_t port);

int getApplicationProtocolId(const HostAttributeEntry* host_entry,
    int ipprotocol,
    uint16_t port,
    char direction);

// FIXIT-L not used anywhere
#define SFAT_UNKNOWN_STREAM_POLICY 0
uint16_t getStreamPolicy(const HostAttributeEntry* host_entry);
#define SFAT_UNKNOWN_FRAG_POLICY 0
uint16_t getFragPolicy(const HostAttributeEntry* host_entry);

#endif

