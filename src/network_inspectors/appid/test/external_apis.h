//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// external_apis.h author Sourcefire Inc.

#ifndef EXTERNAL_APIS_H
#define EXTERNAL_APIS_H

#include <cstdint>

#include "flow/flow.h"

struct sfaddr_t;
struct SnortConfig;
struct Packet;
using tSfPolicyId = int;

#define PKT_FROM_SERVER     0x00000040  /* this packet came from the server
                                           side of a connection (TCP) */
#define PKT_FROM_CLIENT     0x00000080  /* this packet came from the client
                                           side of a connection (TCP) */
// _dpd APIs
void logMsg(const char*, ...);
void errMsg(const char*, ...);
void debugMsg(uint64_t type, const char*, ...);
int16_t addProtocolReference(const char* protocol);

void* addPreproc(
    SnortConfig*, void (* pp_func)(void*, void*), uint16_t priority,
    uint32_t appId, uint32_t flags);

tSfPolicyId getParserPolicy(SnortConfig*);
tSfPolicyId getDefaultPolicy();
bool isAppIdRequired();
uint32_t getSnortInstance();
int16_t findProtocolReference(const char* app);

// Session APIs
void enable_preproc_all_ports(SnortConfig*, uint32_t appId, uint32_t flags);
void* get_application_data(void* stream_session, uint32_t protocol);
int set_application_data(void* scbptr, uint32_t protocol, void* data, StreamAppDataFree);
uint32_t get_packet_direction(Packet*);
uint32_t get_session_flags(void* ssnptr);
sfaddr_t* get_session_ip_address(void* scbptr, uint32_t direction);
int16_t get_application_protocol_id(void* scbptr);
char** get_http_xff_precedence(void* ssn, uint32_t flags, int* nFields);

// Stream APIs
bool is_session_decrypted(void* stream_session);
void set_application_id(
    void* ssnptr, int16_t serviceAppid, int16_t ClientAppid,
    int16_t payloadAppId, int16_t miscAppid);

bool is_session_http2(void* ssn);

#endif
