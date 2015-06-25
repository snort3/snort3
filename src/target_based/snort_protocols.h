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

// snort_protocols.h derived from sftarget_protocol_reference.h by Steven Sturges

#ifndef SNORT_PROTOCOLS_H
#define SNORT_PROTOCOLS_H

#include "snort_types.h"

#define MAX_PROTOCOL_ORDINAL 8192  // FIXIT-L use std::vector and eliminate this

// FIXIT-L use logical type instead of int16_t
// for all reference protocols

// these protocols are always defined because
// they are used as consts in switch statements
// other protos are added dynamically as used
const int16_t SNORT_PROTO_IP   = 1;
const int16_t SNORT_PROTO_ICMP = 2;
const int16_t SNORT_PROTO_TCP  = 3;
const int16_t SNORT_PROTO_UDP  = 4;
const int16_t SNORT_PROTO_FILE = 5;

static inline bool is_network_protocol(int16_t proto)
{ return (proto > 0 and proto < SNORT_PROTO_FILE); }

static inline bool is_service_protocol(int16_t proto)
{ return !is_network_protocol(proto); }

void InitializeProtocolReferenceTable(void);
void FreeProtoocolReferenceTable(void);

const char* get_protocol_name(uint16_t id);
const char* get_protocol_name_sorted(uint16_t id);

int16_t AddProtocolReference(const char* protocol);
SO_PUBLIC int16_t FindProtocolReference(const char* protocol);

int16_t GetProtocolReference(struct Packet*);

#endif

