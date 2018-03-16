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

// snort_protocols.h derived from sftarget_protocol_reference.h by Steven Sturges

#ifndef SNORT_PROTOCOLS_H
#define SNORT_PROTOCOLS_H

#include <string>
#include <vector>
#include <unordered_map>

#include "main/snort_types.h"

using SnortProtocolId = uint16_t;

// these protocols are always defined because
// they are used as consts in switch statements
// other protos are added dynamically as used
enum SnortProtocols : SnortProtocolId
{
    //  The is_*_protocol functions depend on the order of these enums.
    SNORT_PROTO_IP = 1,
    SNORT_PROTO_ICMP,
    SNORT_PROTO_TCP,
    SNORT_PROTO_UDP,
    SNORT_PROTO_USER,
    SNORT_PROTO_FILE,
    SNORT_PROTO_MAX
};

constexpr SnortProtocolId UNKNOWN_PROTOCOL_ID = 0;
constexpr SnortProtocolId INVALID_PROTOCOL_ID = 0xffff;

inline bool is_network_protocol(SnortProtocolId proto)
{ return (proto >= SNORT_PROTO_IP and proto <= SNORT_PROTO_UDP); }

inline bool is_builtin_protocol(SnortProtocolId proto)
{ return proto < SNORT_PROTO_MAX; }

inline bool is_service_protocol(SnortProtocolId proto)
{ return proto > SNORT_PROTO_UDP; }

// A mapping between names and IDs.
class SO_PUBLIC ProtocolReference
{
public:
    ProtocolReference();
    ~ProtocolReference();

    ProtocolReference(ProtocolReference* old_proto_ref);

    ProtocolReference(const ProtocolReference&)  = delete;
    ProtocolReference& operator=(const ProtocolReference&)  = delete;

    SnortProtocolId get_count();

    const char* get_name(SnortProtocolId id);
    const char* get_name_sorted(SnortProtocolId id);

    SnortProtocolId add(const char* protocol);
    SnortProtocolId find(const char* protocol);

    bool operator()(SnortProtocolId a, SnortProtocolId b);

private:
    std::vector<std::string> id_map;
    std::vector<SnortProtocolId> ind_map;
    std::unordered_map<std::string, SnortProtocolId> ref_table;

    // Start at 1 since 0 will be "unknown".
    SnortProtocolId protocol_number = 1;

    void init(ProtocolReference* old_proto_ref);
};

#endif

