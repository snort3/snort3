//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// FIXIT-L use logical type instead of int16_t
// for all reference protocols

// these protocols are always defined because
// they are used as consts in switch statements
// other protos are added dynamically as used
enum SnortProtocols
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

inline bool is_network_protocol(int16_t proto)
{ return (proto >= SNORT_PROTO_IP and proto <= SNORT_PROTO_UDP); }

inline bool is_builtin_protocol(int16_t proto)
{ return proto < SNORT_PROTO_MAX; }

inline bool is_service_protocol(int16_t proto)
{ return proto > SNORT_PROTO_UDP; }

class SO_PUBLIC ProtocolReference
{
public:
    ProtocolReference();
    ~ProtocolReference();

    int16_t get_count();

    const char* get_name(uint16_t id);
    const char* get_name_sorted(uint16_t id);

    int16_t add(const char* protocol);
    int16_t find(const char* protocol);

    bool operator()(uint16_t a, uint16_t b);

private:
    std::vector<std::string> id_map;
    std::vector<uint16_t> ind_map;
    std::unordered_map<std::string, int16_t> ref_table;
    int16_t protocol_number = 1;
};

#endif

