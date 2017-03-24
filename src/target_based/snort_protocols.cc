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

// snort_protocols.cc derived from sftarget_protocol_reference.c by Steven Sturges

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_protocols.h"

#include <algorithm>

#include "hash/sfghash.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "sftarget_data.h"

using namespace std;

struct SFTargetProtocolReference
{
    char name[SFAT_BUFSZ];
    int16_t ordinal;
};

int16_t ProtocolReference::get_count()
{ return protocol_number; }

const char* ProtocolReference::get_name(uint16_t id)
{
    if ( id >= id_map.size() )
        id = 0;

    return id_map[id].c_str();
}

struct Compare
{
    bool operator()(uint16_t a, uint16_t b)
    { return map[a] < map[b]; }

    vector<string>& map;
};

const char* ProtocolReference::get_name_sorted(uint16_t id)
{
    if ( ind_map.size() < id_map.size() )
    {
        while ( ind_map.size() < id_map.size() )
            ind_map.push_back((uint16_t)ind_map.size());

        Compare c { id_map };
        sort(ind_map.begin(), ind_map.end(), c);
    }
    if ( id >= ind_map.size() )
        return nullptr;

    return id_map[ind_map[id]].c_str();
}

int16_t ProtocolReference::add(const char* protocol)
{
    if (!protocol)
        return SFTARGET_UNKNOWN_PROTOCOL;

    SFTargetProtocolReference* reference = (SFTargetProtocolReference*)sfghash_find(
        ref_table, (void*)protocol);

    if (reference)
    {
        DebugFormat(DEBUG_ATTRIBUTE,
            "Protocol Reference for %s exists as %d\n",
            protocol, reference->ordinal);

        return reference->ordinal;
    }

    if ( protocol_number == 1 )
        id_map.push_back("unknown");

    id_map.push_back(protocol);

    reference = (SFTargetProtocolReference*)snort_calloc(sizeof(SFTargetProtocolReference));
    reference->ordinal = protocol_number++;
    SnortStrncpy(reference->name, protocol, SFAT_BUFSZ);

    sfghash_add(ref_table, reference->name, reference);

    DebugFormat(DEBUG_ATTRIBUTE,
        "Added Protocol Reference for %s as %d\n", protocol, reference->ordinal);

    return reference->ordinal;
}

int16_t ProtocolReference::find(const char* protocol)
{
    SFTargetProtocolReference* reference;

    if (!protocol)
        return SFTARGET_UNKNOWN_PROTOCOL;

    reference = (SFTargetProtocolReference*)sfghash_find(ref_table, (void*)protocol);

    if (reference)
        return reference->ordinal;

    return SFTARGET_UNKNOWN_PROTOCOL;
}

ProtocolReference::ProtocolReference()
{
    ref_table = sfghash_new(65, 0, 1, snort_free);

    bool ok;

    ok = ( add("ip") == SNORT_PROTO_IP );
    ok = ( add("icmp") == SNORT_PROTO_ICMP ) and ok;
    ok = ( add("tcp") == SNORT_PROTO_TCP ) and ok;
    ok = ( add("udp") == SNORT_PROTO_UDP ) and ok;
    ok = ( add("user") == SNORT_PROTO_USER ) and ok;
    ok = ( add("file") == SNORT_PROTO_FILE ) and ok;

    assert(ok);

    if ( !ok )
        FatalError("standard protocol reference mismatch");
}

ProtocolReference::~ProtocolReference()
{
    sfghash_delete(ref_table);
}

