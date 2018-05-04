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

// snort_protocols.cc derived from sftarget_protocol_reference.c by Steven Sturges

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_protocols.h"

#include <algorithm>

#include "log/messages.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "sftarget_data.h"

using namespace snort;
using namespace std;

SnortProtocolId ProtocolReference::get_count()
{
    return protocol_number;
}

const char* ProtocolReference::get_name(SnortProtocolId id)
{
    if ( id >= id_map.size() )
        id = 0;

    return id_map[id].c_str();
}

struct Compare
{
    bool operator()(SnortProtocolId a, SnortProtocolId b)
    { return map[a] < map[b]; }

    vector<string>& map;
};

const char* ProtocolReference::get_name_sorted(SnortProtocolId id)
{
    if ( ind_map.size() < id_map.size() )
    {
        while ( ind_map.size() < id_map.size() )
            ind_map.push_back((SnortProtocolId)ind_map.size());

        Compare c { id_map };
        sort(ind_map.begin(), ind_map.end(), c);
    }
    if ( id >= ind_map.size() )
        return nullptr;

    return id_map[ind_map[id]].c_str();
}

SnortProtocolId ProtocolReference::add(const char* protocol)
{
    if (!protocol)
        return UNKNOWN_PROTOCOL_ID;

    auto protocol_ref = ref_table.find(protocol);
    if ( protocol_ref != ref_table.end() )
    {
        return protocol_ref->second;
    }

    SnortProtocolId snort_protocol_id = protocol_number++;
    id_map.push_back(protocol);
    ref_table[protocol] = snort_protocol_id;

    return snort_protocol_id;
}

SnortProtocolId ProtocolReference::find(const char* protocol)
{
    auto protocol_ref = ref_table.find(protocol);
    if ( protocol_ref != ref_table.end() )
    {
        return protocol_ref->second;
    }

    return UNKNOWN_PROTOCOL_ID;
}

void ProtocolReference::init(ProtocolReference* old_proto_ref)
{
    if(!old_proto_ref)
    {
        bool ok = ( add("unknown") == UNKNOWN_PROTOCOL_ID );
        ok = ( add("ip") == SNORT_PROTO_IP ) and ok;
        ok = ( add("icmp") == SNORT_PROTO_ICMP ) and ok;
        ok = ( add("tcp") == SNORT_PROTO_TCP ) and ok;
        ok = ( add("udp") == SNORT_PROTO_UDP ) and ok;
        ok = ( add("user") == SNORT_PROTO_USER ) and ok;
        ok = ( add("file") == SNORT_PROTO_FILE ) and ok;
        assert(ok);
    }
    else
    {
        // Copy old ProtocolReference ID/name pairs to new ProtocolReference
        for(SnortProtocolId id = 0; id < old_proto_ref->get_count(); id++)
        {
            add(old_proto_ref->get_name(id));
        }
    }
}

ProtocolReference::ProtocolReference()
{
    init(nullptr);
}

ProtocolReference::ProtocolReference(ProtocolReference* old_proto_ref)
{
    init(old_proto_ref);
}

ProtocolReference::~ProtocolReference()
{
    ref_table.clear();
}

