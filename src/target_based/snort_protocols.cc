//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "snort_protocols.h"

#include <algorithm>
#include <string>
#include <vector>
using namespace std;

#include "sftarget_reader.h"
#include "sftarget_hostentry.h"
#include "sftarget_data.h"

#include "hash/sfghash.h"
#include "utils/util.h"
#include "main/snort_debug.h"
#include "stream/stream_api.h"

struct SFTargetProtocolReference
{
    char name[SFAT_BUFSZ];
    int16_t ordinal;
};

static SFGHASH* proto_reference_table = NULL;  // STATIC
static int16_t protocol_number = 1;

int16_t get_protocol_count()
{ return protocol_number; }

static vector<string> id_map;

const char* get_protocol_name(uint16_t id)
{
    if ( id >= id_map.size() )
        id = 0;

    return id_map[id].c_str();
}

static bool comp_ind(uint16_t a, uint16_t b)
{
    return id_map[a] < id_map[b];
}

const char* get_protocol_name_sorted(uint16_t id)
{
    static vector<uint16_t> ind_map;  // indirect

    if ( ind_map.size() < id_map.size() )
    {
        while ( ind_map.size() < id_map.size() )
            ind_map.push_back((uint16_t)ind_map.size());

        sort(ind_map.begin(), ind_map.end(), comp_ind);
    }
    if ( id >= ind_map.size() )
        return nullptr;

    return id_map[ind_map[id]].c_str();
}

/* XXX XXX Probably need to do this during swap time since the
 * proto_reference_table is accessed during runtime */
int16_t AddProtocolReference(const char* protocol)
{
    SFTargetProtocolReference* reference;

    if (!protocol)
        return SFTARGET_UNKNOWN_PROTOCOL;

    reference = (SFTargetProtocolReference*)sfghash_find(proto_reference_table, (void*)protocol);
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

    sfghash_add(proto_reference_table, reference->name, reference);

    DebugFormat(DEBUG_ATTRIBUTE,
        "Added Protocol Reference for %s as %d\n", protocol, reference->ordinal);

    return reference->ordinal;
}

int16_t FindProtocolReference(const char* protocol)
{
    SFTargetProtocolReference* reference;

    if (!protocol)
        return SFTARGET_UNKNOWN_PROTOCOL;

    reference = (SFTargetProtocolReference*)sfghash_find(proto_reference_table, (void*)protocol);

    if (reference)
        return reference->ordinal;

    return SFTARGET_UNKNOWN_PROTOCOL;
}

void InitializeProtocolReferenceTable()
{
    /* If already initialized, we're done */
    if (proto_reference_table)
        return;

    proto_reference_table = sfghash_new(65, 0, 1, snort_free);

    bool ok;

    ok = ( AddProtocolReference("ip") == SNORT_PROTO_IP );
    ok = ( AddProtocolReference("icmp") == SNORT_PROTO_ICMP ) and ok;
    ok = ( AddProtocolReference("tcp") == SNORT_PROTO_TCP ) and ok;
    ok = ( AddProtocolReference("udp") == SNORT_PROTO_UDP ) and ok;
    ok = ( AddProtocolReference("user") == SNORT_PROTO_USER ) and ok;
    ok = ( AddProtocolReference("file") == SNORT_PROTO_FILE ) and ok;

    assert(ok);

    if ( !ok )
        FatalError("standard protocol reference mismatch");
}

void FreeProtoocolReferenceTable()
{
    sfghash_delete(proto_reference_table);
    proto_reference_table = NULL;
}

#if 0
int16_t GetProtocolReference(Packet* p)
{
    int16_t protocol = 0;
    int16_t ipprotocol = 0;

    if (!p)
        return protocol;

    if ( int16_t app_proto = p->get_application_protocol() )
        return app_proto;

    do /* Simple do loop to break out of quickly, not really a loop */
    {
        HostAttributeEntry* host_entry;
        if ( p->flow )
        {
            /* Use session information via Stream API */
            protocol = stream.get_application_protocol_id(p->flow);

            if ( protocol )
                break;
        }

        switch (p->type())
        {
        case PktType::TCP:
            ipprotocol = SNORT_PROTO_TCP;
            break;
        case PktType::UDP:
            ipprotocol = SNORT_PROTO_UDP;
            break;
        case PktType::ICMP:
            ipprotocol = SNORT_PROTO_ICMP;
            break;
        default: /* so compiler doesn't complain about unhandled cases */
            break;
        }

        /* Lookup the destination host to find the protocol for the
         * destination port
         */
        host_entry = SFAT_LookupHostEntryByDst(p);

        if (host_entry)
            protocol = getApplicationProtocolId(host_entry, ipprotocol, p->ptrs.dp, SFAT_SERVICE);

        if ( protocol )
            break;

        /* If not found, do same for src host/src port. */
        host_entry = SFAT_LookupHostEntryBySrc(p);

        if (host_entry)
            protocol = getApplicationProtocolId(host_entry, ipprotocol, p->ptrs.sp, SFAT_SERVICE);

        if ( protocol )
            break;
    }
    while (0);   /* Simple do loop to break out of quickly, not really a loop */

    /* Store it to alleviate future lookups */
    p->set_application_protocol(protocol);

    return protocol;
}
#endif

