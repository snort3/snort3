//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// netflow.cc author Ron Dempster <rdempste@cisco.com>
//                   Shashikant Lad <shaslad@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netflow.h"
#include "netflow_module.h"

#include "host_tracker/host_cache.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

THREAD_LOCAL NetflowStats netflow_stats;
THREAD_LOCAL ProfileStats netflow_perf_stats;

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------
// FIXIT-M - keeping only few checks right now
static bool decode_netflow_v9(const unsigned char* data, uint16_t size)
{
    Netflow9Hdr header;
    const Netflow9Hdr *pheader;

    if( size < sizeof(Netflow9Hdr) )
        return false;

    pheader = (const Netflow9Hdr *)data;
    header.flow_count = ntohs(pheader->flow_count);

    // Invalid header flow count
    if( header.flow_count < NETFLOW_MIN_COUNT or header.flow_count > NETFLOW_MAX_COUNT)
        return false;

    return true;
}

static bool decode_netflow_v5(const unsigned char* data, uint16_t size)
{
    Netflow5Hdr header;
    const Netflow5Hdr *pheader;
    const Netflow5RecordHdr *precord;
    const Netflow5RecordHdr *end;

    end = (const Netflow5RecordHdr *)(data + size);

    pheader = (const Netflow5Hdr *)data;
    header.flow_count  = ntohs(pheader->flow_count);

    // invalid header flow count
    if( header.flow_count  < NETFLOW_MIN_COUNT or header.flow_count  > NETFLOW_MAX_COUNT )
        return false;

    data += sizeof(Netflow5Hdr);
    precord = (const Netflow5RecordHdr *)data;

    // Invalid flow count
    if ( (precord + header.flow_count) > end )
        return false;

    header.sys_uptime = ntohl(pheader->sys_uptime) / 1000;
    header.unix_secs = ntohl(pheader->unix_secs);
    header.unix_secs -= header.sys_uptime;

    // update total records
    netflow_stats.records += header.flow_count;

    unsigned i;
    for ( i=0; i < header.flow_count; i++, precord++ )
    {

        uint32_t first_packet = header.unix_secs + (ntohl(precord->flow_first)/1000);
        uint32_t last_packet = header.unix_secs + (ntohl(precord->flow_last)/1000);

        // invalid flow time values
        if ( first_packet > MAX_TIME or last_packet > MAX_TIME or first_packet > last_packet )
            return false;

    }
    return true;
}

static bool validate_netflow(const Packet* p)
{
    uint16_t size = p->dsize;
    const unsigned char* data = p->data;
    uint16_t version;
    bool retval = false;

    // invalid packet size
    if( size < sizeof(Netflow5Hdr))
        return false;

    version = ntohs(*((const uint16_t *)data));

    if( version == 5 )
    {
        retval = decode_netflow_v5(data, size);
        if ( retval )
        {
            ++netflow_stats.packets;
            ++netflow_stats.version_5;
        }
    }
    else if (version == 9)
    {
        retval = decode_netflow_v9(data, size);
        if ( retval )
        {
            ++netflow_stats.packets;
            ++netflow_stats.version_9;
        }
    }

    return retval;
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

void NetflowInspector::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data));

    if ( ! validate_netflow(p) )
        ++netflow_stats.invalid_netflow_pkts;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* netflow_mod_ctor()
{ return new NetflowModule; }

static void netflow_mod_dtor(Module* m)
{ delete m; }

static Inspector* netflow_ctor(Module* m)
{ return new NetflowInspector((NetflowModule*)m); }

static void netflow_dtor(Inspector* p)
{ delete p; }

static const InspectApi netflow_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        NETFLOW_NAME,
        NETFLOW_HELP,
        netflow_mod_ctor,
        netflow_mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__UDP,
    nullptr,    // buffers
    "netflow",  // service
    nullptr,
    nullptr,    //pterm
    nullptr,    // pre-config tinit
    nullptr,    // pre-config tterm
    netflow_ctor,
    netflow_dtor,
    nullptr,    // ssn
    nullptr     // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_netflow[] =
#endif
{
    &netflow_api.base,
    nullptr
};
