//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// opcua.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "opcua_session.h"
#include "opcua_decode.h"
#include "opcua_module.h"
#include "opcua_splitter.h"

using namespace snort;

// Indices in the buffer array exposed by InspectApi
// Must remain synchronized with opcua_bufs
enum OpcuaBufId
{
    OPCUA_DATA_BUFID = 1
};

THREAD_LOCAL OpcuaStats opcua_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned OpcuaFlowData::inspector_id = 0;

void OpcuaFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

OpcuaFlowData::OpcuaFlowData() :
    FlowData(inspector_id)
{
    opcua_stats.concurrent_sessions++;
    if (opcua_stats.max_concurrent_sessions < opcua_stats.concurrent_sessions)
    {
        opcua_stats.max_concurrent_sessions = opcua_stats.concurrent_sessions;
    }
}

OpcuaFlowData::~OpcuaFlowData()
{
    reset();

    delete [] client_ssn_data.chunk_data;
    delete [] server_ssn_data.chunk_data;

    assert(opcua_stats.concurrent_sessions > 0);
    opcua_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Opcua : public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet*) override;

    uint32_t get_message_type(uint32_t version, const char* name);
    uint32_t get_info_type(uint32_t version, const char* name);

    StreamSplitter* get_splitter(bool c2s) override
    {
        return new OpcuaSplitter(c2s);
    }
};

void Opcua::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(opcua_prof);

    assert(p->has_tcp_data());

    OpcuaFlowData* opcuafd = (OpcuaFlowData*)p->flow->get_flow_data(OpcuaFlowData::inspector_id);

    // not including any checks for a full PDU as we're not guaranteed to
    // have one with the available pipelining options to get to OPC UA

    if (!opcuafd)
    {
        opcuafd = new OpcuaFlowData;
        p->flow->set_flow_data(opcuafd);
        opcuafd->reset();
        opcua_stats.sessions++;
    }

    opcua_stats.frames++;

    // When pipelined OPC UA PDUs appear in a single TCP segment, the
    // detection engine caches the results of the rule options after
    // evaluating on the first PDU. Setting this flag stops the caching.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    if (!opcua_decode(p, opcuafd))
    {
        opcuafd->reset();
    }
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new OpcuaModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void opcua_init()
{
    OpcuaFlowData::init();
}

static Inspector* opcua_ctor(Module*)
{
    return new Opcua;
}

static void opcua_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const char* opcua_bufs[] =
{
    nullptr
};

static const InspectApi opcua_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        OPCUA_NAME,
        OPCUA_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    opcua_bufs,
    "opcua",
    opcua_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    opcua_ctor,
    opcua_dtor,
    nullptr, // ssn
    nullptr  // reset
};

// BaseApi for each rule option
extern const BaseApi* ips_opcua_msg_type;
extern const BaseApi* ips_opcua_msg_service;
extern const BaseApi* ips_opcua_node_id;
extern const BaseApi* ips_opcua_node_namespace_index;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi * sin_opcua[] =
#endif
{
    &opcua_api.base,
    ips_opcua_msg_type,
    ips_opcua_msg_service,
    ips_opcua_node_id,
    ips_opcua_node_namespace_index,
    nullptr
};

