//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

// dce_tcp.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_tcp.h"

#include "detection/detection_engine.h"
#include "utils/util.h"

#include "dce_context_data.h"
#include "dce_common.h"

using namespace snort;

Dce2TcpFlowData::Dce2TcpFlowData() : FlowData(inspector_id)
{
    dce2_tcp_stats.concurrent_sessions++;
    if(dce2_tcp_stats.max_concurrent_sessions < dce2_tcp_stats.concurrent_sessions)
        dce2_tcp_stats.max_concurrent_sessions = dce2_tcp_stats.concurrent_sessions;
}

Dce2TcpFlowData::~Dce2TcpFlowData()
{
    DCE2_CoCleanTracker(&dce2_tcp_session.co_tracker);
    assert(dce2_tcp_stats.concurrent_sessions > 0);
    dce2_tcp_stats.concurrent_sessions--;
}

THREAD_LOCAL dce2TcpStats dce2_tcp_stats;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_main;

unsigned Dce2TcpFlowData::inspector_id = 0;

DCE2_TcpSsnData* get_dce2_tcp_session_data(Flow* flow)
{
    Dce2TcpFlowData* fd = (Dce2TcpFlowData*)flow->get_flow_data(Dce2TcpFlowData::inspector_id);

    // check whether this session was expected and mark it as realized
    if (fd && fd->state == DCE2_TCP_FLOW__EXPECTED)
    {
        fd->state = DCE2_TCP_FLOW__REALIZED;
        dce2_tcp_stats.tcp_expected_realized_sessions++;
    }
    return fd ? &fd->dce2_tcp_session : nullptr;
}

static DCE2_TcpSsnData* set_new_dce2_tcp_session(Packet* p)
{
    Dce2TcpFlowData* fd = new Dce2TcpFlowData;

    fd->state = DCE2_TCP_FLOW__COMMON;
    memset(&fd->dce2_tcp_session,0,sizeof(DCE2_TcpSsnData));
    p->flow->set_flow_data(fd);
    return(&fd->dce2_tcp_session);
}

static DCE2_TcpSsnData* dce2_create_new_tcp_session(Packet* p, dce2TcpProtoConf* config)
{
    DCE2_TcpSsnData* dce2_tcp_sess = set_new_dce2_tcp_session(p);

    if ( dce2_tcp_sess )
    {
        DCE2_CoInitTracker(&dce2_tcp_sess->co_tracker);
        DCE2_ResetRopts(&dce2_tcp_sess->sd, p);

        dce2_tcp_stats.tcp_sessions++;

        dce2_tcp_sess->sd.trans = DCE2_TRANS_TYPE__TCP;
        dce2_tcp_sess->sd.server_policy = config->common.policy;
        dce2_tcp_sess->sd.client_policy = DCE2_POLICY__WINXP;
        dce2_tcp_sess->sd.config = (void*)config;
    }

    return dce2_tcp_sess;
}

static DCE2_TcpSsnData* dce2_handle_tcp_session(Packet* p, dce2TcpProtoConf* config)
{
    DCE2_TcpSsnData* dce2_tcp_sess =  get_dce2_tcp_session_data(p->flow);

    if (dce2_tcp_sess == nullptr)
    {
        dce2_tcp_sess = dce2_create_new_tcp_session(p, config);
    }

    return dce2_tcp_sess;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Dce2Tcp::Dce2Tcp(const dce2TcpProtoConf& pc) :
    config(pc), esm(config) {}

bool Dce2Tcp::configure(snort::SnortConfig* sc)
{
    esm.set_proto_id(sc->proto_ref->add(DCE_RPC_SERVICE_NAME));
    return true;
}

void Dce2Tcp::show(const SnortConfig*) const
{
    print_dce2_tcp_conf(config);
}

void Dce2Tcp::eval(Packet* p)
{
    DCE2_TcpSsnData* dce2_tcp_sess;
    Profile profile(dce2_tcp_pstat_main);

    assert(p->has_tcp_data());
    assert(p->flow);

    if ( p->test_session_flags(SSNFLAG_MIDSTREAM) )
    {
        return;
    }

    dce2_tcp_sess = dce2_handle_tcp_session(p, &config);

    if (dce2_tcp_sess)
    {
        p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
        dce2_detected = 0;
        dce2_tcp_stats.tcp_pkts++;
        p->endianness = new DceEndianness();
        DCE2_CoProcess(&dce2_tcp_sess->sd, &dce2_tcp_sess->co_tracker, p->data, p->dsize);

        if (!dce2_detected)
            DCE2_Detect(&dce2_tcp_sess->sd);

        delete p->endianness;
        p->endianness = nullptr;
    }
}

void Dce2Tcp::clear(Packet* p)
{
    DCE2_TcpSsnData* dce2_tcp_sess = get_dce2_tcp_session_data(p->flow);
    if ( dce2_tcp_sess )
    {
        DCE2_ResetRopts(&dce2_tcp_sess->sd, p);
    }

}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Dce2TcpModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* dce2_tcp_ctor(Module* m)
{
    Dce2TcpModule* mod = (Dce2TcpModule*)m;
    dce2TcpProtoConf config;
    mod->get_data(config);
    return new Dce2Tcp(config);
}

static void dce2_tcp_dtor(Inspector* p)
{
    delete p;
}

static void dce2_tcp_init()
{
    Dce2TcpFlowData::init();
    DceContextData::init(DCE2_TRANS_TYPE__TCP);
}

static const char* dce2_tcp_bufs[] =
{
    "dce_iface",
    "dce_stub_data",
    "file_data",
    nullptr
};

const InspectApi dce2_tcp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE2_TCP_NAME,
        DCE2_TCP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    dce2_tcp_bufs,
    DCE_RPC_SERVICE_NAME,
    dce2_tcp_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce2_tcp_ctor,
    dce2_tcp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

