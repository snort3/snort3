//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// dce_udp.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_udp.h"

#include "detection/detection_engine.h"
#include "utils/util.h"

#include "dce_context_data.h"
#include "dce_udp_module.h"

using namespace snort;

THREAD_LOCAL dce2UdpStats dce2_udp_stats;

THREAD_LOCAL ProfileStats dce2_udp_pstat_main;
THREAD_LOCAL ProfileStats dce2_udp_pstat_session;
THREAD_LOCAL ProfileStats dce2_udp_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_udp_pstat_detect;
THREAD_LOCAL ProfileStats dce2_udp_pstat_log;
THREAD_LOCAL ProfileStats dce2_udp_pstat_cl_acts;
THREAD_LOCAL ProfileStats dce2_udp_pstat_cl_frag;
THREAD_LOCAL ProfileStats dce2_udp_pstat_cl_reass;

static void DCE2_ClCleanTracker(DCE2_ClTracker* clt)
{
    if (clt == nullptr)
        return;

    /* Destroy activity trackers list - this will have the
     * effect of freeing everything inside of it */
    DCE2_ListDestroy(clt->act_trackers);
    clt->act_trackers = nullptr;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Dce2UdpFlowData::Dce2UdpFlowData() : FlowData(inspector_id)
{
    dce2_udp_stats.concurrent_sessions++;
    if(dce2_udp_stats.max_concurrent_sessions < dce2_udp_stats.concurrent_sessions)
        dce2_udp_stats.max_concurrent_sessions = dce2_udp_stats.concurrent_sessions;
}

Dce2UdpFlowData::~Dce2UdpFlowData()
{
    DCE2_ClCleanTracker(&dce2_udp_session.cl_tracker);
    assert(dce2_udp_stats.concurrent_sessions > 0);
    dce2_udp_stats.concurrent_sessions--;
}

unsigned Dce2UdpFlowData::inspector_id = 0;

DCE2_UdpSsnData* get_dce2_udp_session_data(Flow* flow)
{
    Dce2UdpFlowData* fd = (Dce2UdpFlowData*)flow->get_flow_data(Dce2UdpFlowData::inspector_id);
    return fd ? &fd->dce2_udp_session : nullptr;
}

static DCE2_UdpSsnData* set_new_dce2_udp_session(Packet* p)
{
    Dce2UdpFlowData* fd = new Dce2UdpFlowData;

    memset(&fd->dce2_udp_session,0,sizeof(DCE2_UdpSsnData));
    p->flow->set_flow_data(fd);
    return(&fd->dce2_udp_session);
}

static DCE2_UdpSsnData* dce2_create_new_udp_session(Packet* p, dce2UdpProtoConf* config)
{
    Profile profile(dce2_udp_pstat_new_session);

    DCE2_UdpSsnData* dce2_udp_sess = set_new_dce2_udp_session(p);

    DCE2_ResetRopts(&dce2_udp_sess->sd, p);

    dce2_udp_stats.udp_sessions++;
    dce2_udp_sess->sd.trans = DCE2_TRANS_TYPE__UDP;
    dce2_udp_sess->sd.wire_pkt = p;
    dce2_udp_sess->sd.config = (void*)config;

    return dce2_udp_sess;
}

static DCE2_UdpSsnData* dce2_handle_udp_session(Packet* p, dce2UdpProtoConf* config)
{
    Profile profile(dce2_udp_pstat_session);

    DCE2_UdpSsnData* dce2_udp_sess =  get_dce2_udp_session_data(p->flow);

    if (dce2_udp_sess == nullptr)
    {
        dce2_udp_sess = dce2_create_new_udp_session(p, config);
    }

    return dce2_udp_sess;
}

class Dce2Udp : public Inspector
{
public:
    Dce2Udp(dce2UdpProtoConf&);
    void show(SnortConfig*) override;
    void eval(Packet*) override;
    void clear(Packet*) override;

private:
    dce2UdpProtoConf config;
};

Dce2Udp::Dce2Udp(dce2UdpProtoConf& pc)
{
    config = pc;
}

void Dce2Udp::show(SnortConfig*)
{
    print_dce2_udp_conf(config);
}

void Dce2Udp::eval(Packet* p)
{
    DCE2_UdpSsnData* dce2_udp_sess;
    Profile profile(dce2_udp_pstat_main);

    assert(p->flow);

    dce2_udp_sess = dce2_handle_udp_session(p, &config);

    if (dce2_udp_sess)
    {
        p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
        dce2_detected = 0;

        p->endianness = new DceEndianness();

        dce2_udp_stats.udp_pkts++;
        DCE2_ClProcess(&dce2_udp_sess->sd, &dce2_udp_sess->cl_tracker);

        if (!dce2_detected)
            DCE2_Detect(&dce2_udp_sess->sd);

        delete p->endianness;
        p->endianness = nullptr;
    }
}

void Dce2Udp::clear(Packet* p)
{
    DCE2_UdpSsnData* dce2_udp_sess = get_dce2_udp_session_data(p->flow);
    if ( dce2_udp_sess )
    {
        DCE2_ResetRopts(&dce2_udp_sess->sd, p);
    }

}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Dce2UdpModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* dce2_udp_ctor(Module* m)
{
    Dce2UdpModule* mod = (Dce2UdpModule*)m;
    dce2UdpProtoConf config;
    mod->get_data(config);
    return new Dce2Udp(config);
}

static void dce2_udp_dtor(Inspector* p)
{
    delete p;
}

static void dce2_udp_init()
{
    Dce2UdpFlowData::init();
    DceContextData::init(DCE2_TRANS_TYPE__UDP);
}

const InspectApi dce2_udp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE2_UDP_NAME,
        DCE2_UDP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__UDP,
    nullptr,  // buffers
    DCE_RPC_SERVICE_NAME,
    dce2_udp_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce2_udp_ctor,
    dce2_udp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

