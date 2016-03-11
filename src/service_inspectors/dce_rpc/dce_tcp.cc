//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "dce_tcp.h"
#include "dce_tcp_paf.h"
#include "dce_tcp_module.h"
#include "dce_co.h"
#include "main/snort_debug.h"
#include "detection/detect.h"

Dce2TcpFlowData::Dce2TcpFlowData() : FlowData(flow_id)
{
}

THREAD_LOCAL dce2TcpStats dce2_tcp_stats;

THREAD_LOCAL ProfileStats dce2_tcp_pstat_main;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_session;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_detect;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_log;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_seg;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_frag;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_reass;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_co_ctx;

unsigned Dce2TcpFlowData::flow_id = 0;

DCE2_TcpSsnData* get_dce2_tcp_session_data(Flow* flow)
{
    Dce2TcpFlowData* fd = (Dce2TcpFlowData*)flow->get_application_data(
        Dce2TcpFlowData::flow_id);

    return fd ? &fd->dce2_tcp_session : nullptr;
}

static DCE2_TcpSsnData* set_new_dce2_tcp_session(Packet* p)
{
    Dce2TcpFlowData* fd = new Dce2TcpFlowData;

    p->flow->set_application_data(fd);
    return(&fd->dce2_tcp_session);
}

static DCE2_TcpSsnData* dce2_create_new_tcp_session(Packet* p, dce2TcpProtoConf* config)
{
    DCE2_TcpSsnData* dce2_tcp_sess = nullptr;
    Profile profile(dce2_tcp_pstat_new_session);

    //FIXIT-M Re-evaluate after infrastructure/binder support if autodetect here
    //is necessary
    if (DCE2_TcpAutodetect(p))
    {
        DebugMessage(DEBUG_DCE_TCP, "DCE over TCP packet detected\n");
        DebugMessage(DEBUG_DCE_TCP, "Creating new session\n");

        dce2_tcp_sess = set_new_dce2_tcp_session(p);

        if ( dce2_tcp_sess )
        {
            DCE2_CoInitTracker(&dce2_tcp_sess->co_tracker);
            DCE2_ResetRopts(&dce2_tcp_sess->sd.ropts);

            dce2_tcp_stats.tcp_sessions++;
            DebugFormat(DEBUG_DCE_TCP,"Created (%p)\n", (void*)dce2_tcp_sess);

            dce2_tcp_sess->sd.trans = DCE2_TRANS_TYPE__TCP;
            dce2_tcp_sess->sd.server_policy = config->common.policy;
            dce2_tcp_sess->sd.client_policy = DCE2_POLICY__WINXP;
            dce2_tcp_sess->sd.wire_pkt = p;
            dce2_tcp_sess->sd.config = (void*)config;

            DCE2_SsnSetAutodetected(&dce2_tcp_sess->sd, p);
        }
    }

    return dce2_tcp_sess;
}

static DCE2_TcpSsnData* dce2_handle_tcp_session(Packet* p, dce2TcpProtoConf* config)
{
    Profile profile(dce2_tcp_pstat_session);

    DCE2_TcpSsnData* dce2_tcp_sess =  get_dce2_tcp_session_data(p->flow);

    if (dce2_tcp_sess == nullptr)
    {
        dce2_tcp_sess = dce2_create_new_tcp_session(p, config);
    }
    else
    {
        DCE2_SsnData* sd = (DCE2_SsnData*)dce2_tcp_sess;
        sd->wire_pkt = p;

        if (DCE2_SsnAutodetected(sd) && !(p->packet_flags & sd->autodetect_dir))
        {
            /* Try to autodetect in opposite direction */
            if (!DCE2_TcpAutodetect(p))
            {
                DebugMessage(DEBUG_DCE_TCP, "Bad autodetect.\n");
                DCE2_SsnNoInspect(sd);
                dce2_tcp_stats.sessions_aborted++;
                dce2_tcp_stats.bad_autodetects++;
                return nullptr;
            }

            DCE2_SsnClearAutodetected(sd);
        }
    }

    DebugFormat(DEBUG_DCE_TCP, "Session pointer: %p\n", (void*)dce2_tcp_sess);
    if (dce2_tcp_sess)
    {
        //FIXIT-M Stack push

        p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
        dce2_detected = 0;
    }

    return dce2_tcp_sess;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dce2Tcp : public Inspector
{
public:
    Dce2Tcp(dce2TcpProtoConf&);

    void show(SnortConfig*) override;
    void eval(Packet*) override;
    StreamSplitter* get_splitter(bool c2s) override
    {
        return new Dce2TcpSplitter(c2s);
    }

private:
    dce2TcpProtoConf config;
};

Dce2Tcp::Dce2Tcp(dce2TcpProtoConf& pc)
{
    config = pc;
}

void Dce2Tcp::show(SnortConfig*)
{
    print_dce2_tcp_conf(config);
}

void Dce2Tcp::eval(Packet* p)
{
    DCE2_TcpSsnData* dce2_tcp_sess;
    Profile profile(dce2_tcp_pstat_main);
    if (DCE2_SsnFromServer(p))
    {
        DebugMessage(DEBUG_DCE_TCP, "Packet from Server.\n");
    }
    else
    {
        DebugMessage(DEBUG_DCE_TCP, "Packet from Client.\n");
    }

    assert(p->has_tcp_data());
    assert(p->flow);

    if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
    {
        DebugMessage(DEBUG_DCE_TCP,
            "Midstream - not inspecting.\n");
        return;
    }

    dce2_tcp_sess = dce2_handle_tcp_session(p, &config);
    if (dce2_tcp_sess)
    {
        dce2_tcp_stats.tcp_pkts++;
        DCE2_CoProcess(&dce2_tcp_sess->sd, &dce2_tcp_sess->co_tracker, p->data,
            p->dsize);

        if (!dce2_detected)
            DCE2_Detect(&dce2_tcp_sess->sd);

        DCE2_ResetRopts(&dce2_tcp_sess->sd.ropts);
        //FIXIT-M DCE2_PopPkt(sd);

        if (!DCE2_SsnAutodetected(&dce2_tcp_sess->sd))
            DisableInspection();
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
}

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
    (uint16_t)PktType::PDU,
    nullptr,  // buffers
    "dce_tcp",
    dce2_tcp_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce2_tcp_ctor,
    dce2_tcp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

