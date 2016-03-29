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

// dce_smb.cc author Rashmi Pitre <rrp@cisco.com>

#include "dce_smb.h"
#include "dce_smb_paf.h"
#include "dce_smb_module.h"
#include "dce_list.h"
#include "main/snort_debug.h"
#include "file_api/file_service.h"
#include "utils/util.h"

THREAD_LOCAL int dce2_smb_inspector_instances = 0;

THREAD_LOCAL dce2SmbStats dce2_smb_stats;
THREAD_LOCAL Packet* dce2_smb_rpkt[DCE2_SMB_RPKT_TYPE_MAX] = { nullptr, nullptr, nullptr,
                                                               nullptr };

THREAD_LOCAL ProfileStats dce2_smb_pstat_main;
THREAD_LOCAL ProfileStats dce2_smb_pstat_session;
THREAD_LOCAL ProfileStats dce2_smb_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_smb_pstat_detect;
THREAD_LOCAL ProfileStats dce2_smb_pstat_log;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_seg;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_frag;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_reass;
THREAD_LOCAL ProfileStats dce2_smb_pstat_co_ctx;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_seg;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_req;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_uid;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_tid;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_fid;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file_detect;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file_api;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_fingerprint;
THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_negotiate;

Dce2SmbFlowData::Dce2SmbFlowData() : FlowData(flow_id)
{
}

unsigned Dce2SmbFlowData::flow_id = 0;

DCE2_SmbSsnData* get_dce2_smb_session_data(Flow* flow)
{
    Dce2SmbFlowData* fd = (Dce2SmbFlowData*)flow->get_application_data(
        Dce2SmbFlowData::flow_id);

    return fd ? &fd->dce2_smb_session : nullptr;
}

static DCE2_SmbSsnData* set_new_dce2_smb_session(Packet* p)
{
    Dce2SmbFlowData* fd = new Dce2SmbFlowData;

    memset(&fd->dce2_smb_session,0,sizeof(DCE2_SmbSsnData));
    p->flow->set_application_data(fd);
    return(&fd->dce2_smb_session);
}

static DCE2_SmbSsnData* dce2_create_new_smb_session(Packet* p, dce2SmbProtoConf* config)
{
    DCE2_SmbSsnData* dce2_smb_sess = nullptr;
    Profile profile(dce2_smb_pstat_new_session);

    //FIXIT-M Re-evaluate after infrastructure/binder support if autodetect here
    //is necessary

    if (DCE2_SmbAutodetect(p))
    {
        DebugMessage(DEBUG_DCE_SMB, "DCE over SMB packet detected\n");
        DebugMessage(DEBUG_DCE_SMB, "Creating new session\n");

        dce2_smb_sess = set_new_dce2_smb_session(p);
        if ( dce2_smb_sess )
        {
            dce2_smb_sess->dialect_index = DCE2_SENTINEL;
            dce2_smb_sess->max_outstanding_requests = 10;  // Until Negotiate/SessionSetupAndX
            dce2_smb_sess->cli_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
            dce2_smb_sess->srv_data_state = DCE2_SMB_DATA_STATE__NETBIOS_HEADER;
            dce2_smb_sess->pdu_state = DCE2_SMB_PDU_STATE__COMMAND;
            dce2_smb_sess->uid = DCE2_SENTINEL;
            dce2_smb_sess->tid = DCE2_SENTINEL;
            dce2_smb_sess->ftracker.fid = DCE2_SENTINEL;
            dce2_smb_sess->rtracker.mid = DCE2_SENTINEL;
            dce2_smb_sess->max_file_depth = FileService::get_max_file_depth();

            DCE2_ResetRopts(&dce2_smb_sess->sd.ropts);

            dce2_smb_stats.smb_sessions++;
            DebugFormat(DEBUG_DCE_SMB,"Created (%p)\n", (void*)dce2_smb_sess);

            dce2_smb_sess->sd.trans = DCE2_TRANS_TYPE__SMB;
            dce2_smb_sess->sd.server_policy = config->common.policy;
            dce2_smb_sess->sd.client_policy = DCE2_POLICY__WINXP;
            dce2_smb_sess->sd.wire_pkt = p;
            dce2_smb_sess->sd.config = (void*)config;

            DCE2_SsnSetAutodetected(&dce2_smb_sess->sd, p);
        }
    }

    return dce2_smb_sess;
}

static DCE2_SmbSsnData* dce2_handle_smb_session(Packet* p, dce2SmbProtoConf* config)
{
    Profile profile(dce2_smb_pstat_session);

    DCE2_SmbSsnData* dce2_smb_sess =  get_dce2_smb_session_data(p->flow);

    if (dce2_smb_sess == nullptr)
    {
        dce2_smb_sess = dce2_create_new_smb_session(p, config);
    }
    else
    {
        DCE2_SsnData* sd = (DCE2_SsnData*)dce2_smb_sess;
        sd->wire_pkt = p;

        if (DCE2_SsnAutodetected(sd) && !(p->packet_flags & sd->autodetect_dir))
        {
            /* Try to autodetect in opposite direction */
            if (!DCE2_SmbAutodetect(p))
            {
                DebugMessage(DEBUG_DCE_SMB, "Bad autodetect.\n");
                DCE2_SsnNoInspect(sd);
                dce2_smb_stats.sessions_aborted++;
                dce2_smb_stats.bad_autodetects++;
                return nullptr;
            }
            DCE2_SsnClearAutodetected(sd);
        }
    }
    DebugFormat(DEBUG_DCE_SMB, "Session pointer: %p\n", (void*)dce2_smb_sess);

    // FIXIT-M add remaining session handling logic

    return dce2_smb_sess;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dce2Smb : public Inspector
{
public:
    Dce2Smb(dce2SmbProtoConf&);
    ~Dce2Smb();

    void show(SnortConfig*) override;
    void eval(Packet*) override;
    StreamSplitter* get_splitter(bool c2s) override
    {
        return new Dce2SmbSplitter(c2s);
    }

private:
    dce2SmbProtoConf config;
};

Dce2Smb::Dce2Smb(dce2SmbProtoConf& pc)
{
    config = pc;
}

Dce2Smb::~Dce2Smb()
{
    if (config.smb_invalid_shares)
    {
        DCE2_ListDestroy(config.smb_invalid_shares);
    }
}

void Dce2Smb::show(SnortConfig*)
{
    print_dce2_smb_conf(config);
}

void Dce2Smb::eval(Packet* p)
{
    DCE2_SmbSsnData* dce2_smb_sess;
    Profile profile(dce2_smb_pstat_main);

    assert(p->has_tcp_data());
    assert(p->flow);

    if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
    {
        DebugMessage(DEBUG_DCE_SMB,
            "Midstream - not inspecting.\n");
        return;
    }

    dce2_smb_sess = dce2_handle_smb_session(p, &config);
    if (!dce2_smb_sess)
    {
        return;
    }
    dce2_smb_stats.smb_pkts++;

    // FIXIT-L - when porting processing code also add DceEndianness allocation
    // (see dce_tcp.cc eval)
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Dce2SmbModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void dce2_smb_init()
{
    Dce2SmbFlowData::init();
}

static Inspector* dce2_smb_ctor(Module* m)
{
    Dce2SmbModule* mod = (Dce2SmbModule*)m;
    dce2SmbProtoConf config;
    mod->get_data(config);
    return new Dce2Smb(config);
}

static void dce2_smb_dtor(Inspector* p)
{
    delete p;
}

static void dce2_smb_thread_init()
{
    if (dce2_inspector_instances == 0)
    {
        dce2_pkt_stack = DCE2_CStackNew(DCE2_PKT_STACK__SIZE, nullptr);
    }
    if (dce2_smb_inspector_instances == 0)
    {
        for (int i=0; i < DCE2_SMB_RPKT_TYPE_MAX; i++)
        {
            Packet* p = (Packet*)SnortAlloc(sizeof(Packet));
            p->data = (uint8_t*)SnortAlloc(DCE2_REASSEMBLY_BUF_SIZE);
            p->dsize = DCE2_REASSEMBLY_BUF_SIZE;
            dce2_smb_rpkt[i] = p;
        }
    }
    dce2_smb_inspector_instances++;
    dce2_inspector_instances++;
}

static void dce2_smb_thread_term()
{
    dce2_inspector_instances--;
    dce2_smb_inspector_instances--;

    if (dce2_smb_inspector_instances == 0)
    {
        for (int i=0; i<DCE2_SMB_RPKT_TYPE_MAX; i++)
        {
            if ( dce2_smb_rpkt[i] != nullptr )
            {
                Packet* p = dce2_smb_rpkt[i];
                if (p->data)
                {
                    free((void*)p->data);
                }
                free(p);
                dce2_smb_rpkt[i] = nullptr;
            }
        }
    }
    if (dce2_inspector_instances == 0)
    {
        DCE2_CStackDestroy(dce2_pkt_stack);
        dce2_pkt_stack = nullptr;
    }
}

const InspectApi dce2_smb_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE2_SMB_NAME,
        DCE2_SMB_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr,  // buffers
    "dce_smb",
    dce2_smb_init,
    nullptr, // pterm
    dce2_smb_thread_init, // tinit
    dce2_smb_thread_term, // tterm
    dce2_smb_ctor,
    dce2_smb_dtor,
    nullptr, // ssn
    nullptr  // reset
};

