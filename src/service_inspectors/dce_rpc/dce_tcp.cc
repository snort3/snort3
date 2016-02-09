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
#include "main/snort_debug.h"

THREAD_LOCAL dce2TcpStats dce2_tcp_stats;

THREAD_LOCAL ProfileStats dce2_tcp_pstat_main;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_session;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_tcp_pstat_session_state;
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
    DCE2_TcpSsnData* dce2_sess = get_dce2_tcp_session_data(p->flow);

    if (dce2_sess == nullptr)
    {
        /*Check if it is a DCE2 over TCP packet*/
       
        if (DCE2_TcpAutodetect(p))
        {
            DebugMessage(DEBUG_DCE_TCP, "DCE over TCP packet detected\n");
        }
        
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
    nullptr,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce2_tcp_ctor,
    dce2_tcp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

