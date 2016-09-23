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

// dce_udp.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#include "dce_udp.h"
#include "dce_udp_module.h"
#include "main/snort_debug.h"
#include "detection/detect.h"
#include "log/messages.h"
#include "protocols/packet_manager.h"
#include "utils/util.h"

THREAD_LOCAL int dce2_udp_inspector_instances = 0;

THREAD_LOCAL dce2UdpStats dce2_udp_stats;

THREAD_LOCAL ProfileStats dce2_udp_pstat_main;
THREAD_LOCAL ProfileStats dce2_udp_pstat_session;
THREAD_LOCAL ProfileStats dce2_udp_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_udp_pstat_detect;
THREAD_LOCAL ProfileStats dce2_udp_pstat_log;
THREAD_LOCAL ProfileStats dce2_udp_pstat_cl_acts;
THREAD_LOCAL ProfileStats dce2_udp_pstat_cl_frag;
THREAD_LOCAL ProfileStats dce2_udp_pstat_cl_reass;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Dce2UdpFlowData::Dce2UdpFlowData() : FlowData(flow_id)
{
}

Dce2UdpFlowData::~Dce2UdpFlowData()
{
    // FIXIT-M add cl_tracker cleanup
}

unsigned Dce2UdpFlowData::flow_id = 0;

class Dce2Udp : public Inspector
{
public:
    Dce2Udp(dce2UdpProtoConf&);
    void show(SnortConfig*) override;
    void eval(Packet*) override;

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

void Dce2Udp::eval(Packet*)
{
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
}

static void dce2_udp_thread_init()
{
    dce2_udp_inspector_instances++;
}

static void dce2_udp_thread_term()
{
    dce2_udp_inspector_instances--;
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
    (uint16_t)PktType::UDP,
    nullptr,  // buffers
    "dce_udp",
    dce2_udp_init,
    nullptr, // pterm
    dce2_udp_thread_init, // tinit
    dce2_udp_thread_term, // tterm
    dce2_udp_ctor,
    dce2_udp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

