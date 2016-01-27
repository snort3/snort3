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

#include "dce2_smb.h"
#include "dce2_smb_module.h"
#include "dce2_list.h"

THREAD_LOCAL dce2SmbStats dce2_smb_stats;

THREAD_LOCAL ProfileStats dce2_smb_pstat_main;
THREAD_LOCAL ProfileStats dce2_smb_pstat_session;
THREAD_LOCAL ProfileStats dce2_smb_pstat_new_session;
THREAD_LOCAL ProfileStats dce2_smb_pstat_session_state;
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
    nullptr,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce2_smb_ctor,
    dce2_smb_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dce2_smb_api.base,
    ips_dce_iface,
    ips_dce_opnum,
    ips_dce_stub_data,
    nullptr
};
#else
const BaseApi* sin_dce_smb = &dce2_smb_api.base;
#endif

