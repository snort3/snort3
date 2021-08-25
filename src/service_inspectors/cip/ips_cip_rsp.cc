//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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

// ips_cip_rsp.cc author Jian Wu <jiawu2@cisco.com>

/* Description: Rule options for CIP inspector */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "cip.h"

using namespace snort;

#define s_name "cip_rsp"
#define s_help \
    "detection option to match CIP response"

//-------------------------------------------------------------------------
// CIP Rsp rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats cip_rsp_perf_stats;

class CipRspOption : public IpsOption
{
public:
    CipRspOption() : IpsOption(s_name) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;
};

uint32_t CipRspOption::hash() const
{
    uint32_t a = IpsOption::hash(), b = 0, c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool CipRspOption::operator==(const IpsOption& ips) const
{
    return IpsOption::operator==(ips);
}

IpsOption::EvalStatus CipRspOption::eval(Cursor&, Packet* p)
{
    Profile profile(cip_rsp_perf_stats);

    if ( !p->flow || !p->is_full_pdu() )
        return NO_MATCH;

    CipFlowData* fd = static_cast<CipFlowData*>(p->flow->get_flow_data(CipFlowData::inspector_id));

    if (!fd)
        return NO_MATCH;

    CipSessionData* session_data = &fd->session;

    if (session_data->current_data.cip_message_type == CipMessageTypeExplicit
        && !session_data->current_data.cip_msg.is_cip_request)
    {
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class CipRspModule : public Module
{
public:
    CipRspModule() : Module(s_name, s_help) { }
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }
};

ProfileStats* CipRspModule::get_profile() const
{
    return &cip_rsp_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* cip_rsp_mod_ctor()
{
    return new CipRspModule;
}

static void cip_rsp_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* cip_rsp_ctor(Module*, OptTreeNode*)
{
    return new CipRspOption;
}

static void cip_rsp_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        cip_rsp_mod_ctor,
        cip_rsp_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    cip_rsp_ctor,
    cip_rsp_dtor,
    nullptr
};

const BaseApi* ips_cip_rsp = &ips_api.base;

