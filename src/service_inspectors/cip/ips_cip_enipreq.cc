//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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

// ips_cip_enipreq.cc author Jian Wu <jiawu2@cisco.com>

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

#define s_name "enip_req"
#define s_help \
    "detection option to match ENIP Request"

//-------------------------------------------------------------------------
// CIP Enipreq rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats cip_enipreq_perf_stats;

class CipEnipreqOption : public IpsOption
{
public:
    CipEnipreqOption() : IpsOption(s_name) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;
};

uint32_t CipEnipreqOption::hash() const
{
    uint32_t a = IpsOption::hash(), b = 0, c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool CipEnipreqOption::operator==(const IpsOption& ips) const
{
    return IpsOption::operator==(ips);
}

IpsOption::EvalStatus CipEnipreqOption::eval(Cursor&, Packet* p)
{
    Profile profile(cip_enipreq_perf_stats);

    if ( !p->flow || !p->is_full_pdu() )
        return NO_MATCH;

    CipFlowData* fd = static_cast<CipFlowData*>(p->flow->get_flow_data(CipFlowData::inspector_id));

    if (!fd)
        return NO_MATCH;

    CipSessionData* session_data = &fd->session;

    if (session_data->current_data.direction == CIP_FROM_CLIENT)
    {
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class CipEnipreqModule : public Module
{
public:
    CipEnipreqModule() : Module(s_name, s_help) { }
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }
};

ProfileStats* CipEnipreqModule::get_profile() const
{
    return &cip_enipreq_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* cip_enipreq_mod_ctor()
{
    return new CipEnipreqModule;
}

static void cip_enipreq_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* cip_enipreq_ctor(Module*, OptTreeNode*)
{
    return new CipEnipreqOption;
}

static void cip_enipreq_dtor(IpsOption* p)
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
        cip_enipreq_mod_ctor,
        cip_enipreq_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    cip_enipreq_ctor,
    cip_enipreq_dtor,
    nullptr
};

const BaseApi* ips_cip_enipreq = &ips_api.base;

