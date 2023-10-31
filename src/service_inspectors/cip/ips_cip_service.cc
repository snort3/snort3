//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

// ips_cip_service.cc author Jian Wu <jiawu2@cisco.com>

/* Description: Rule options for CIP inspector */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "cip.h"

using namespace snort;

#define s_name "cip_service"
#define s_help \
    "detection option to match CIP service"

//-------------------------------------------------------------------------
// CIP Service rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats cip_service_perf_stats;

class CipServiceOption : public IpsOption
{
public:
    CipServiceOption(const RangeCheck& v) : IpsOption(s_name), cip_serv(v)
    { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck cip_serv;
};

uint32_t CipServiceOption::hash() const
{
    uint32_t a = cip_serv.hash();
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;

    mix(a, b, c);
    finalize(a,b,c);
    return c;
}

bool CipServiceOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const CipServiceOption& rhs = static_cast<const CipServiceOption&>(ips);
    return ( cip_serv == rhs.cip_serv );
}

IpsOption::EvalStatus CipServiceOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(cip_service_perf_stats);

    if ( !p->flow || !p->is_full_pdu() )
        return NO_MATCH;

    CipFlowData* fd = static_cast<CipFlowData*>(p->flow->get_flow_data(CipFlowData::inspector_id));

    if (!fd)
        return NO_MATCH;

    CipSessionData* session_data = &fd->session;

    if (session_data->current_data.cip_message_type != CipMessageTypeExplicit)
    {
        return NO_MATCH;
    }

    if (session_data->current_data.cip_msg.is_cip_request)
    {
        if ( cip_serv.eval(session_data->current_data.cip_msg.request.service) )
            return MATCH;
    }
    else
    {
        if ( cip_serv.eval(session_data->current_data.cip_msg.response.service) )
            return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:127"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "match CIP service" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class CipServiceModule : public Module
{
public:
    CipServiceModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck cip_serv;
};

bool CipServiceModule::begin(const char*, int, SnortConfig*)
{
    cip_serv.init();
    return true;
}

bool CipServiceModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~range"));
    return cip_serv.validate(v.get_string(), RANGE);
}

ProfileStats* CipServiceModule::get_profile() const
{
    return &cip_service_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* cip_service_mod_ctor()
{
    return new CipServiceModule;
}

static void cip_service_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* cip_service_ctor(Module* p, OptTreeNode*)
{
    CipServiceModule* m = static_cast<CipServiceModule*>(p);
    return new CipServiceOption(m->cip_serv);
}

static void cip_service_dtor(IpsOption* p)
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
        cip_service_mod_ctor,
        cip_service_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    cip_service_ctor,
    cip_service_dtor,
    nullptr
};

const BaseApi* ips_cip_service = &ips_api.base;

