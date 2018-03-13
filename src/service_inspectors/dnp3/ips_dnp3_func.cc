//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// ips_dnp3_func.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "dnp3.h"
#include "dnp3_map.h"

using namespace snort;

//-------------------------------------------------------------------------
// DNP3 function code rule options
//-------------------------------------------------------------------------

#define s_name "dnp3_func"
#define s_help \
    "detection option to check DNP3 function code"

static THREAD_LOCAL ProfileStats dnp3_func_perf_stats;

class Dnp3FuncOption : public IpsOption
{
public:
    Dnp3FuncOption(uint16_t v) : IpsOption(s_name)
    { func = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint16_t func;
};

uint32_t Dnp3FuncOption::hash() const
{
    uint32_t a = func, b = 0, c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool Dnp3FuncOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const Dnp3FuncOption& rhs = (const Dnp3FuncOption&)ips;
    return (func == rhs.func);
}

IpsOption::EvalStatus Dnp3FuncOption::eval(Cursor&, Packet* p)
{
    Profile profile(dnp3_func_perf_stats);

    if ((p->has_tcp_data() && !p->is_full_pdu()) || !p->flow || !p->dsize)
        return NO_MATCH;

    Dnp3FlowData* fd = (Dnp3FlowData*)p->flow->get_flow_data(Dnp3FlowData::inspector_id);

    if (!fd)
        return NO_MATCH;

    dnp3_session_data_t* dnp3_session = &fd->dnp3_session;
    dnp3_reassembly_data_t* rdata;

    if (dnp3_session->direction == DNP3_CLIENT)
        rdata = &(dnp3_session->client_rdata);
    else
        rdata = &(dnp3_session->server_rdata);

    /* Only evaluate rules against complete Application-layer fragments */
    if (rdata->state != DNP3_REASSEMBLY_STATE__DONE)
        return NO_MATCH;

    if (dnp3_session->func == func)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// dnp3_func module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "match DNP3 function code or name" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Dnp3FuncModule : public Module
{
public:
    Dnp3FuncModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }

public:
    uint16_t func;
};

ProfileStats* Dnp3FuncModule::get_profile() const
{
    return &dnp3_func_perf_stats;
}

bool Dnp3FuncModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~"))
        return false;

    long n;

    if (v.strtol(n))
    {
        if ((n > 255) || (n < 0))
            return false;
    }
    else
    {
        n = dnp3_func_str_to_code(v.get_string());
        if (n == -1)
            return false;
    }

    func = (uint16_t)n;

    return true;
}

//-------------------------------------------------------------------------
// dnp3_func api
//-------------------------------------------------------------------------

static Module* dnp3_func_mod_ctor()
{
    return new Dnp3FuncModule;
}

static void dnp3_func_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dnp3_func_ctor(Module* p, OptTreeNode*)
{
    Dnp3FuncModule* m = (Dnp3FuncModule*)p;
    return new Dnp3FuncOption(m->func);
}

static void dnp3_func_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dnp3_func_api =
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
        dnp3_func_mod_ctor,
        dnp3_func_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dnp3_func_ctor,
    dnp3_func_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in dnp3.cc
const BaseApi* ips_dnp3_func = &dnp3_func_api.base;

