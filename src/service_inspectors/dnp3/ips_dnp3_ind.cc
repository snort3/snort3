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

// ips_dnp3_ind.cc author Maya Dagon <mdagon@cisco.com>
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
// DNP3 indicator flags rule options
//-------------------------------------------------------------------------

#define s_name "dnp3_ind"
#define s_help \
    "detection option to check DNP3 indicator flags"

static THREAD_LOCAL ProfileStats dnp3_ind_perf_stats;

class Dnp3IndOption : public IpsOption
{
public:
    Dnp3IndOption(uint16_t v) : IpsOption(s_name)
    { flags = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint16_t flags;
};

uint32_t Dnp3IndOption::hash() const
{
    uint32_t a = flags, b = 0, c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool Dnp3IndOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const Dnp3IndOption& rhs = (const Dnp3IndOption&)ips;

    return (flags == rhs.flags);
}

IpsOption::EvalStatus Dnp3IndOption::eval(Cursor&, Packet* p)
{
    Profile profile(dnp3_ind_perf_stats);

    if ((p->has_tcp_data() && !p->is_full_pdu()) || !p->flow || !p->dsize)
        return NO_MATCH;

    Dnp3FlowData* fd = (Dnp3FlowData*)p->flow->get_flow_data(Dnp3FlowData::inspector_id);

    if (!fd)
        return NO_MATCH;

    dnp3_session_data_t* dnp3_session = &fd->dnp3_session;

    /* Internal Indications only apply to DNP3 responses, not requests. */
    if (dnp3_session->direction == DNP3_CLIENT)
        return NO_MATCH;

    dnp3_reassembly_data_t* rdata = &(dnp3_session->server_rdata);

    /* Only evaluate rules against complete Application-layer fragments */
    if (rdata->state != DNP3_REASSEMBLY_STATE__DONE)
        return NO_MATCH;

    if (dnp3_session->indications & flags)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// dnp3_ind module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "match given DNP3 indicator flags" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Dnp3IndModule : public Module
{
public:
    Dnp3IndModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }

public:
    uint16_t flags;
};

bool Dnp3IndModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    flags = 0;

    v.set_first_token();
    std::string tok;

    while ( v.get_next_token(tok) )
    {
        int flag;

        if ( tok[0] == '"' )
            tok.erase(0, 1);

        if ( tok[tok.length()-1] == '"' )
            tok.erase(tok.length()-1, 1);

        flag = dnp3_ind_str_to_code(tok.c_str());
        if ( flag == -1 )
            return false;

        flags |= (uint16_t)flag;
    }
    return true;
}

ProfileStats* Dnp3IndModule::get_profile() const
{
    return &dnp3_ind_perf_stats;
}

//-------------------------------------------------------------------------
// dnp3_ind api
//-------------------------------------------------------------------------

static Module* dnp3_ind_mod_ctor()
{
    return new Dnp3IndModule;
}

static void dnp3_ind_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dnp3_ind_ctor(Module* p, OptTreeNode*)
{
    Dnp3IndModule* m = (Dnp3IndModule*)p;
    return new Dnp3IndOption(m->flags);
}

static void dnp3_ind_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dnp3_ind_api =
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
        dnp3_ind_mod_ctor,
        dnp3_ind_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dnp3_ind_ctor,
    dnp3_ind_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in dnp3.cc
const BaseApi* ips_dnp3_ind = &dnp3_ind_api.base;

