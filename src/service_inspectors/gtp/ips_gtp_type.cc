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

// ips_gtp_type.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// gtp_type rule option implementation

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "gtp.h"
#include "gtp_inspect.h"

using namespace snort;

static const char* s_name = "gtp_type";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats gtp_type_prof;

class GtpTypeOption : public IpsOption
{
public:
    GtpTypeOption(ByteBitSet*);

    CursorActionType get_cursor_type() const override
    { return CAT_SET_OTHER; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    // set n is for version n (named types can have 
    // different codes in different versions)
    ByteBitSet types[MAX_GTP_VERSION_CODE + 1];
};

GtpTypeOption::GtpTypeOption(ByteBitSet* t) : IpsOption(s_name)
{
    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        types[v] = t[v];
}

uint32_t GtpTypeOption::hash() const
{
    assert(MAX_GTP_VERSION_CODE == 2);

    uint32_t a = types[0].count();
    uint32_t b = types[1].count();
    uint32_t c = types[2].count();

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool GtpTypeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const GtpTypeOption& rhs = (const GtpTypeOption&)ips;

    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        if ( types[v] != rhs.types[v] )
            return false;

    return true;
}

IpsOption::EvalStatus GtpTypeOption::eval(Cursor&, Packet* p)
{
    Profile profile(gtp_type_prof);

    if ( !p or !p->flow )
        return NO_MATCH;

    GtpFlowData* gfd = (GtpFlowData*)p->flow->get_flow_data(GtpFlowData::inspector_id);

    if ( !gfd )
        return NO_MATCH;

    GTP_Roptions& ropts = gfd->ropts;

    if ( !types[ropts.gtp_version].test(ropts.gtp_type) )
        return NO_MATCH;

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "list of types to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check gtp types"

class GtpTypeModule : public Module
{
public:
    GtpTypeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    bool set_types(long);
    bool set_types(const char*);

    ProfileStats* get_profile() const override
    { return &gtp_type_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    ByteBitSet types[MAX_GTP_VERSION_CODE + 1];
};

bool GtpTypeModule::begin(const char*, int, SnortConfig*)
{
    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        types[v].reset();

    return true;
}

bool GtpTypeModule::set_types(long t)
{
    if ( t < MIN_GTP_TYPE_CODE or t > MAX_GTP_TYPE_CODE )
        return false;

    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        types[v].set((uint8_t)t);

    return true;
}

bool GtpTypeModule::set_types(const char* name)
{
    bool ok = false;

    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
    {
        int t = get_message_type(v, name);

        if ( t < 0 )
            continue;

        types[v].set((uint8_t)t);
        ok = true;
    }
    return ok;
}

bool GtpTypeModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    v.set_first_token();
    std::string tok;

    while ( v.get_next_token(tok) )
    {
        long n;

        if ( tok[0] == '"' )
            tok.erase(0, 1);

        if ( tok[tok.length()-1] == '"' )
            tok.erase(tok.length()-1, 1);

        if ( v.strtol(n, tok) )
        {
            if ( !set_types(n) )
                return false;
        }
        else if ( !set_types(tok.c_str()) )
            return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new GtpTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    GtpTypeModule* mod = (GtpTypeModule*)m;
    return new GtpTypeOption(mod->types);
}

static void opt_dtor(IpsOption* p)
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
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_gtp_type = &ips_api.base;

