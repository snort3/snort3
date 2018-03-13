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

// ips_gtp_info.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// gtp_info rule option implementation

#include "hash/hashfcn.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "gtp.h"
#include "gtp_inspect.h"

using namespace snort;

static const char* s_name = "gtp_info";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats gtp_info_prof;

class GtpInfoOption : public IpsOption
{
public:
    GtpInfoOption(const uint8_t*);

    CursorActionType get_cursor_type() const override
    { return CAT_SET_OTHER; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    // byte n is for version n (named types can have 
    // different codes in different versions)
    uint8_t types[MAX_GTP_VERSION_CODE + 1];
};

GtpInfoOption::GtpInfoOption(const uint8_t* t) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET)
{
    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        types[v] = t[v];
}

uint32_t GtpInfoOption::hash() const
{
    assert(MAX_GTP_VERSION_CODE == 2);

    uint32_t a = types[0];
    uint32_t b = types[1];
    uint32_t c = types[2];

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool GtpInfoOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const GtpInfoOption& rhs = (const GtpInfoOption&)ips;

    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        if ( types[v] != rhs.types[v] )
            return false;

    return true;
}

IpsOption::EvalStatus GtpInfoOption::eval(Cursor& c, Packet* p)
{
    Profile profile(gtp_info_prof);

    if ( !p or !p->flow )
        return NO_MATCH;

    GtpFlowData* gfd = (GtpFlowData*)p->flow->get_flow_data(GtpFlowData::inspector_id);

    if ( !gfd or !gfd->ropts.gtp_infoElements )
        return NO_MATCH;

    GTP_Roptions& ropts = gfd->ropts;

    // match the status code
    uint8_t ieType = types[ropts.gtp_version];

    if ( !ieType )
        return NO_MATCH;

    GTP_IEData* ieData = ropts.gtp_infoElements + ieType;

    // bail if the data is not up to date
    if ( ieData->msg_id != ropts.msg_id )
        return NO_MATCH;

    c.set(s_name, ieData->shift + ropts.gtp_header, ieData->length);
    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "info element to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check gtp info element"

class GtpInfoModule : public Module
{
public:
    GtpInfoModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    bool set_types(long);
    bool set_types(const char*);

    ProfileStats* get_profile() const override
    { return &gtp_info_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t types[MAX_GTP_VERSION_CODE + 1];
};

bool GtpInfoModule::set_types(long t)
{
    if ( t < MIN_GTP_IE_CODE or t > MAX_GTP_IE_CODE )
        return false;

    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
        types[v] = (uint8_t)t;

    return true;
}

bool GtpInfoModule::set_types(const char* name)
{
    bool ok = false;

    for ( int v = 0; v <= MAX_GTP_VERSION_CODE; ++v )
    {
        int t = get_info_type(v, name);

        if ( t < 0 )
            continue;

        types[v] = t;
        ok = true;
    }
    return ok;
}

bool GtpInfoModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    long n;

    if ( v.strtol(n) )
        return set_types(n);

    return set_types(v.get_string());
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new GtpInfoModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    GtpInfoModule* mod = (GtpInfoModule*)m;
    return new GtpInfoOption(mod->types);
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

const BaseApi* ips_gtp_info = &ips_api.base;

