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

// ips_gtp_version.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// gtp_version rule option implementation

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "gtp_inspect.h"

using namespace snort;

static const char* s_name = "gtp_version";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats gtp_ver_prof;

class GtpVersionOption : public IpsOption
{
public:
    GtpVersionOption(uint8_t v) : IpsOption(s_name)
    { version = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t version;
};

uint32_t GtpVersionOption::hash() const
{
    uint32_t a = version, b = 0, c = 0;

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool GtpVersionOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const GtpVersionOption& rhs = (const GtpVersionOption&)ips;
    return ( version == rhs.version );
}

IpsOption::EvalStatus GtpVersionOption::eval(Cursor&, Packet* p)
{
    Profile profile(gtp_ver_prof);

    if ( !p->flow )
        return NO_MATCH;

    GtpFlowData* gfd = (GtpFlowData*)p->flow->get_flow_data(GtpFlowData::inspector_id);

    if ( gfd and version == gfd->ropts.gtp_version )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_INT, "0:2", nullptr,
      "version to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check GTP version"

class GtpVersionModule : public Module
{
public:
    GtpVersionModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &gtp_ver_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t version;
};

bool GtpVersionModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    version = v.get_long();
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new GtpVersionModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    GtpVersionModule* mod = (GtpVersionModule*)m;
    return new GtpVersionOption(mod->version);
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

const BaseApi* ips_gtp_version = &ips_api.base;

