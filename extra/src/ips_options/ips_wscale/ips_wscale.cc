//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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

// ips_wscale.cc author Russ Combs <rucombs@cisco.com>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/sfhashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"

static const char* s_name = "wscale";
static const char* s_help = "detection for TCP window scale";

static THREAD_LOCAL ProfileStats tcpWscalePerfStats;

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class TcpWscaleOption : public IpsOption
{
public:
    TcpWscaleOption(const RangeCheck& c) : IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

uint32_t TcpWscaleOption::hash() const
{
    uint32_t a, b, c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool TcpWscaleOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    TcpWscaleOption& rhs = (TcpWscaleOption&)ips;
    return ( config == rhs.config );
}

static bool get_wscale(Packet* p, uint16_t& wscale)
{
    if ( !p->ptrs.tcph )
        return false;

    tcp::TcpOptIterator iter(p->ptrs.tcph, p);

    for (const auto& opt : iter)
    {
        if (opt.code == tcp::TcpOptCode::WSCALE)
        {
            wscale = opt.data[0];
            return true;
        }
    }
    return false;
}

IpsOption::EvalStatus TcpWscaleOption::eval(Cursor&, Packet* p)
{
    Profile profile(tcpWscalePerfStats);
    uint16_t wscale;

    if ( get_wscale(p, wscale) and config.eval(wscale) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:65535"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check if TCP window scale is in given range" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class WscaleModule : public Module
{
public:
    WscaleModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &tcpWscalePerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck data;
};

bool WscaleModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool WscaleModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~range") )
        return false;

    return data.validate(v.get_string(), RANGE);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new WscaleModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* wscale_ctor(Module* p, OptTreeNode*)
{
    WscaleModule* m = (WscaleModule*)p;
    return new TcpWscaleOption(m->data);
}

static void wscale_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi wscale_api =
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
    1, PROTO_BIT__TCP,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    wscale_ctor,
    wscale_dtor,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &wscale_api.base,
    nullptr
};

