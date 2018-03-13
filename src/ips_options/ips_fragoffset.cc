//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_fragoffset.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "fragoffset"

static THREAD_LOCAL ProfileStats fragOffsetPerfStats;

class FragOffsetOption : public IpsOption
{
public:
    FragOffsetOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t FragOffsetOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = (uint32_t)config.min;
    c = (uint32_t)config.max;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool FragOffsetOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const FragOffsetOption& rhs = (const FragOffsetOption&)ips;
    return config == rhs.config;
}

IpsOption::EvalStatus FragOffsetOption::eval(Cursor&, Packet* p)
{
    Profile profile(fragOffsetPerfStats);

    if (!p->has_ip())
        return NO_MATCH;


    if ( !config.eval(p->ptrs.ip_api.off()) )
        return NO_MATCH;

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:8192"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check if ip fragment offset is in given range" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to test IP frag offset"

class FragOffsetModule : public Module
{
public:
    FragOffsetModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &fragOffsetPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck data;
};

bool FragOffsetModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool FragOffsetModule::set(const char*, Value& v, SnortConfig*)
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
    return new FragOffsetModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* fragoffset_ctor(Module* p, OptTreeNode*)
{
    FragOffsetModule* m = (FragOffsetModule*)p;
    return new FragOffsetOption(m->data);
}

static void fragoffset_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi fragoffset_api =
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
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    fragoffset_ctor,
    fragoffset_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_fragoffset[] =
#endif
{
    &fragoffset_api.base,
    nullptr
};

