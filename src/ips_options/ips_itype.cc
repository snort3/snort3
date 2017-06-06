//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// ips_itype.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/sfhashfcn.h"
#include "profiler/profiler.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"

#define s_name "itype"

static THREAD_LOCAL ProfileStats icmpTypePerfStats;

class IcmpTypeOption : public IpsOption
{
public:
    IcmpTypeOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpTypeOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool IcmpTypeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcmpTypeOption& rhs = (IcmpTypeOption&)ips;
    return ( config == rhs.config );
}

int IcmpTypeOption::eval(Cursor&, Packet* p)
{
    Profile profile(icmpTypePerfStats);

    // return 0 if we don't have an icmp header
    if (!p->ptrs.icmph)
        return DETECTION_OPTION_NO_MATCH;

    if ( config.eval(p->ptrs.icmph->type) )
        return DETECTION_OPTION_MATCH;

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:255"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "check if icmp type is 'type | min<>max | <max | >min', range is " RANGE },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check ICMP type"

class ItypeModule : public Module
{
public:
    ItypeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &icmpTypePerfStats; }

    RangeCheck data;
};

bool ItypeModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool ItypeModule::set(const char*, Value& v, SnortConfig*)
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
    return new ItypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* itype_ctor(Module* p, OptTreeNode*)
{
    ItypeModule* m = (ItypeModule*)p;
    return new IcmpTypeOption(m->data);
}

static void itype_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi itype_api =
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
    1, PROTO_BIT__ICMP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    itype_ctor,
    itype_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_itype[] =
#endif
{
    &itype_api.base,
    nullptr
};

