//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// ips_icode.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "icode"

static THREAD_LOCAL ProfileStats icmpCodePerfStats;

class IcodeOption : public IpsOption
{
public:
    IcodeOption(const RangeCheck& c) :
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

uint32_t IcodeOption::hash() const
{
    uint32_t a = config.hash();
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;

    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool IcodeOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const IcodeOption& rhs = (const IcodeOption&)ips;
    return ( config == rhs.config );
}

IpsOption::EvalStatus IcodeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(icmpCodePerfStats);

    // return 0  if we don't have an icmp header
    if (!p->ptrs.icmph)
        return NO_MATCH;

    if ( config.eval(p->ptrs.icmph->code) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:255"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check if ICMP code is in given range is" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check ICMP code"

class IcodeModule : public Module
{
public:
    IcodeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &icmpCodePerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck data;
};

bool IcodeModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool IcodeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~range"));
    return data.validate(v.get_string(), RANGE);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IcodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* icode_ctor(Module* p, OptTreeNode*)
{
    IcodeModule* m = (IcodeModule*)p;
    return new IcodeOption(m->data);
}

static void icode_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi icode_api =
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
    icode_ctor,
    icode_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_icode[] =
#endif
{
    &icode_api.base,
    nullptr
};

