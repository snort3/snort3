//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_s7comm_func.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "s7comm.h"

using namespace snort;

static const char* s_name = "s7commplus_func";

//-------------------------------------------------------------------------
// func lookup
//-------------------------------------------------------------------------

struct S7commplusFuncMap
{
    const char* name;
    uint16_t func;
};

/* Mapping of name -> function code for 's7commplus_func' option. */
static S7commplusFuncMap s7commp_func_map[] =
{
    { "explore",          0x04BB },
    { "createobject",     0x04CA },
    { "deleteobject",     0x04D4 },
    { "setvariable",      0x04F2 },
    { "getlink",          0x0524 },
    { "setmultivar",      0x0542 },
    { "getmultivar",      0x054C },
    { "beginsequence",    0x0556 },
    { "endsequence",      0x0560 },
    { "invoke",           0x056B },
    { "getvarsubstr",     0x0586 }
};

static bool get_func(const char* s, long& n)
{
    constexpr size_t max = (sizeof(s7commp_func_map) / sizeof(S7commplusFuncMap));

    for ( size_t i = 0; i < max; ++i )
    {
        if ( !strcmp(s, s7commp_func_map[i].name) )
        {
            n = s7commp_func_map[i].func;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// func option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7commplus_func_prof;

class S7commplusFuncOption : public IpsOption
{
public:
    S7commplusFuncOption(uint16_t v) : IpsOption(s_name)
    { func = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint16_t func;
};

uint32_t S7commplusFuncOption::hash() const
{
    uint32_t a = func, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool S7commplusFuncOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const S7commplusFuncOption& rhs = (const S7commplusFuncOption&)ips;
    return ( func == rhs.func );
}

IpsOption::EvalStatus S7commplusFuncOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7commplus_func_prof);  // cppcheck-suppress unreadVariable

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    S7commplusFlowData* mfd =
        (S7commplusFlowData*)p->flow->get_flow_data(S7commplusFlowData::inspector_id);

    if ( mfd and func == mfd->ssn_data.s7commplus_function )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "function code to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7commplus function code"

class S7commplusFuncModule : public Module
{
public:
    S7commplusFuncModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &s7commplus_func_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    //uint8_t func;
    uint16_t func = 0;
};

bool S7commplusFuncModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if ( v.strtol(n) )
        func = static_cast<uint16_t>(n);

    else if ( get_func(v.get_string(), n) )
        func = static_cast<uint16_t>(n);

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commplusFuncModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    S7commplusFuncModule* mod = (S7commplusFuncModule*)m;
    return new S7commplusFuncOption(mod->func);
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

const BaseApi* ips_s7commplus_func = &ips_api.base;

