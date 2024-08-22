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

// ips_s7comm_func.cc author Yarin Peretz <yarinp123@gmail.com>
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

static const char* s_name = "s7comm_func";

//-------------------------------------------------------------------------
// func lookup
//-------------------------------------------------------------------------

struct S7commFuncMap
{
    const char* name;
    uint8_t func;
};

/* Mapping of name -> message type for 's7comm_func' option. */
static S7commFuncMap s7comm_func_map[] =
{
    { "job_request",    0x01 },
    { "ack",            0x02 },
    { "ack_data",       0x03 },
    { "userdata",       0x07 }
};

static bool get_func(const char* s, long& n)
{
    constexpr size_t max = (sizeof(s7comm_func_map) / sizeof(S7commFuncMap));

    for ( size_t i = 0; i < max; ++i )
    {
        if ( !strcmp(s, s7comm_func_map[i].name) )
        {
            n = s7comm_func_map[i].func;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// func option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_func_prof;

class S7commFuncOption : public IpsOption
{
public:
    S7commFuncOption(uint8_t v) : IpsOption(s_name)
    { func = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t func;
};

uint32_t S7commFuncOption::hash() const
{
    uint32_t a = func, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool S7commFuncOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const S7commFuncOption& rhs = (const S7commFuncOption&)ips;
    return ( func == rhs.func );
}

IpsOption::EvalStatus S7commFuncOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_func_prof);  // cppcheck-suppress unreadVariable

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    S7commFlowData* mfd =
        (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if ( mfd and func == mfd->ssn_data.s7comm_message_type )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "message type to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm message type"

class S7commFuncModule : public Module
{
public:
    S7commFuncModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &s7comm_func_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t func = 0;
};

bool S7commFuncModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if ( v.strtol(n) )
        func = static_cast<uint8_t>(n);

    else if ( get_func(v.get_string(), n) )
        func = static_cast<uint8_t>(n);

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commFuncModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    S7commFuncModule* mod = (S7commFuncModule*)m;
    return new S7commFuncOption(mod->func);
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

const BaseApi* ips_s7comm_func = &ips_api.base;
