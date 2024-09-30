// ips_s7comm_function_code.cc:

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

// ips_s7comm_function_code.cc author Yarin Peretz <yarinp123@gmail.com>
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
#include "s7comm_helpers.h"

using namespace snort;

static const char* s_name = "s7comm_function_code";

//-------------------------------------------------------------------------
// function_code option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_function_code_prof;

class S7commFunctionCodeOption : public IpsOption
{
public:
    S7commFunctionCodeOption(uint8_t fc) : IpsOption(s_name)
    { function_code = fc; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t function_code;
};

uint32_t S7commFunctionCodeOption::hash() const
{
    uint32_t a = function_code, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool S7commFunctionCodeOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const S7commFunctionCodeOption& rhs = (const S7commFunctionCodeOption&)ips;
    return (function_code == rhs.function_code);
}

IpsOption::EvalStatus S7commFunctionCodeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_function_code_prof);  // cppcheck-suppress unreadVariable

    if (!p->flow)
        return NO_MATCH;

    if (!p->is_full_pdu())
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);
    

    if (mfd && (mfd->ssn_data.s7comm_message_type == s7comm_func_map[0].func || mfd->ssn_data.s7comm_message_type == s7comm_func_map[2].func)) // Check for ack_data message type
    {
        if (mfd->ssn_data.s7comm_function_code == function_code)
            return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "function code to match for ack_data messages" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm ack_data function code"

class S7commFunctionCodeModule : public Module
{
public:
    S7commFunctionCodeModule() : Module(s_name, s_help, s_params) {}

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &s7comm_function_code_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint8_t function_code = 0;
};

bool S7commFunctionCodeModule::set(const char* name, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if ( v.strtol(n) )
        {
            function_code = static_cast<uint8_t>(n);
            return true;
        }
    else
        return false; // Invalid function code
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commFunctionCodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    S7commFunctionCodeModule* mod = (S7commFunctionCodeModule*)m;
    return new S7commFunctionCodeOption(mod->function_code);
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

const BaseApi* ips_s7comm_function_code = &ips_api.base;
