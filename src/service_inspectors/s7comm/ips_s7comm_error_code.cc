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

static const char* s_name = "s7comm_error_code";

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

//-------------------------------------------------------------------------
// error code option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_error_code_prof;

class S7commErrorCodeOption : public IpsOption
{
public:
    S7commErrorCodeOption(uint8_t ec) : IpsOption(s_name)
    {error_code=ec;}

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t error_code;
};

uint32_t S7commErrorCodeOption::hash() const
{
    uint32_t a = error_code, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool S7commErrorCodeOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const S7commErrorCodeOption& rhs = (const S7commErrorCodeOption&)ips;
    return (error_code == rhs.error_code);
}

IpsOption::EvalStatus S7commErrorCodeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_error_code_prof);  // cppcheck-suppress unreadVariable

    if (!p->flow)
        return NO_MATCH;

    if (!p->is_full_pdu())
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if (mfd && mfd->ssn_data.s7comm_message_type == s7comm_func_map[2].func) // Check for ack_data message type
    {
        if (mfd->ssn_data.s7comm_error_code == error_code)
            return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "error code to match for ack_data messages" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm ack_data error code"

class S7commErrorCodeModule : public Module
{
public:
    S7commErrorCodeModule() : Module(s_name, s_help, s_params) {}

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &s7comm_error_code_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint16_t error_code = 0;
};

bool S7commErrorCodeModule::set(const char* name, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if ( v.strtol(n) )
        {
            error_code = static_cast<uint8_t>(n);
            return true;
        }
    else
        return false; // Invalid error code


}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commErrorCodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    S7commErrorCodeModule* mod = (S7commErrorCodeModule*)m;
    return new S7commErrorCodeOption(mod->error_code);
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

const BaseApi* ips_s7comm_error_code = &ips_api.base;
