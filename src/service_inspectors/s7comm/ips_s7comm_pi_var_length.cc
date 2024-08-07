// ips_s7comm_var_length.cc

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

// ips_s7comm_var_length.cc author <Your Name> <Your Email>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include <iostream> // For debug output
#include "s7comm.h"

using namespace snort;

static const char* s_name = "s7comm_pi_var_length";

//-------------------------------------------------------------------------
// var_length option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_var_length_prof;

class S7commVarLengthOption : public IpsOption
{
public:
    S7commVarLengthOption(const RangeCheck& c)
     : IpsOption(s_name), config(c)
    {}

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    RangeCheck config;
};

uint32_t S7commVarLengthOption::hash() const
{
    uint32_t a = config.hash(), b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool S7commVarLengthOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const S7commVarLengthOption& rhs = (const S7commVarLengthOption&)ips;
    return (config == rhs.config);
}

IpsOption::EvalStatus S7commVarLengthOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_var_length_prof);  // cppcheck-suppress unreadVariable

    if (!p->flow)
        return NO_MATCH;

    if (!p->is_full_pdu())
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if (mfd)
    {
        for (const auto& requestItem : mfd->ssn_data.request_items)
        {
            if (config.eval(requestItem.var_length))
                return MATCH;
        }
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:255"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr, "var_length to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm var_length"

class S7commVarLengthModule : public Module
{
public:
    S7commVarLengthModule() : Module(s_name, s_help, s_params) {}

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &s7comm_var_length_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    RangeCheck var_length;
};

bool S7commVarLengthModule::begin(const char*, int, SnortConfig*)
{
    var_length.init();
    return true;
}

bool S7commVarLengthModule::set(const char* name, Value& v, SnortConfig*)
{
    if ( v.is("~range") )
        return var_length.validate(v.get_string(), RANGE);

    return false; // Invalid var_length
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commVarLengthModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    S7commVarLengthModule* mod = (S7commVarLengthModule*)m;
    return new S7commVarLengthOption(mod->var_length);
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

const BaseApi* ips_s7comm_pi_var_length = &ips_api.base;
