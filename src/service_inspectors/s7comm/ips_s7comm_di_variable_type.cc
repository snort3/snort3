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

// ips_s7comm_variable_type.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream> // For debug output
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "s7comm.h"

using namespace snort;

static const char* s_name = "s7comm_variable_type";

//-------------------------------------------------------------------------
// variable_type option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_variable_type_prof;

class S7commVariableTypeOption : public IpsOption
{
public:
    S7commVariableTypeOption(uint8_t v) : IpsOption(s_name), variable_type(v) {}

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t variable_type;
};

uint32_t S7commVariableTypeOption::hash() const
{
    uint32_t a = variable_type, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool S7commVariableTypeOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const S7commVariableTypeOption& rhs = (const S7commVariableTypeOption&)ips;
    return (variable_type == rhs.variable_type);
}

IpsOption::EvalStatus S7commVariableTypeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_variable_type_prof);

    if (!p->flow)
        return NO_MATCH;

    if (!p->is_full_pdu())
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if (!mfd)
        return NO_MATCH;

    for (const auto& dataItem : mfd->ssn_data.data_items)
    {        
        if (dataItem.variable_type == variable_type)
            return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "variable_type to match" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm variable_type"

class S7commVariableTypeModule : public Module
{
public:
    S7commVariableTypeModule() : Module(s_name, s_help, s_params) {}

    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override { return &s7comm_variable_type_prof; }
    Usage get_usage() const override { return DETECT; }

public:
    uint8_t variable_type = 0;
};

bool S7commVariableTypeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if (v.strtol(n))
        variable_type = static_cast<uint8_t>(n);

    return true;
}

static Module* mod_ctor()
{
    return new S7commVariableTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    S7commVariableTypeModule* mod = (S7commVariableTypeModule*)m;
    return new S7commVariableTypeOption(mod->variable_type);
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

const BaseApi* ips_s7comm_variable_type = &ips_api.base;
