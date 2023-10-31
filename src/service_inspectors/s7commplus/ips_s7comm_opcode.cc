//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// ips_s7comm_opcode.cc author Pradeep Damodharan <prdamodh@cisco.com>
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

static const char* s_name = "s7commplus_opcode";

//-------------------------------------------------------------------------
// func lookup
//-------------------------------------------------------------------------

struct S7commplusOpcodeMap
{
    const char* name;
    uint8_t opcode;
};

/* Mapping of name -> opcode for 's7p_opcode' option. */
static S7commplusOpcodeMap s7commp_opcode_map[] =
{
    { "request",      0x31 },
    { "response",     0x32 },
    { "notification", 0x33 },
    { "response2",    0x02 }
};

static bool get_opcode(const char* s, long& n)
{
    constexpr size_t max = (sizeof(s7commp_opcode_map) / sizeof(S7commplusOpcodeMap));

    for ( size_t i = 0; i < max; ++i )
    {
        if ( !strcmp(s, s7commp_opcode_map[i].name) )
        {
            n = s7commp_opcode_map[i].opcode;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// opcode option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7commplus_opcode_prof;

class S7commplusOpcodeOption : public IpsOption
{
public:
    S7commplusOpcodeOption(uint8_t v) : IpsOption(s_name)
    { opcode = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t opcode;
};

uint32_t S7commplusOpcodeOption::hash() const
{
    uint32_t a = opcode, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool S7commplusOpcodeOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const S7commplusOpcodeOption& rhs = (const S7commplusOpcodeOption&)ips;
    return ( opcode == rhs.opcode );
}

IpsOption::EvalStatus S7commplusOpcodeOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7commplus_opcode_prof);    // cppcheck-suppress unreadVariable

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    S7commplusFlowData* mfd =
        (S7commplusFlowData*)p->flow->get_flow_data(S7commplusFlowData::inspector_id);

    if ( mfd and opcode == mfd->ssn_data.s7commplus_opcode)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "opcode code to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7commplus opcode code"

class S7commplusOpcodeModule : public Module
{
public:
    S7commplusOpcodeModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &s7commplus_opcode_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t opcode = 0;
};

bool S7commplusOpcodeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if ( v.strtol(n) )
        opcode = (uint8_t)n;

    else if ( get_opcode(v.get_string(), n) )
        opcode = (uint8_t)n;

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commplusOpcodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    S7commplusOpcodeModule* mod = (S7commplusOpcodeModule*)m;
    return new S7commplusOpcodeOption(mod->opcode);
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

const BaseApi* ips_s7commplus_opcode = &ips_api.base;

