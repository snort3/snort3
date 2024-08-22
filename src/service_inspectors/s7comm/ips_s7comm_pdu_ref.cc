// ips_s7comm_pdu_ref.cc:

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

// ips_s7comm_pdu_ref.cc author Yarin Peretz <yarinp123@gmail.com>
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

static const char* s_name = "s7comm_pdu_ref";

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
// pdu_ref option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_pdu_ref_prof;

class S7commPduRefOption : public IpsOption
{
public:
    S7commPduRefOption(uint16_t pr) : IpsOption(s_name)
    { pdu_ref = pr; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint16_t pdu_ref;
};

uint32_t S7commPduRefOption::hash() const
{
    uint32_t a = pdu_ref, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool S7commPduRefOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const S7commPduRefOption& rhs = (const S7commPduRefOption&)ips;
    return (pdu_ref == rhs.pdu_ref);
}

IpsOption::EvalStatus S7commPduRefOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(s7comm_pdu_ref_prof);  // cppcheck-suppress unreadVariable

    if (!p->flow)
        return NO_MATCH;

    if (!p->is_full_pdu())
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if (mfd && mfd->ssn_data.s7comm_pdu_reference == pdu_ref)
            return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "PDU reference to match for ack_data messages" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check s7comm ack_data PDU reference"

class S7commPduRefModule : public Module
{
public:
    S7commPduRefModule() : Module(s_name, s_help, s_params) {}

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &s7comm_pdu_ref_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint16_t pdu_ref = 0;
};

bool S7commPduRefModule::set(const char* name, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if ( v.strtol(n) )
        {
            pdu_ref = static_cast<uint16_t>(n);
            return true;
        }
    else
        return false; // Invalid PDU reference
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commPduRefModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    S7commPduRefModule* mod = (S7commPduRefModule*)m;
    return new S7commPduRefOption(mod->pdu_ref);
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

const BaseApi* ips_s7comm_pdu_ref = &ips_api.base;
