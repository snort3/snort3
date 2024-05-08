//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_cip_enipcommand.cc author Jian Wu <jiawu2@cisco.com>

/* Description: Rule options for CIP inspector */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "cip.h"

using namespace snort;

#define s_name "enip_command"
#define s_help \
    "detection option to match CIP Enip Command"

//-------------------------------------------------------------------------
// CIP EnipCommand rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats cip_enipcommand_perf_stats;

class CipEnipCommandOption : public IpsOption
{
public:
    CipEnipCommandOption(const RangeCheck& v) : IpsOption(s_name), cip_enip_cmd(v)
    { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck cip_enip_cmd;
};

uint32_t CipEnipCommandOption::hash() const
{
    uint32_t a = cip_enip_cmd.hash();
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;

    mix(a, b, c);
    finalize(a,b,c);
    return c;
}

bool CipEnipCommandOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const CipEnipCommandOption& rhs = static_cast<const CipEnipCommandOption&>(ips);
    return ( cip_enip_cmd == rhs.cip_enip_cmd );
}

IpsOption::EvalStatus CipEnipCommandOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(cip_enipcommand_perf_stats);

    if ( !p->flow || !p->is_full_pdu() )
        return NO_MATCH;

    CipFlowData* fd = static_cast<CipFlowData*>(p->flow->get_flow_data(CipFlowData::inspector_id));

    if (!fd)
        return NO_MATCH;

    CipSessionData* session_data = &fd->session;

    if ( cip_enip_cmd.eval(session_data->current_data.enip_data.enip_header.command) )
    {
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:65535"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "match CIP Enip Command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class CipEnipCommandModule : public Module
{
public:
    CipEnipCommandModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck cip_enip_cmd;
};

bool CipEnipCommandModule::begin(const char*, int, SnortConfig*)
{
    cip_enip_cmd.init();
    return true;
}

bool CipEnipCommandModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~range"));
    return cip_enip_cmd.validate(v.get_string(), RANGE);
}

ProfileStats* CipEnipCommandModule::get_profile() const
{
    return &cip_enipcommand_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* cip_enipcommand_mod_ctor()
{
    return new CipEnipCommandModule;
}

static void cip_enipcommand_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* cip_enipcommand_ctor(Module* p, IpsInfo&)
{
    CipEnipCommandModule* m = static_cast<CipEnipCommandModule*>(p);
    return new CipEnipCommandOption(m->cip_enip_cmd);
}

static void cip_enipcommand_dtor(IpsOption* p)
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
        cip_enipcommand_mod_ctor,
        cip_enipcommand_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    cip_enipcommand_ctor,
    cip_enipcommand_dtor,
    nullptr
};

const BaseApi* ips_cip_enipcommand = &ips_api.base;

