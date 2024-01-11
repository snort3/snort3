//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_iec104_apci_type.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after ips_modbus_func.cc (author Russ Combs <rucombs@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "iec104.h"
#include "iec104_parse_apdu.h"

using namespace snort;

static const char* s_name = "iec104_apci_type";

//-------------------------------------------------------------------------
// apci type lookup
//-------------------------------------------------------------------------

struct Iec104ApciTypeMap
{
    const char* name;
    uint8_t apci_type;
};

/* Mapping of name -> apci type for 'iec104_apci_type' option. */
static Iec104ApciTypeMap iec104_apci_type_map[] =
{
    { "u", IEC104_APCI_TYPE_U },                              // unnumbered control function
    { "U", IEC104_APCI_TYPE_U },                              // unnumbered control function
    { "unnumbered_control_function", IEC104_APCI_TYPE_U },    // unnumbered control function
    { "s", IEC104_APCI_TYPE_S },                              // numbered supervisory function
    { "S", IEC104_APCI_TYPE_S },                              // numbered supervisory function
    { "numbered_supervisory_function", IEC104_APCI_TYPE_S },  // numbered supervisory function
    { "i", IEC104_APCI_TYPE_I },                              // information transfer format
    { "I", IEC104_APCI_TYPE_I },                              // information transfer format
    { "information_transfer_format", IEC104_APCI_TYPE_I },    // information transfer format
};

static bool get_apci_type(const char* s, long& n)
{
    constexpr size_t max = (sizeof(iec104_apci_type_map) / sizeof(Iec104ApciTypeMap));

    for (size_t i = 0; i < max; ++i)
    {
        if (!strcmp(s, iec104_apci_type_map[i].name))
        {
            n = iec104_apci_type_map[i].apci_type;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// apci_type option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats iec104_apci_type_prof;

class Iec104ApciTypeOption: public IpsOption
{
public:
    Iec104ApciTypeOption(uint16_t v) :
        IpsOption(s_name)
    {
        apci_type = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t apci_type;
};

uint32_t Iec104ApciTypeOption::hash() const
{
    uint32_t a = apci_type, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool Iec104ApciTypeOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const Iec104ApciTypeOption& rhs = (const Iec104ApciTypeOption&) ips;
    return (apci_type == rhs.apci_type);
}

IpsOption::EvalStatus Iec104ApciTypeOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(iec104_apci_type_prof);

    if (!p->flow)
    {
        return NO_MATCH;
    }

    if (!p->is_full_pdu())
    {
        return NO_MATCH;
    }

    // check if the packet apci_type matches the rule option apci_type
    Iec104FlowData* iec104fd = (Iec104FlowData*) p->flow->get_flow_data(Iec104FlowData::inspector_id);
    if (iec104fd and apci_type == iec104fd->ssn_data.iec104_apci_type)
    {
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "APCI type to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check iec104 apci type"

class Iec104ApciTypeModule: public Module
{
public:
    Iec104ApciTypeModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &iec104_apci_type_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint8_t apci_type = IEC104_NO_APCI;
};

bool Iec104ApciTypeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    long n;

    if (v.strtol(n))
        apci_type = static_cast<uint8_t>(n);

    else if (get_apci_type(v.get_string(), n))
        apci_type = static_cast<uint8_t>(n);

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Iec104ApciTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    Iec104ApciTypeModule* mod = (Iec104ApciTypeModule*) m;
    return new Iec104ApciTypeOption(mod->apci_type);
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
    0,
    PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_iec104_apci_type = &ips_api.base;

