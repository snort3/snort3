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
// ips_ber_skip.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "utils/util_ber.h"

using namespace snort;

#define s_name "ber_skip"

static THREAD_LOCAL ProfileStats berSkipPerfStats;

class BerSkipOption : public IpsOption
{
public:
    BerSkipOption(uint32_t t, bool o) : IpsOption(s_name)
    { type = t; optional = o; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return true; }

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

private:
    uint32_t type;
    bool optional;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t BerSkipOption::hash() const
{
    uint32_t a = type, b = optional, c = IpsOption::hash();

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool BerSkipOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const BerSkipOption& rhs = (const BerSkipOption&)ips;

    if ( type != rhs.type )
        return false;

    if ( optional != rhs.optional )
        return false;

    return true;
}

IpsOption::EvalStatus BerSkipOption::eval(Cursor& c, Packet*)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(berSkipPerfStats);

    BerReader ber(c);
    BerElement e;

    if ( !ber.read(c.start(), e) )
        return NO_MATCH;

    if ( e.type != type )
    {
        if ( optional )
            return MATCH;
        else
            return NO_MATCH;
    }

    if ( e.total_length > c.length() )
        return NO_MATCH;

    if ( !c.add_pos(e.total_length) )
        return NO_MATCH;

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~type", Parameter::PT_INT, "0:255", nullptr,
      "BER element type to skip" },

    { "optional", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match even if the specified BER type is not found" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help "rule option to skip BER element"

class BerSkipModule : public Module
{
public:
    BerSkipModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &berSkipPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint32_t type = 0;
    bool optional = false;
};

bool BerSkipModule::begin(const char*, int, SnortConfig*)
{
    type = 0;
    optional = false;
    return true;
}

bool BerSkipModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~type") )
        type = v.get_uint32();

    else if ( v.is("optional") )
        optional = true;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new BerSkipModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ber_skip_ctor(Module* p, OptTreeNode*)
{
    BerSkipModule* m = (BerSkipModule*)p;
    return new BerSkipOption(m->type, m->optional);
}

static void ber_skip_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ber_skip_api =
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
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ber_skip_ctor,
    ber_skip_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_ber_skip[] =
#endif
{
    &ber_skip_api.base,
    nullptr
};

