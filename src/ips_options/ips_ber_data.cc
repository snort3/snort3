//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// ips_ber_data.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "helpers/ber.h"
#include "profiler/profiler.h"

using namespace snort;

#define s_name "ber_data"

static THREAD_LOCAL ProfileStats berDataPerfStats;

class BerDataOption : public IpsOption
{
public:
    BerDataOption(uint32_t t) : IpsOption(s_name)
    { type = t; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return true; }

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

private:
    uint32_t type;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t BerDataOption::hash() const
{
    uint32_t a = type, b = IpsOption::hash(), c = 0;

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool BerDataOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const BerDataOption& rhs = (const BerDataOption&)ips;

    if ( type != rhs.type )
        return false;

    return true;
}

IpsOption::EvalStatus BerDataOption::eval(Cursor& c, Packet*)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(berDataPerfStats);

    BerReader ber(c);
    BerElement e;

    if ( !ber.read(c.start(), e) )
        return NO_MATCH;

    if ( e.type != type )
        return NO_MATCH;

    if ( e.header_length > c.length() )
        return NO_MATCH;

    if ( !c.add_pos(e.header_length) )
        return NO_MATCH;

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~type", Parameter::PT_INT, "0:255", nullptr,
      "move to the data for the specified BER element type" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to move to the data for a specified BER element"

class BerDataModule : public Module
{
public:
    BerDataModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &berDataPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint32_t type = 0;
};

bool BerDataModule::begin(const char*, int, SnortConfig*)
{
    type = 0;
    return true;
}

bool BerDataModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~type"));
    type = v.get_uint32();
    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new BerDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ber_data_ctor(Module* p, IpsInfo&)
{
    BerDataModule* m = (BerDataModule*)p;
    return new BerDataOption(m->type);
}

static void ber_data_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ber_data_api =
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
    ber_data_ctor,
    ber_data_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_ber_data[] =
#endif
{
    &ber_data_api.base,
    nullptr
};

