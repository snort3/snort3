//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// ips_bufferlen.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"

using namespace snort;

#define s_name "bufferlen"

#define s_help \
    "rule option to check length of current buffer"

static THREAD_LOCAL ProfileStats lenCheckPerfStats;

class LenOption : public IpsOption
{
public:
    LenOption(const RangeCheck& c, bool r) : IpsOption(s_name)
    { config = c; relative = r; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return relative; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
    bool relative;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t LenOption::hash() const
{
    uint32_t a = config.hash();
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;

    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool LenOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const LenOption& rhs = (const LenOption&)ips;
    return ( config == rhs.config and relative == rhs.relative );
}

IpsOption::EvalStatus LenOption::eval(Cursor& c, Packet*)
{
    RuleProfile profile(lenCheckPerfStats);
    unsigned n = relative ? c.length() : c.size();

    if ( config.eval(n) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:65535"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check that total length of current buffer is in given range" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "use remaining length (from current position) instead of total length" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class LenModule : public Module
{
public:
    LenModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &lenCheckPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck data;
    bool relative = false;
};

bool LenModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool LenModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~range") )
        return data.validate(v.get_string(), RANGE);

    if ( v.is("relative") )
        relative = true;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new LenModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* len_ctor(Module* p, OptTreeNode*)
{
    LenModule* m = (LenModule*)p;
    return new LenOption(m->data, m->relative);
}

static void len_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi len_api =
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
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    len_ctor,
    len_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_bufferlen[] =
#endif
{
    &len_api.base,
    nullptr
};

