//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_defines.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/sfhashfcn.h"
#include "profiler/profiler.h"

#define s_name "bufferlen"

#define s_help \
    "rule option to check length of current buffer"

static THREAD_LOCAL ProfileStats lenCheckPerfStats;

class LenOption : public IpsOption
{
public:
    LenOption(const RangeCheck& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t LenOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool LenOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    LenOption& rhs = (LenOption&)ips;
    return ( config == rhs.config );
}

int LenOption::eval(Cursor& c, Packet*)
{
    Profile profile(lenCheckPerfStats);

    if ( config.eval(c.length()) )
        return DETECTION_OPTION_MATCH;

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "0:65535"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "len | min<>max | <max | >min, range is " RANGE },

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

    RangeCheck data;
};

bool LenModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool LenModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~range") )
        return false;

    return data.validate(v.get_string(), RANGE);
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
    return new LenOption(m->data);
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

