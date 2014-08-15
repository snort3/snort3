/*
 ** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if nto, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 ** USA
 */
// ips_bufferlen.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>

#include "snort_types.h"
#include "snort_debug.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "profiler.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "range.h"
#include "framework/ips_option.h"
#include "framework/inspector.h"
#include "framework/cursor.h"
#include "framework/module.h"

static const char* s_name = "bufferlen";

static THREAD_LOCAL ProfileStats lenCheckPerfStats;

class LenOption : public IpsOption
{
public:
    LenOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

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
    final(a,b,c);

    return c;
}

bool LenOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    LenOption& rhs = (LenOption&)ips;
    return ( config == rhs.config );
}

int LenOption::eval(Cursor& c, Packet*)
{
    int rval = DETECTION_OPTION_NO_MATCH;

    PROFILE_VARS;
    MODULE_PROFILE_START(lenCheckPerfStats);

    if ( config.eval(c.length()) )
        rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(lenCheckPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter len_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "min<>max | <max | >min" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class LenModule : public Module
{
public:
    LenModule() : Module(s_name, len_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &lenCheckPerfStats; };

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

    return data.parse(v.get_string());
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
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
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
{
    &len_api.base,
    nullptr
};
#else
const BaseApi* ips_bufferlen = &len_api.base;
#endif

