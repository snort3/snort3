/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "snort_types.h"
#include "detection/treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "detection/fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/range.h"

#define GREATER_THAN            1
#define LESS_THAN               2

#define FB_NORMAL   0
#define FB_ALL      1
#define FB_ANY      2
#define FB_NOT      3

#define FB_RB  0x8000
#define FB_DF  0x4000
#define FB_MF  0x2000

static const char* s_name = "fragoffset";

static THREAD_LOCAL ProfileStats fragOffsetPerfStats;

class FragOffsetOption : public IpsOption
{
public:
    FragOffsetOption(const RangeCheck& c) :
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

uint32_t FragOffsetOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = (uint32_t)config.min;
    c = (uint32_t)config.max;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool FragOffsetOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FragOffsetOption& rhs = (FragOffsetOption&)ips;
    return config == rhs.config;

    return false;
}

int FragOffsetOption::eval(Cursor&, Packet *p)
{
    int p_offset = p->frag_offset * 8;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
    {
        return rval;
    }

    MODULE_PROFILE_START(fragOffsetPerfStats);

    if ( config.eval(p_offset) )
        rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(fragOffsetPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter fragoff_params[] =
{
    { "*range", Parameter::PT_STRING, nullptr, nullptr,
      "check if packet payload size is min<>max | <max | >min" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class FragOffsetModule : public Module
{
public:
    FragOffsetModule() : Module(s_name, fragoff_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &fragOffsetPerfStats; };

    RangeCheck data;
};

bool FragOffsetModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool FragOffsetModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("*range") )
        return false;

    return data.parse(v.get_string());
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FragOffsetModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* fragoffset_ctor(Module* p, OptTreeNode*)
{
    FragOffsetModule* m = (FragOffsetModule*)p;
    return new FragOffsetOption(m->data);
}

static void fragoffset_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi fragoffset_api =
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
    0, 0,  // FIXIT more than one fragoffset per rule?
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    fragoffset_ctor,
    fragoffset_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &fragoffset_api.base,
    nullptr
};
#else
const BaseApi* ips_fragoffset = &fragoffset_api.base;
#endif

