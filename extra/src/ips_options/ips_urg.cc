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
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// ips_urg.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "main/snort_types.h"
#include "main/thread.h"
#include "detection/detection_defines.h"
#include "detection/treenodes.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
//#include "framework/range.h"
#include "hash/sfhashfcn.h"
#include "protocols/packet.h"
#include "time/profiler.h"

static const char* s_name = "urg";

// FIXIT-H profiling is desirable but must be refactored to
// avoid dependence on snort_config.h which snowballs
//#undef PERF_PROFILING

static THREAD_LOCAL ProfileStats tcpUrgPerfStats;

//-------------------------------------------------------------------------
// range check
//-------------------------------------------------------------------------
// FIXIT-L this is a stub until we can use range.{h,cc}

struct RangeCheck
{
    unsigned op, min, max;

    RangeCheck()
    { init(); };

    void init()
    { op = min = max = 0; };

    bool operator==(const RangeCheck& rhs) const
    { return ( op == rhs.op && min == rhs.min && max == rhs.max ); };

    bool eval(unsigned up)
    { return up == min; };

    bool parse(const char* s)
    { min = atoi(s); return true; };
};

//-------------------------------------------------------------------------
// option 
//-------------------------------------------------------------------------

class TcpUrgOption : public IpsOption
{
public:
    TcpUrgOption(const RangeCheck& c) : IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    RangeCheck config;
};

uint32_t TcpUrgOption::hash() const
{
    uint32_t a, b, c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TcpUrgOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    TcpUrgOption& rhs = (TcpUrgOption&)ips;
    return ( config == rhs.config );
}

int TcpUrgOption::eval(Packet *p)
{
    //PROFILE_VARS;
    //MODULE_PROFILE_START(tcpUrgPerfStats);

    int rval = DETECTION_OPTION_NO_MATCH;

    if ( p->tcph && config.eval(p->tcph->th_ack) )
        rval = DETECTION_OPTION_MATCH;

    //MODULE_PROFILE_END(tcpUrgPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter urg_params[] =
{
    { "*range", Parameter::PT_STRING, nullptr, nullptr,
      "check if urgent offset is min<>max | <max | >min" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class UrgModule : public Module
{
public:
    UrgModule() : Module(s_name, urg_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &tcpUrgPerfStats; };

    RangeCheck data;
};

bool UrgModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool UrgModule::set(const char*, Value& v, SnortConfig*)
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
    return new UrgModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* urg_ctor(Module* p, OptTreeNode*)
{
    UrgModule* m = (UrgModule*)p;
    return new TcpUrgOption(m->data);
}

static void urg_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi urg_api =
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
    1, PROTO_BIT__TCP,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    urg_ctor,
    urg_dtor,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &urg_api.base,
    nullptr
};

