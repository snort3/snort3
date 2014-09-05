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
#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

static const char* s_name = "ipopts";

static THREAD_LOCAL ProfileStats ipOptionPerfStats;

struct IpOptionData
{
    u_char ip_option;
    u_char any_flag;

};

class IpOptOption : public IpsOption
{
public:
    IpOptOption(const IpOptionData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

    IpOptionData* get_data() 
    { return &config; };

private:
    IpOptionData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IpOptOption::hash() const
{
    uint32_t a,b,c;
    const IpOptionData *data = &config;

    a = data->ip_option;
    b = data->any_flag;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IpOptOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IpOptOption& rhs = (IpOptOption&)ips;
    IpOptionData *left = (IpOptionData*)&config;
    IpOptionData *right = (IpOptionData*)&rhs.config;

    if ((left->ip_option == right->ip_option) &&
        (left->any_flag == right->any_flag))
    {
        return true;
    }

    return false;
}

int IpOptOption::eval(Cursor&, Packet *p)
{
    IpOptionData *ipOptionData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    int i;
    PROFILE_VARS;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "CheckIpOptions:"););
    if(!p->ip_api.is_valid())
        return rval; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    MODULE_PROFILE_START(ipOptionPerfStats);

    if((ipOptionData->any_flag == 1) && (p->ip_option_count > 0))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Matched any ip options!\n"););
        rval = DETECTION_OPTION_MATCH;
        MODULE_PROFILE_END(ipOptionPerfStats);
        return rval;
    }

    for(i=0; i< (int) p->ip_option_count; i++)
    {
    	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "testing pkt(%d):rule(%d)\n",
				ipOptionData->ip_option,
				p->ip_options[i].code); );

        if(ipOptionData->ip_option == p->ip_options[i].code)
        {
            rval = DETECTION_OPTION_MATCH;
            MODULE_PROFILE_END(ipOptionPerfStats);
            return rval;
        }
    }

    /* if the test isn't successful, return 0 */
    MODULE_PROFILE_END(ipOptionPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void ipopts_parse(const char* data, IpOptionData* ds_ptr)
{
    if(strcasecmp(data, "rr") == 0)
    {
        ds_ptr->ip_option = IPOPT_RR;
    }
    else if(strcasecmp(data, "eol") == 0)
    {
        ds_ptr->ip_option = IPOPT_EOL;
    }
    else if(strcasecmp(data, "nop") == 0)
    {
        ds_ptr->ip_option = IPOPT_NOP;
    }
    else if(strcasecmp(data, "ts") == 0)
    {
        ds_ptr->ip_option = IPOPT_TS;
    }
    else if(strcasecmp(data, "esec") == 0)
    {
        ds_ptr->ip_option = IPOPT_ESEC;
    }
    else if(strcasecmp(data, "sec") == 0)
    {
        ds_ptr->ip_option = IPOPT_SECURITY;
    }
    else if(strcasecmp(data, "lsrr") == 0)
    {
        ds_ptr->ip_option = IPOPT_LSRR;
    }
    else if(strcasecmp(data, "lsrre") == 0)
    {
        ds_ptr->ip_option = IPOPT_LSRR_E;
    }
    else if(strcasecmp(data, "satid") == 0)
    {
        ds_ptr->ip_option = IPOPT_SATID;
    }
    else if(strcasecmp(data, "ssrr") == 0)
    {
        ds_ptr->ip_option = IPOPT_SSRR;
    }
    else if(strcasecmp(data, "any") == 0)
    {
        ds_ptr->ip_option = 0;
        ds_ptr->any_flag = 1;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const char* s_opts =
    "rr|eol|nop|ts|sec|esec|lsrr|lsrre|ssrr|satid|any";

static const Parameter s_params[] =
{
    { "~opt", Parameter::PT_SELECT, s_opts, nullptr,
      "output format" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const char* s_help =
    "rule option to check for IP options";

class IpOptModule : public Module
{
public:
    IpOptModule() : Module(s_name, s_help, s_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &ipOptionPerfStats; };

    IpOptionData data;
};

bool IpOptModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool IpOptModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~opt") )
        ipopts_parse(v.get_string(), &data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IpOptModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ipopts_ctor(Module* p, OptTreeNode*)
{
    IpOptModule* m = (IpOptModule*)p;
    return new IpOptOption(m->data);
}

static void ipopts_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ipopts_api =
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
    ipopts_ctor,
    ipopts_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ipopts_api.base,
    nullptr
};
#else
const BaseApi* ips_ipopts = &ipopts_api.base;
#endif

