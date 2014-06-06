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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

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

static const char* s_name = "tos";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats ipTosPerfStats;

static PreprocStats* tos_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &ipTosPerfStats;

    return nullptr;
}
#endif

typedef struct _IpTosCheckData
{
    uint8_t ip_tos;
    uint8_t not_flag;

} IpTosData;

class IpTosOption : public IpsOption
{
public:
    IpTosOption(const IpTosData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

    IpTosData* get_data() 
    { return &config; };

private:
    IpTosData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IpTosOption::hash() const
{
    uint32_t a,b,c;
    const IpTosData *data = &config;

    a = data->ip_tos;
    b = data->not_flag;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IpTosOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IpTosOption& rhs = (IpTosOption&)ips;
    IpTosData *left = (IpTosData*)&config;
    IpTosData *right = (IpTosData*)&rhs.config;

    if ((left->ip_tos == right->ip_tos) &&
        (left->not_flag == right->not_flag))
    {
        return true;
    }

    return false;
}

/* Purpose: Test the ip header's tos field to see if its value is equal to the
 * value in the rule.  This is useful to detect things like the "bubonic" DoS tool.
 */
 
int IpTosOption::eval(Packet *p)
{
    IpTosData *ipTosData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
        return rval; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(ipTosPerfStats);

    if((ipTosData->ip_tos == GET_IPH_TOS(p)) ^ (ipTosData->not_flag))
    {
        rval = DETECTION_OPTION_MATCH;
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ipTosPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void tos_parse(char *data, IpTosData *ds_ptr)
{
    char *endTok;
    char *start;

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }

    if(data[0] == '!')
    {
        ds_ptr->not_flag = 1;
        start = &data[1];
    }
    else
    {
        start = &data[0];
    }

    if(strchr(start, (int) 'x') == NULL && strchr(start, (int)'X') == NULL)
    {
        ds_ptr->ip_tos = (uint8_t)SnortStrtoulRange(start, &endTok, 10, 0, UINT8_MAX);
        if ((endTok == start) || (*endTok != '\0'))
        {
            ParseError("Invalid parameter '%s' to 'tos' (not a number?) ", data);
        }
    }
    else
    {
        /* hex? */
        start = strchr(data,(int)'x');
        if(!start)
        {
            start = strchr(data,(int)'X');
        }
        if (start)
        {
            ds_ptr->ip_tos = (uint8_t)SnortStrtoulRange(start+1, &endTok, 16, 0, UINT8_MAX);
        }
        if (!start || (endTok == start+1) || (*endTok != '\0'))
        {
            ParseError("Invalid parameter '%s' to 'tos' (not a number?) ", data);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"TOS set to %d\n", ds_ptr->ip_tos););
}

static IpsOption* tos_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IpTosData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    tos_parse(data, &ds_ptr);
    return new IpTosOption(ds_ptr);
}

static void tos_dtor(IpsOption* p)
{
    delete p;
}

static void tos_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &ipTosPerfStats, tos_get_profile);
#endif
}

static const IpsApi tos_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, 0,
    tos_ginit,
    nullptr,
    nullptr,
    nullptr,
    tos_ctor,
    tos_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &tos_api.base,
    nullptr
};
#else
const BaseApi* ips_tos = &tos_api.base;
#endif

