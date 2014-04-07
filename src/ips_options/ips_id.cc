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

#include "snort_types.h"
#include "treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "id";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats ipIdPerfStats;

static PreprocStats* id_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &ipIdPerfStats;

    return nullptr;
}
#endif

typedef struct _IpIdCheckData
{
    u_long ip_id;

} IpIdCheckData;

class IpIdOption : public IpsOption
{
public:
    IpIdOption(const IpIdCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    IpIdCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IpIdOption::hash() const
{
    uint32_t a,b,c;
    const IpIdCheckData *data = &config;

    a = data->ip_id;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IpIdOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IpIdOption& rhs = (IpIdOption&)ips;
    IpIdCheckData *left = (IpIdCheckData*)&config;
    IpIdCheckData *right = (IpIdCheckData*)&rhs.config;

    if (left->ip_id == right->ip_id)
    {
        return true;
    }

    return false;
}

int IpIdOption::eval(Packet *p)
{
    IpIdCheckData *ipIdCheckData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
        return rval; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(ipIdPerfStats);

    if(ipIdCheckData->ip_id == GET_IPH_ID(p))
    {
        /* call the next function in the function list recursively */
        rval = DETECTION_OPTION_MATCH;
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No match for sp_ip_id_check\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ipIdPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void id_parse(char *data, IpIdCheckData* ds_ptr)
{
    int ip_id;
    char *endTok;

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }

    ip_id = SnortStrtolRange(data, &endTok, 10, 0, UINT16_MAX);
    if ((endTok == data) || (*endTok != '\0'))
    {
        ParseError("Invalid parameter '%s' to id (not a number?) ", data);
    }
    ds_ptr->ip_id = htons( (u_short) ip_id);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ID set to %ld\n", ds_ptr->ip_id););
}

static IpsOption* id_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IpIdCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    id_parse(data, &ds_ptr);
    return new IpIdOption(ds_ptr);
}

static void id_dtor(IpsOption* p)
{
    delete p;
}

static void id_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &ipIdPerfStats, id_get_profile);
#endif
}

static const IpsApi id_api =
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
    id_ginit,
    nullptr,
    nullptr,
    nullptr,
    id_ctor,
    id_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &id_api.base,
    nullptr
};
#else
const BaseApi* ips_id = &id_api.base;
#endif

