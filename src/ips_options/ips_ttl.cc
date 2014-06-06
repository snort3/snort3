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

#include <stdlib.h>
#include <ctype.h>

#include "snort_types.h"
#include "treenodes.h"
#include "protocols/packet.h"
#include "snort_debug.h"
#include "parser.h"
#include "util.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "ttl";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats ttlCheckPerfStats;

static PreprocStats* ttl_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &ttlCheckPerfStats;

    return nullptr;
}
#endif

#define TTL_CHECK_EQ 1
#define TTL_CHECK_GT 2
#define TTL_CHECK_LT 3
#define TTL_CHECK_RG 4
#define TTL_CHECK_GT_EQ 5
#define TTL_CHECK_LT_EQ 6

typedef struct _TtlCheckData
{
    int ttl;
    int h_ttl;
    char oper;
} TtlCheckData;

class TtlOption : public IpsOption
{
public:
    TtlOption(const TtlCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    TtlCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t TtlOption::hash() const
{
    uint32_t a,b,c;
    const TtlCheckData *data = &config;

    a = data->ttl;
    b = data->h_ttl;
    c = data->oper;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TtlOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    TtlOption& rhs = (TtlOption&)ips;
    TtlCheckData *left = (TtlCheckData*)&config;
    TtlCheckData *right = (TtlCheckData*)&rhs.config;

    if ((left->ttl == right->ttl) &&
        (left->h_ttl == right->h_ttl) &&
        (left->oper == right->oper))
    {
        return true;
    }

    return false;
}

int TtlOption::eval(Packet *p)
{
    TtlCheckData *ttlCheckData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
        return rval;

    PREPROC_PROFILE_START(ttlCheckPerfStats);

    switch (ttlCheckData->oper)
    {
        case TTL_CHECK_EQ:
            if (ttlCheckData->ttl == GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG_MSGS
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not equal to %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
        case TTL_CHECK_GT:
            if (ttlCheckData->ttl < GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG_MSGS
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not greater than %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
        case TTL_CHECK_LT:
            if (ttlCheckData->ttl > GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG_MSGS
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not less than %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
        case TTL_CHECK_GT_EQ:
            if (ttlCheckData->ttl <= GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG_MSGS
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not greater than or equal to %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
        case TTL_CHECK_LT_EQ:
            if (ttlCheckData->ttl >= GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG_MSGS
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not less than or equal to %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;

         case TTL_CHECK_RG:
            if ((ttlCheckData->ttl <= GET_IPH_TTL(p)) &&
                (ttlCheckData->h_ttl >= GET_IPH_TTL(p)))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG_MSGS
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlLT: Not Within the range %d - %d (%d)\n",
                     ttlCheckData->ttl,
                     ttlCheckData->h_ttl,
                     GET_IPH_TTL(p));
            }
#endif
            break;
        default:
            break;
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ttlCheckPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void ttl_parse(char *data, TtlCheckData *ds_ptr)
{
    char ttlrel;
    char *endTok;
    int ttl;
    char *origData = data;
    char *curPtr  = data;
    int equals_present = 0, rel_present =0;

    if(data == NULL)
    {
        ParseError("No arguments to 'ttl'");
    }

    while(isspace((int)*data)) data++;

    ttlrel = *data;
    curPtr = data;

    switch (ttlrel) {
        case '-':
            ds_ptr->h_ttl = -1; /* leading dash flag */
            data++;
            rel_present = 1;
            break;
        case '>':
        case '<':
            curPtr++;
            while(isspace((int)*curPtr)) curPtr++;
            if((*curPtr) == '=')
            {
                equals_present = 1;
                data = curPtr;
            }
        case '=':
            data++;
            rel_present = 1;
            break;
       default:
            ttlrel = '=';
    }
    while(isspace((int)*data)) data++;

    ttl = SnortStrtol(data, &endTok, 10);
    /* next char after first number must either be - or NULL */
    if ((endTok == data) || ((*endTok != '-') && (*endTok != '\0')))
    {
        ParseError("Invalid parameter '%s' to 'ttl' (not a number?)", origData);
    }

    if (ttl< 0 || ttl > 255)
    {
        ParseError("Invalid number '%s' to 'ttl' (should be between 0 to 255)",
            origData);
    }
    ds_ptr->ttl = ttl;

    data = endTok;
    if (*data == '-')
    {
        if(rel_present || (ds_ptr->h_ttl == -1 ))
        {
            ParseError("Invalid parameter '%s' to 'ttl' (not a number?)", origData);
        }
        data++;
        ttlrel = '-';
    }
    switch (ttlrel)
    {
        case '>':
            if(equals_present)
                ds_ptr->oper = TTL_CHECK_GT_EQ;
            else
                ds_ptr->oper = TTL_CHECK_GT;
            break;
        case '<':
            if(equals_present)
                ds_ptr->oper = TTL_CHECK_LT_EQ;
            else
                ds_ptr->oper = TTL_CHECK_LT;
            break;
        case '=':
            ds_ptr->oper = TTL_CHECK_EQ;
            break;
        case '-':
            while(isspace((int)*data)) data++;
            if (ds_ptr->h_ttl != -1)
            {
                if(*data=='\0')
                {
                    ds_ptr->h_ttl = 255;
                }
                else
                {
                    ttl = SnortStrtol(data, &endTok, 10);
                    if ((endTok == data) || (*endTok != '\0') || (ds_ptr->ttl > ttl))
                    {
                        ParseError("Invalid parameter '%s' to 'ttl' "
                                "(not a number or invalid range?) ", origData);
                    }
                    if (ttl< 0 || ttl > 255)
                    {
                        ParseError("Invalid number '%s' to 'ttl' (should be between 0 to  "
                                "255) ", origData);
                    }
                    if (ttl == 0)
                        ds_ptr->h_ttl = 255;
                    else
                        ds_ptr->h_ttl = ttl;
                }
            }
            else /* leading dash*/
            {
                ds_ptr->h_ttl = ds_ptr->ttl;
                ds_ptr->ttl   = 0;
            }
            ds_ptr->oper = TTL_CHECK_RG;
            break;
        default:
            break;
    }
    DEBUG_WRAP(DebugMessage(
        DEBUG_PLUGIN, "Set TTL check value to %c%d (%d)\n",
        ttlrel, ds_ptr->ttl, ds_ptr->h_ttl););
}

static IpsOption* ttl_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    TtlCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    ttl_parse(data, &ds_ptr);
    return new TtlOption(ds_ptr);
}

static void ttl_dtor(IpsOption* p)
{
    delete p;
}

static void ttl_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &ttlCheckPerfStats, ttl_get_profile);
#endif
}

static const IpsApi ttl_api =
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
    ttl_ginit,
    nullptr,
    nullptr,
    nullptr,
    ttl_ctor,
    ttl_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ttl_api.base,
    nullptr
};
#else
const BaseApi* ips_ttl = &ttl_api.base;
#endif

