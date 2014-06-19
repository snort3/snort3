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

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats fragOffsetPerfStats;

static PreprocStats* fo_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &fragOffsetPerfStats;

    return nullptr;
}
#endif

typedef struct _FragOffsetData
{
    uint8_t  comparison_flag;
    uint8_t  not_flag;
    uint16_t offset;
} FragOffsetData;

class FragOffsetOption : public IpsOption
{
public:
    FragOffsetOption(const FragOffsetData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    FragOffsetData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t FragOffsetOption::hash() const
{
    uint32_t a,b,c;
    const FragOffsetData *data = &config;

    a = data->comparison_flag || (data->not_flag << 8);
    b = data->offset;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool FragOffsetOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FragOffsetOption& rhs = (FragOffsetOption&)ips;
    FragOffsetData *left = (FragOffsetData*)&config;
    FragOffsetData *right = (FragOffsetData*)&rhs.config;

    if ((left->comparison_flag == right->comparison_flag) &&
        (left->not_flag == right->not_flag) &&
        (left->offset == right->offset))
    {
        return true;
    }

    return false;
}

int FragOffsetOption::eval(Cursor&, Packet *p)
{
    FragOffsetData *ipd = &config;
    int p_offset = p->frag_offset * 8;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
    {
        return rval;
    }

    PREPROC_PROFILE_START(fragOffsetPerfStats);


#ifdef DEBUG_MSGS
    DebugMessage(DEBUG_PLUGIN,
         "[!] Checking fragoffset %d against %d\n",
         ipd->offset, p->frag_offset * 8);

    if(p->frag_flag)
    {
        DebugMessage(DEBUG_PLUGIN, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
             (p->frag_offset & 0x1FFF) * 8,
             (ntohs(GET_IPH_LEN(p)) - p->frag_offset - IP_HEADER_LEN));
    }
#endif


    if(!ipd->comparison_flag)
    {
        if((ipd->offset == p_offset) ^ ipd->not_flag)
        {
            rval = DETECTION_OPTION_MATCH;
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
        }
    }
    else
    {
        if(ipd->comparison_flag == GREATER_THAN)
        {
            if(p_offset > ipd->offset)
            {
                rval = DETECTION_OPTION_MATCH;
            }
        }
        else
        {
            if(p_offset < ipd->offset)
            {
                rval = DETECTION_OPTION_MATCH;
            }
        }
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(fragOffsetPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void fragoffset_parse(char *data, FragOffsetData *ds_ptr)
{
    char *fptr;
    char *endTok;

    /* manipulate the option arguments here */
    fptr = data;

    while(isspace((u_char) *fptr))
    {
        fptr++;
    }

    if(strlen(fptr) == 0)
    {
        ParseError("No arguments to the fragoffset keyword");
    }

    if(*fptr == '!')
    {
        ds_ptr->not_flag = 1;
        fptr++;
    }

    if(*fptr == '>')
    {
        if(!ds_ptr->not_flag)
        {
            ds_ptr->comparison_flag = GREATER_THAN;
            fptr++;
        }
    }

    if(*fptr == '<')
    {
        if(!ds_ptr->comparison_flag && !ds_ptr->not_flag)
        {
            ds_ptr->comparison_flag = LESS_THAN;
            fptr++;
        }
    }

    ds_ptr->offset = (uint16_t)SnortStrtoulRange(fptr, &endTok, 10, 0, UINT16_MAX);
    if ((endTok == fptr) || (*endTok != '\0'))
    {
        ParseError("Invalid parameter '%s' to fragoffset (not a number?)", fptr);
    }
}

static IpsOption* fragoffset_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    FragOffsetData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    fragoffset_parse(data, &ds_ptr);
    return new FragOffsetOption(ds_ptr);
}

static void fragoffset_dtor(IpsOption* p)
{
    delete p;
}

static void fragoffset_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &fragOffsetPerfStats, fo_get_profile);
#endif
}

static const IpsApi fragoffset_api =
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
    0, 0,  // FIXIT more than one fragoffset per rule?
    fragoffset_ginit,
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

