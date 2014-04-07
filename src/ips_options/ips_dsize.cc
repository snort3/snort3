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

#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <string.h>

#include "snort_types.h"
#include "detection/treenodes.h"
#include "decode.h"
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

static const char* s_name = "dsize";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats dsizePerfStats;

static PreprocStats* dsz_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &dsizePerfStats;

    return nullptr;
}
#endif

#define DSIZE_EQ                   1
#define DSIZE_GT                   2
#define DSIZE_LT                   3
#define DSIZE_RANGE                4

typedef struct _DsizeCheckData
{
    int dsize;
    int dsize2;
    char opcode;
} DsizeCheckData;

class DsizeOption : public IpsOption
{
public:
    DsizeOption(const DsizeCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    ~DsizeOption() { };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    DsizeCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t DsizeOption::hash() const
{
    uint32_t a,b,c;
    const DsizeCheckData *data = &config;

    a = data->dsize;
    b = data->dsize2;
    c = data->opcode;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool DsizeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    DsizeOption& rhs = (DsizeOption&)ips;
    DsizeCheckData *left = (DsizeCheckData*)&config;
    DsizeCheckData *right = (DsizeCheckData*)&rhs.config;

    if (( left->dsize == right->dsize) &&
        ( left->dsize2 == right->dsize2) &&
        ( left->opcode == right->opcode))
    {
        return true;
    }

    return false;
}

// Test the packet's payload size against the rule payload size value
int DsizeOption::eval(Packet *p)
{
    DsizeCheckData *ds_ptr = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dsizePerfStats);

    /* fake packet dsizes are always wrong */
    /* (unless they are PDUs) */
    if (
        (p->packet_flags & PKT_REBUILT_STREAM) &&
        !(p->packet_flags & PKT_PDU_HEAD) )
    {
        PREPROC_PROFILE_END(dsizePerfStats);
        return rval;
    }

    switch (ds_ptr->opcode)
    {
        case DSIZE_EQ:
            if (ds_ptr->dsize == p->dsize)
                rval = DETECTION_OPTION_MATCH;
            break;
        case DSIZE_GT:
            if (ds_ptr->dsize < p->dsize)
                rval = DETECTION_OPTION_MATCH;
            break;
        case DSIZE_LT:
            if (ds_ptr->dsize > p->dsize)
                rval = DETECTION_OPTION_MATCH;
            break;
        case DSIZE_RANGE:
            if ((ds_ptr->dsize <= p->dsize) &&
                (ds_ptr->dsize2 >= p->dsize))
                rval = DETECTION_OPTION_MATCH;
            break;
        default:
            break;
    }

    PREPROC_PROFILE_END(dsizePerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void dsize_parse(char *data, DsizeCheckData *ds_ptr)
{
    char *pcEnd;
    char *pcTok;
    int  iDsize = 0;

    while(isspace((int)*data)) data++;

    /* If a range is specified, put min in ds_ptr->dsize and max in
       ds_ptr->dsize2 */

    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
    {
        char* lasts = nullptr;
        pcTok = strtok_r(data, " <>", &lasts);
        if(!pcTok)
        {
            /*
            **  Fatal
            */
            ParseError("Invalid 'dsize' argument.");
        }

        iDsize = strtol(pcTok, &pcEnd, 10);
        if(iDsize < 0 || *pcEnd)
        {
            ParseError("Invalid 'dsize' argument.");
        }

        ds_ptr->dsize = (unsigned short)iDsize;

        pcTok = strtok_r(NULL, " <>", &lasts);
        if(!pcTok)
        {
            ParseError("Invalid 'dsize' argument.");
        }

        iDsize = strtol(pcTok, &pcEnd, 10);
        if(iDsize < 0 || *pcEnd)
        {
            ParseError("Invalid 'dsize' argument.");
        }

        ds_ptr->dsize2 = (unsigned short)iDsize;

        ds_ptr->opcode = DSIZE_RANGE;
        return;
    }
    else if(*data == '>')
    {
        data++;
        ds_ptr->opcode = DSIZE_GT;
    }
    else if(*data == '<')
    {
        data++;
        ds_ptr->opcode = DSIZE_LT;
    }
    else
    {
        ds_ptr->opcode = DSIZE_EQ;
    }

    while(isspace((int)*data)) data++;

    iDsize = strtol(data, &pcEnd, 10);
    if(iDsize < 0 || *pcEnd)
    {
        ParseError("Invalid 'dsize' argument.");
    }

    ds_ptr->dsize = (unsigned short)iDsize;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Payload length = %d\n", ds_ptr->dsize););

}

static IpsOption* dsize_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    DsizeCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    dsize_parse(data, &ds_ptr);
    return new DsizeOption(ds_ptr);
}

static void dsize_dtor(IpsOption* p)
{
    delete p;
}

static void dsize_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &dsizePerfStats, dsz_get_profile);
#endif
}

static const IpsApi dsize_api =
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
    dsize_ginit,
    nullptr,
    nullptr,
    nullptr,
    dsize_ctor,
    dsize_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dsize_api.base,
    nullptr
};
#else
const BaseApi* ips_dsize = &dsize_api.base;
#endif

