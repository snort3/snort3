/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2005-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "snort_types.h"
#include "treenodes.h"
#include "protocols/packet.h"
#include "snort_debug.h"
#include "parser.h"
#include "util.h"
#include "sfhashfcn.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "detection_util.h"
#include "framework/ips_option.h"
#include "framework/inspector.h"
#include "flow/flow.h"

static const char* s_name = "urilen";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats urilenCheckPerfStats;

static PreprocStats* uc_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &urilenCheckPerfStats;

    return nullptr;
}
#endif

#define URI_LEN_BUF_NORM  "norm"
#define URI_LEN_BUF_RAW   "raw"

#define URILEN_CHECK_EQ 1
#define URILEN_CHECK_GT 2
#define URILEN_CHECK_LT 3
#define URILEN_CHECK_RG 4

struct UriLenCheckData 
{
    uint16_t urilen;
    uint16_t urilen2;
    char oper;
    const char* key;

};

class UriLenOption : public IpsOption
{
public:
    UriLenOption(const UriLenCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    UriLenCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t UriLenOption::hash() const
{
    uint32_t a,b,c;
    const UriLenCheckData *data = &config;

    a = data->urilen;
    b = data->urilen2;
    c = data->oper;

    mix(a,b,c);

    a += strcmp(data->key, "http_uri");
    b += 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool UriLenOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    UriLenOption& rhs = (UriLenOption&)ips;
    UriLenCheckData *left = (UriLenCheckData*)&config;
    UriLenCheckData *right = (UriLenCheckData*)&rhs.config;

    if ((left->urilen == right->urilen)
            && (left->urilen2 == right->urilen2)
            && (left->oper == right->oper)
            && (!strcmp(left->key, right->key)) )
    {
        return true;
    }

    return false;
}

int UriLenOption::eval(Cursor&, Packet* p)
{
    UriLenCheckData *udata = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    InspectionBuffer hb;

    PROFILE_VARS;
    PREPROC_PROFILE_START(urilenCheckPerfStats);

    if ( !p->flow || !p->flow->clouseau ||
         // FIXIT cache id at parse time for runtime use
         !p->flow->clouseau->get_buf(udata->key, p, hb) )
    {
        PREPROC_PROFILE_END(urilenCheckPerfStats);
        return rval;
    }

    switch (udata->oper)
    {
        case URILEN_CHECK_EQ:
            if (udata->urilen == hb.len)
                rval = DETECTION_OPTION_MATCH;
            break;
        case URILEN_CHECK_GT:
            if (udata->urilen < hb.len)
                rval = DETECTION_OPTION_MATCH;
            break;
        case URILEN_CHECK_LT:
            if (udata->urilen > hb.len)
                rval = DETECTION_OPTION_MATCH;
            break;
        case URILEN_CHECK_RG:
            if ((udata->urilen <= hb.len) && (udata->urilen2 >= hb.len))
                rval = DETECTION_OPTION_MATCH;
            break;
        default:
            break;
    }

    PREPROC_PROFILE_END(urilenCheckPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void urilen_parse(char* argp, UriLenCheckData* ds_ptr)
{
    char* curp = NULL;
    char **toks;
    int num_toks;

    toks = mSplit(argp, ",", 2, &num_toks, '\\');
    if (!num_toks)
    {
        ParseError("'urilen' requires arguments.");
    }

    curp = toks[0];

    /* Parse the string */
    if (isdigit((int)*curp) && strstr(curp, "<>"))
    {
        char **mtoks;
        int num_mtoks;
        char* endp = NULL;
        long int val;

        mtoks = mSplit(curp, "<>", 2, &num_mtoks, '\\');
        if (num_mtoks != 2)
        {
            ParseError("Invalid 'urilen' argument.");
        }

        val = strtol(mtoks[0], &endp, 0);
        if ((val < 0) || *endp || (val > UINT16_MAX))
        {
            ParseError("Invalid 'urilen' argument.");
        }

        ds_ptr->urilen = (uint16_t)val;

        val = strtol(mtoks[1], &endp, 0);
        if ((val < 0) || *endp || (val > UINT16_MAX))
        {
            ParseError("Invalid 'urilen' argument.");
        }

        ds_ptr->urilen2 = (uint16_t)val;

        if (ds_ptr->urilen2 < ds_ptr->urilen)
        {
            uint16_t tmp = ds_ptr->urilen;
            ds_ptr->urilen = ds_ptr->urilen2;
            ds_ptr->urilen2 = tmp;
        }

        ds_ptr->oper = URILEN_CHECK_RG;

        mSplitFree(&mtoks, num_mtoks);
    }
    else
    {
        char* endp = NULL;
        long int val;

        if(*curp == '>')
        {
            curp++;
            ds_ptr->oper = URILEN_CHECK_GT;
        }
        else if(*curp == '<')
        {
            curp++;
            ds_ptr->oper = URILEN_CHECK_LT;
        }
        else
        {
            ds_ptr->oper = URILEN_CHECK_EQ;
        }

        while(isspace((int)*curp)) curp++;

        if (!*curp)
        {
            ParseError("Invalid 'urilen' argument.");
        }

        val = strtol(curp, &endp, 0);
        if ((val < 0) || *endp || (val > UINT16_MAX))
        {
            ParseError("Invalid 'urilen' argument.");
        }

        if ((ds_ptr->oper == URILEN_CHECK_LT) && (val == 0))
        {
            ParseError("Invalid 'urilen' argument.");
        }

        ds_ptr->urilen = (uint16_t)val;
    }

    if (num_toks > 1)
    {
        if (!strcmp(toks[1], URI_LEN_BUF_NORM))
            ds_ptr->key = "http_uri";
        else if (!strcmp(toks[1], URI_LEN_BUF_RAW))
            ds_ptr->key = "http_raw_uri";
        else
            ParseError("Invalid 'urilen' argument.");
    }
    else
    {
        if (strchr(argp, ','))
        {
            ParseError("Invalid 'urilen' argument.");
        }

        ds_ptr->key = "http_raw_uri";
    }

    mSplitFree(&toks, num_toks);
}

static IpsOption* urilen_ctor(
    SnortConfig*, char* argp, OptTreeNode*)
{
    UriLenCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    urilen_parse(argp, &ds_ptr);
    return new UriLenOption(ds_ptr);
}

static void urilen_dtor(IpsOption* p)
{
    delete p;
}

static void urilen_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &urilenCheckPerfStats, uc_get_profile);
#endif
}

static const IpsApi urilen_api =
{
    {
        PT_IPS_OPTION,
        "urilen",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, 0,
    urilen_ginit,
    nullptr,
    nullptr,
    nullptr,
    urilen_ctor,
    urilen_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &urilen_api.base,
    nullptr
};
#else
const BaseApi* ips_urilen = &urilen_api.base;
#endif

