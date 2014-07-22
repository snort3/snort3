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
#include "framework/cursor.h"
#include "framework/module.h"
#include "flow/flow.h"

static const char* s_name = "bufferlen";

static THREAD_LOCAL ProfileStats lenCheckPerfStats;

#define LEN_CHECK_EQ 1
#define LEN_CHECK_GT 2
#define LEN_CHECK_LT 3
#define LEN_CHECK_RG 4

struct LenCheckData 
{
    uint16_t len;
    uint16_t len2;
    char oper;
};

class LenOption : public IpsOption
{
public:
    LenOption(const LenCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    LenCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t LenOption::hash() const
{
    uint32_t a,b,c;
    const LenCheckData *data = &config;

    a = data->len;
    b = data->len2;
    c = data->oper;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool LenOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    LenOption& rhs = (LenOption&)ips;
    LenCheckData *left = (LenCheckData*)&config;
    LenCheckData *right = (LenCheckData*)&rhs.config;

    if ( (left->len == right->len)
            && (left->len2 == right->len2)
            && (left->oper == right->oper) )
    {
        return true;
    }

    return false;
}

int LenOption::eval(Cursor& c, Packet*)
{
    LenCheckData *udata = &config;
    int rval = DETECTION_OPTION_NO_MATCH;

    PROFILE_VARS;
    PREPROC_PROFILE_START(lenCheckPerfStats);

    switch (udata->oper)
    {
        case LEN_CHECK_EQ:
            if (udata->len == c.size())
                rval = DETECTION_OPTION_MATCH;
            break;
        case LEN_CHECK_GT:
            if (udata->len < c.size())
                rval = DETECTION_OPTION_MATCH;
            break;
        case LEN_CHECK_LT:
            if (udata->len > c.size())
                rval = DETECTION_OPTION_MATCH;
            break;
        case LEN_CHECK_RG:
            if ((udata->len <= c.size()) && (udata->len2 >= c.size()))
                rval = DETECTION_OPTION_MATCH;
            break;
        default:
            break;
    }

    PREPROC_PROFILE_END(lenCheckPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module methods
//-------------------------------------------------------------------------

static void len_parse(const char* argp, LenCheckData* ds_ptr)
{
    char* curp = NULL;
    char **toks;
    int num_toks;

    toks = mSplit(argp, ",", 2, &num_toks, '\\');
    if (!num_toks)
    {
        ParseError("'%s' requires arguments.", s_name);
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
            ParseError("Invalid '%s' argument.", s_name);
        }

        val = strtol(mtoks[0], &endp, 0);
        if ((val < 0) || *endp || (val > UINT16_MAX))
        {
            ParseError("Invalid '%s' argument.", s_name);
        }

        ds_ptr->len = (uint16_t)val;

        val = strtol(mtoks[1], &endp, 0);
        if ((val < 0) || *endp || (val > UINT16_MAX))
        {
            ParseError("Invalid '%s' argument.", s_name);
        }

        ds_ptr->len2 = (uint16_t)val;

        if (ds_ptr->len2 < ds_ptr->len)
        {
            uint16_t tmp = ds_ptr->len;
            ds_ptr->len = ds_ptr->len2;
            ds_ptr->len2 = tmp;
        }

        ds_ptr->oper = LEN_CHECK_RG;

        mSplitFree(&mtoks, num_mtoks);
    }
    else
    {
        char* endp = NULL;
        long int val;

        if(*curp == '>')
        {
            curp++;
            ds_ptr->oper = LEN_CHECK_GT;
        }
        else if(*curp == '<')
        {
            curp++;
            ds_ptr->oper = LEN_CHECK_LT;
        }
        else
        {
            ds_ptr->oper = LEN_CHECK_EQ;
        }

        while(isspace((int)*curp)) curp++;

        if (!*curp)
        {
            ParseError("Invalid '%s' argument.", s_name);
        }

        val = strtol(curp, &endp, 0);
        if ((val < 0) || *endp || (val > UINT16_MAX))
        {
            ParseError("Invalid '%s' argument.", s_name);
        }

        if ((ds_ptr->oper == LEN_CHECK_LT) && (val == 0))
        {
            ParseError("Invalid '%s' argument.", s_name);
        }

        ds_ptr->len = (uint16_t)val;
    }

    if (num_toks > 1 || strchr(argp, ','))
    {
        ParseError("Invalid '%s' argument.", s_name);
    }

    mSplitFree(&toks, num_toks);
}

static const Parameter len_params[] =
{
    { "*range", Parameter::PT_STRING, nullptr, nullptr,
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

    LenCheckData data;
};

bool LenModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool LenModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("*range") )
        return false;

    len_parse(v.get_string(), &data);
    return true;
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

