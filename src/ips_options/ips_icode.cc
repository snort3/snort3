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

#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string.h>
#include <ctype.h>

#include "snort_types.h"
#include "treenodes.h"
#include "decode.h"
#include "parser.h"
#include "util.h"
#include "snort_debug.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "icode";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats icmpCodePerfStats;

static PreprocStats* ic_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &icmpCodePerfStats;

    return nullptr;
}
#endif

typedef struct _IcmpCodeCheckData
{
    /* the icmp code number */
    int icmp_code;
    int icmp_code2;
    uint8_t opcode;
} IcmpCodeCheckData;

#define ICMP_CODE_TEST_EQ 1
#define ICMP_CODE_TEST_GT 2
#define ICMP_CODE_TEST_LT 3
#define ICMP_CODE_TEST_RG 4

class IcmpCodeOption : public IpsOption
{
public:
    IcmpCodeOption(const IcmpCodeCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    IcmpCodeCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpCodeOption::hash() const
{
    uint32_t a,b,c;
    const IcmpCodeCheckData *data = &config;

    a = data->icmp_code;
    b = data->icmp_code2;
    c = data->opcode;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IcmpCodeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcmpCodeOption& rhs = (IcmpCodeOption&)ips;
    IcmpCodeCheckData *left = (IcmpCodeCheckData*)&config;
    IcmpCodeCheckData *right = (IcmpCodeCheckData*)&rhs.config;

    if ((left->icmp_code == right->icmp_code) &&
        (left->icmp_code2 == right->icmp_code2) &&
        (left->opcode == right->opcode))
    {
        return true;
    }

    return false;
}

int IcmpCodeOption::eval(Packet *p)
{
    IcmpCodeCheckData *ds_ptr = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    /* return 0  if we don't have an icmp header */
    if(!p->icmph)
        return rval;

    PREPROC_PROFILE_START(icmpCodePerfStats);

    switch(ds_ptr->opcode)
    {
        case ICMP_CODE_TEST_EQ:
            if (ds_ptr->icmp_code == p->icmph->code)
                rval = DETECTION_OPTION_MATCH;
            break;
        case ICMP_CODE_TEST_GT:
            if (p->icmph->code > ds_ptr->icmp_code)
                rval = DETECTION_OPTION_MATCH;
            break;
        case ICMP_CODE_TEST_LT:
            if (p->icmph->code < ds_ptr->icmp_code)
                rval = DETECTION_OPTION_MATCH;
            break;
        case ICMP_CODE_TEST_RG:
            if (p->icmph->code > ds_ptr->icmp_code &&
                    p->icmph->code < ds_ptr->icmp_code2)
                rval = DETECTION_OPTION_MATCH;
            break;
        default:
            break;
    }

    PREPROC_PROFILE_END(icmpCodePerfStats);

    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

void icode_parse(char *data, IcmpCodeCheckData *ds_ptr)
{
    char *code;
    char *endptr = NULL;

    /* set a pointer to the data so to leave the original unchanged */
    code = data;

    if(!data)
    {
        ParseError("No ICMP Code Specified");
    }


    /* get rid of whitespace before the data */
    while(isspace((int)*data))
        data++;

    if (*data == '\0')
    {
        ParseError("No ICMP Code Specified");
    }

    /*
     * If a range is specified, put the min in icmp_code, and the max in
     * icmp_code2
     */

    if (isdigit((int)*data) && strstr(data, "<>"))
    {
        ds_ptr->icmp_code = strtol(data, &endptr, 10);
        while (isspace((int)*endptr))
            endptr++;

        if (*endptr != '<')
        {
            ParseError("Invalid ICMP icode in rule: %s", code);
        }

        data = endptr;

        data += 2;   /* move past <> */

        while (isspace((int)*data))
            data++;

        ds_ptr->icmp_code2 = strtol(data, &endptr, 10);
        if (*data == '\0' || *endptr != '\0')
        {
            ParseError("Invalid ICMP icode in rule: %s", code);
        }

        ds_ptr->opcode = ICMP_CODE_TEST_RG;
    }
    /* otherwise if its greater than... */
    else if (*data == '>')
    {
        data++;
        while (isspace((int)*data))
            data++;

        ds_ptr->icmp_code = strtol(data, &endptr, 10);
        if (*data == '\0' || *endptr != '\0')
        {
            ParseError("Invalid ICMP icode in rule: %s", code);
        }

        ds_ptr->opcode = ICMP_CODE_TEST_GT;
    }
    /* otherwise if its less than ... */
    else if (*data == '<')
    {
        data++;
        while (isspace((int)*data))
            data++;

        ds_ptr->icmp_code = strtol(data, &endptr, 10);
        if (*data == '\0' || *endptr != '\0')
        {
            ParseError("Invalid ICMP icode in rule: %s", code);
        }

        ds_ptr->opcode = ICMP_CODE_TEST_LT;
    }
    /* otherwise check if its a digit */
    else
    {
        ds_ptr->icmp_code = strtol(data, &endptr, 10);
        if (*endptr != '\0')
        {
            ParseError("Invalid ICMP icode in rule: %s", code);
        }

        ds_ptr->opcode = ICMP_CODE_TEST_EQ;
    }
    return;
}

static IpsOption* icode_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IcmpCodeCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    icode_parse(data, &ds_ptr);
    return new IcmpCodeOption(ds_ptr);
}

static void icode_dtor(IpsOption* p)
{
    delete p;
}

static void icode_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &icmpCodePerfStats, ic_get_profile);
#endif
}

static const IpsApi icode_api =
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
    1, PROTO_BIT__ICMP,
    icode_ginit,
    nullptr,
    nullptr,
    nullptr,
    icode_ctor,
    icode_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &icode_api.base,
    nullptr
};
#else
const BaseApi* ips_icode = &icode_api.base;
#endif

