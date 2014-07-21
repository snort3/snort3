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
#include <string.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "itype";

#ifdef PERF_PROFILING
static THREAD_LOCAL ProfileStats icmpTypePerfStats;

static ProfileStats* it_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &icmpTypePerfStats;

    return nullptr;
}
#endif

#define ICMP_TYPE_TEST_EQ 1
#define ICMP_TYPE_TEST_GT 2
#define ICMP_TYPE_TEST_LT 3
#define ICMP_TYPE_TEST_RG 4

typedef struct _IcmpTypeCheckData  // FIXIT used in parser.cc
{
    /* the icmp type number */
    int icmp_type;
    int icmp_type2;
    uint8_t opcode;
} IcmpTypeCheckData;

class IcmpTypeOption : public IpsOption
{
public:
    IcmpTypeOption(const IcmpTypeCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    IcmpTypeCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpTypeOption::hash() const
{
    uint32_t a,b,c;
    const IcmpTypeCheckData *data = &config;

    a = data->icmp_type;
    b = data->icmp_type2;
    c = data->opcode;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IcmpTypeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcmpTypeOption& rhs = (IcmpTypeOption&)ips;
    IcmpTypeCheckData *left = (IcmpTypeCheckData*)&config;
    IcmpTypeCheckData *right = (IcmpTypeCheckData*)&rhs.config;

    if ((left->icmp_type == right->icmp_type) &&
        (left->icmp_type2 == right->icmp_type2) &&
        (left->opcode == right->opcode))
    {
        return true;
    }

    return false;
}

int IcmpTypeOption::eval(Cursor&, Packet *p)
{
    IcmpTypeCheckData *ds_ptr = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    /* return 0  if we don't have an icmp header */
    if(!p->icmph)
        return rval;

    PREPROC_PROFILE_START(icmpTypePerfStats);

    switch(ds_ptr->opcode)
    {
        case ICMP_TYPE_TEST_EQ:
            if (p->icmph->type == ds_ptr->icmp_type)
                rval = DETECTION_OPTION_MATCH;
            break;
        case ICMP_TYPE_TEST_GT:
            if (p->icmph->type > ds_ptr->icmp_type)
                rval = DETECTION_OPTION_MATCH;
            break;
        case ICMP_TYPE_TEST_LT:
            if (p->icmph->type < ds_ptr->icmp_type)
                rval = DETECTION_OPTION_MATCH;
            break;
        case ICMP_TYPE_TEST_RG:
            if (p->icmph->type > ds_ptr->icmp_type &&
                    p->icmph->type < ds_ptr->icmp_type2)
                rval = DETECTION_OPTION_MATCH;
            break;
    }

    DEBUG_WRAP(
        if (rval == DETECTION_OPTION_MATCH)
        {
            DebugMessage(DEBUG_PLUGIN, "Got icmp type match!\n");
        }
        else
        {
            DebugMessage(DEBUG_PLUGIN, "Failed icmp type match!\n");
        }
        );

    PREPROC_PROFILE_END(icmpTypePerfStats);
    return rval;
}
//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void itype_parse(char *data, IcmpTypeCheckData *ds_ptr)
{
    char *type;
    char *endptr = NULL;

    /* set a pointer to the data so to leave the original unchanged */
    type = data;

    if(!data)
    {
        ParseError("No ICMP Type Specified");
    }

    /* get rid of spaces before the data */
    while(isspace((int)*data))
        data++;

    if (*data == '\0')
    {
        ParseError("No ICMP Type Specified : %s", type);
    }

    /*
     * if a range is specified, put the min in icmp_type, and the max in
     * icmp_type2
     */

    if (isdigit((int)*data) && strstr(data, "<>"))
    {
        ds_ptr->icmp_type = strtol(data, &endptr, 10);
        while (isspace((int)*endptr))
            endptr++;

        if (*endptr != '<')
        {
            ParseError("Invalid ICMP itype in rule: %s", type);
        }

        data = endptr;

        data += 2;   /* move past <> */

        while (isspace((int)*data))
            data++;

        ds_ptr->icmp_type2 = strtol(data, &endptr, 10);
        if (*data == '\0' || *endptr != '\0')
        {
            ParseError("Invalid ICMP itype in rule: %s", type);
        }

        ds_ptr->opcode = ICMP_TYPE_TEST_RG;
    }
    /* otherwise if its greater than... */
    else if (*data == '>')
    {
        data++;
        while (isspace((int)*data))
            data++;

        ds_ptr->icmp_type = strtol(data, &endptr, 10);
        if (*data == '\0' || *endptr != '\0')
        {
            ParseError("Invalid ICMP itype in rule: %s", type);
        }

        ds_ptr->opcode = ICMP_TYPE_TEST_GT;
    }
    /* otherwise if its less than ... */
    else if (*data == '<')
    {
        data++;
        while (isspace((int)*data))
            data++;

        ds_ptr->icmp_type = strtol(data, &endptr, 10);
        if (*data == '\0' || *endptr != '\0')
        {
            ParseError("Invalid ICMP itype in rule: %s", type);
        }

        ds_ptr->opcode  = ICMP_TYPE_TEST_LT;
    }
    /* otherwise check if its a digit */
    else
    {
        ds_ptr->icmp_type = strtol(data, &endptr, 10);
        if (*endptr != '\0')
        {
            ParseError("Invalid ICMP itype in rule: %s", type);
        }

        ds_ptr->opcode = ICMP_TYPE_TEST_EQ;
    }

    return;
}

static IpsOption* itype_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IcmpTypeCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    itype_parse(data, &ds_ptr);
    return new IcmpTypeOption(ds_ptr);
}

static void itype_dtor(IpsOption* p)
{
    delete p;
}

static void itype_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, it_get_profile);
#endif
}

static const IpsApi itype_api =
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
    itype_ginit,
    nullptr,
    nullptr,
    nullptr,
    itype_ctor,
    itype_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &itype_api.base,
    nullptr
};
#else
const BaseApi* ips_itype = &itype_api.base;
#endif

