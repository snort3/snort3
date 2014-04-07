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

/* sp_icmp_id
 *
 * Purpose:
 *
 * Test the ID field of ICMP ECHO and ECHO_REPLY packets for specified
 * values.  This is useful for detecting TFN attacks, amongst others.
 *
 * Arguments:
 *
 * The ICMP ID plugin takes a number as an option argument.
 *
 * Effect:
 *
 * Tests ICMP ECHO and ECHO_REPLY packet ID field values and returns a
 * "positive" detection result (i.e. passthrough) upon a value match.
 *
 * Comments:
 *
 * This plugin was developed to detect TFN distributed attacks.
 *
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>

#include "snort_types.h"
#include "detection/treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "fpdetect.h"
#include "framework/ips_option.h"

static const char* s_name = "icmp_id";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats icmpIdPerfStats;

static PreprocStats* ii_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &icmpIdPerfStats;

    return nullptr;
}
#endif

typedef struct _IcmpIdCheckData
{
        u_short icmpid;

} IcmpIdCheckData;

class IcmpIdOption : public IpsOption
{
public:
    IcmpIdOption(const IcmpIdCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    IcmpIdCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpIdOption::hash() const
{
    uint32_t a,b,c;
    const IcmpIdCheckData *data = &config;

    a = data->icmpid;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IcmpIdOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcmpIdOption& rhs = (IcmpIdOption&)ips;
    IcmpIdCheckData *left = (IcmpIdCheckData*)&config;
    IcmpIdCheckData *right = (IcmpIdCheckData*)&rhs.config;

    if (left->icmpid == right->icmpid)
    {
        return true;
    }

    return false;
}

int IcmpIdOption::eval(Packet *p)
{
    IcmpIdCheckData *icmpId = &config;
    PROFILE_VARS;

    if(!p->icmph)
        return DETECTION_OPTION_NO_MATCH; /* if error occured while icmp header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(icmpIdPerfStats);

    if( (p->icmph->type == ICMP_ECHO || p->icmph->type == ICMP_ECHOREPLY)
        || (p->icmph->type == ICMP6_ECHO || p->icmph->type == ICMP6_REPLY)
      )
    {
        /* test the rule ID value against the ICMP extension ID field */
        if(icmpId->icmpid == p->icmph->s_icmp_id)
        {
            PREPROC_PROFILE_END(icmpIdPerfStats);
            return DETECTION_OPTION_MATCH;
        }
    }
    PREPROC_PROFILE_END(icmpIdPerfStats);
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void icmp_id_parse(char *data, IcmpIdCheckData *ds_ptr)
{
    char *endTok;

    /* advance past whitespace */
    while(isspace((int)*data)) data++;

    ds_ptr->icmpid = (uint16_t)SnortStrtoulRange(data, &endTok, 10, 0, UINT16_MAX);
    if ((endTok == data) || (*endTok != '\0'))
    {
        ParseError(
            "Invalid parameter '%s' to icmp_id.  Must be between "
            "0 & 65535, inclusive", data);
    }
    ds_ptr->icmpid = htons(ds_ptr->icmpid);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Set ICMP ID test value to %d\n", ds_ptr->icmpid););
}

static IpsOption* icmp_id_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IcmpIdCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    icmp_id_parse(data, &ds_ptr);
    return new IcmpIdOption(ds_ptr);
}

static void icmp_id_dtor(IpsOption* p)
{
    delete p;
}

static void icmp_id_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &icmpIdPerfStats, ii_get_profile);
#endif
}

static const IpsApi icmp_id_api =
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
    icmp_id_ginit,
    nullptr,
    nullptr,
    nullptr,
    icmp_id_ctor,
    icmp_id_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &icmp_id_api.base,
    nullptr
};
#else
const BaseApi* ips_icmp_id = &icmp_id_api.base;
#endif

