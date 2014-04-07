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

/* sp_icmp_seq_check
 *
 * Purpose:
 *
 * Test the Sequence number field of ICMP ECHO and ECHO_REPLY packets for
 * specified values.  This is useful for detecting TFN attacks, amongst others.
 *
 * Arguments:
 *
 * The ICMP Seq plugin takes a number as an option argument.
 *
 * Effect:
 *
 * Tests ICMP ECHO and ECHO_REPLY packet Seq field values and returns a
 * "positive" detection result (i.e. passthrough) upon a value match.
 *
 * Comments:
 *
 * This plugin was developed to detect TFN distributed attacks.
 *
 */

#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <ctype.h>

#include "snort_types.h"
#include "detection/treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "detection/fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "icmp_seq";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats icmpSeqPerfStats;

static PreprocStats* is_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &icmpSeqPerfStats;

    return nullptr;
}
#endif

typedef struct _IcmpSeqCheckData
{
    unsigned short icmpseq;

} IcmpSeqCheckData;

class IcmpSeqOption : public IpsOption
{
public:
    IcmpSeqOption(const IcmpSeqCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    IcmpSeqCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IcmpSeqOption::hash() const
{
    uint32_t a,b,c;
    const IcmpSeqCheckData *data = &config;

    a = data->icmpseq;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IcmpSeqOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcmpSeqOption& rhs = (IcmpSeqOption&)ips;
    IcmpSeqCheckData *left = (IcmpSeqCheckData*)&config;
    IcmpSeqCheckData *right = (IcmpSeqCheckData*)&rhs.config;

    if (left->icmpseq == right->icmpseq)
    {
        return true;
    }

    return false;
}

int IcmpSeqOption::eval(Packet *p)
{
    IcmpSeqCheckData *icmpSeq = &config;
    PROFILE_VARS;

    if(!p->icmph)
        return DETECTION_OPTION_NO_MATCH; /* if error occured while icmp header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(icmpSeqPerfStats);

    if( (p->icmph->type == ICMP_ECHO || p->icmph->type == ICMP_ECHOREPLY)
        || (p->icmph->type == ICMP6_ECHO || p->icmph->type == ICMP6_REPLY)
      )
    {
        /* test the rule ID value against the ICMP extension ID field */
        if(icmpSeq->icmpseq == p->icmph->s_icmp_seq)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "ICMP ID check success\n"););
            PREPROC_PROFILE_END(icmpSeqPerfStats);
            return DETECTION_OPTION_MATCH;
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "ICMP ID check failed\n"););
        }
    }
    PREPROC_PROFILE_END(icmpSeqPerfStats);
    return DETECTION_OPTION_NO_MATCH;
}
//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void icmp_seq_parse(char *data, IcmpSeqCheckData *ds_ptr)
{
    char *endTok;

    while(isspace((int)*data)) data++;

    ds_ptr->icmpseq = (uint16_t)SnortStrtoulRange(data, &endTok, 10, 0, UINT16_MAX);
    if ((endTok == data) || (*endTok != '\0'))
    {
        ParseError("Invalid parameter '%s' to icmp_seq.  "
                   "Must be between 0 & 65535, inclusive", data);
    }
    ds_ptr->icmpseq = htons(ds_ptr->icmpseq);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set ICMP Seq test value to %d\n", ds_ptr->icmpseq););
}

static IpsOption* icmp_seq_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IcmpSeqCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    icmp_seq_parse(data, &ds_ptr);
    return new IcmpSeqOption(ds_ptr);
}

static void icmp_seq_dtor(IpsOption* p)
{
    delete p;
}

static void icmp_seq_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &icmpSeqPerfStats, is_get_profile);
#endif
}

static const IpsApi icmp_seq_api =
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
    icmp_seq_ginit,
    nullptr,
    nullptr,
    nullptr,
    icmp_seq_ctor,
    icmp_seq_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &icmp_seq_api.base,
    nullptr
};
#else
const BaseApi* ips_icmp_seq = &icmp_seq_api.base;
#endif

