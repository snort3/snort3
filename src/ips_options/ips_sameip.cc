/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2001 Phil Wood <cpw@lanl.gov>
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

#include <sys/types.h>
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
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "sameip";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats sameIpPerfStats;

static PreprocStats* si_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &sameIpPerfStats;

    return nullptr;
}
#endif

class SameIpOption : public IpsOption
{
public:
    SameIpOption() : IpsOption(s_name) { };

    int eval(Packet*);
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

int SameIpOption::eval(Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
        return rval; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(sameIpPerfStats);

    if (IP_EQUALITY( GET_SRC_IP(p), GET_DST_IP(p)))
    {
	    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Match!  %x ->",
                    sfip_ntoa(GET_SRC_IP(p)));
               DebugMessage(DEBUG_PLUGIN, " %x\n",
                    sfip_ntoa(GET_DST_IP(p))));
        rval = DETECTION_OPTION_MATCH;
    }
    else
    {
    	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match!  %x ->",
                    sfip_ntoa(GET_SRC_IP(p)));
               DebugMessage(DEBUG_PLUGIN, " %x\n",
                    sfip_ntoa(GET_DST_IP(p))));
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(sameIpPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static IpsOption* sameip_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if ( data )
        ParseError("sameip takes no options");

    return new SameIpOption;
}

static void sameip_dtor(IpsOption* p)
{
    delete p;
}

static void sameip_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &sameIpPerfStats, si_get_profile);
#endif
}

static const IpsApi sameip_api =
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
    sameip_ginit,
    nullptr,
    nullptr,
    nullptr,
    sameip_ctor,
    sameip_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sameip_api.base,
    nullptr
};
#else
const BaseApi* ips_sameip = &sameip_api.base;
#endif

