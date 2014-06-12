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

// ips_urg.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "main/snort_types.h"
#include "main/thread.h"
#include "detection/detection_defines.h"
#include "detection/treenodes.h"
#include "framework/ips_option.h"
#include "hash/sfhashfcn.h"
#include "protocols/packet.h"
#include "time/profiler.h"

static const char* s_name = "urg";

// FIXIT profiling is desirable but must be refactored to
// avoid dependence on snort_config.h which snowballs
#undef PERF_PROFILING

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats tcpUrgPerfStats;

static PreprocStats* urg_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &tcpUrgPerfStats;

    return nullptr;
}
#endif

class TcpUrgOption : public IpsOption
{
public:
    TcpUrgOption(uint16_t up) : IpsOption(s_name)
    { urg_ptr = htons(up); };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    uint16_t urg_ptr;
};

//-------------------------------------------------------------------------
// option methods
//-------------------------------------------------------------------------

uint32_t TcpUrgOption::hash() const
{
    uint32_t a = urg_ptr, b = 0, c = 0;
    mix_str(a,b,c,get_name());
    final(a,b,c);
    return c;
}

bool TcpUrgOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    TcpUrgOption& rhs = (TcpUrgOption&)ips;

    if ( urg_ptr == rhs.urg_ptr)
    {
        return true;
    }

    return false;
}

int TcpUrgOption::eval(Packet *p)
{
    //PROFILE_VARS;
    //PREPROC_PROFILE_START(tcpUrgPerfStats);
    int result = DETECTION_OPTION_NO_MATCH;

    if ( !p->tcph )
        return result;

    if ( (p->tcph->th_flags & 0x20) &&
         (urg_ptr == p->tcph->th_urp) )
    {
        result = DETECTION_OPTION_MATCH;
    }

    //PREPROC_PROFILE_END(tcpUrgPerfStats);
    return result;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static IpsOption* urg_ctor(
    SnortConfig*, char* arg, OptTreeNode*)
{
    char* end;
    long up = strtol(arg, &end, 0);

    if ( !*arg || *end || up < 0 || up > 0xFFFF )
        up = 0;

    return new TcpUrgOption((uint16_t)up);
}

static void urg_dtor(IpsOption* p)
{
    delete p;
}

static void urg_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        s_name, &tcpUrgPerfStats, 3, &ruleOTNEvalPerfStats, urg_get_profile);
#endif
}

static const IpsApi urg_api =
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
    1, PROTO_BIT__TCP,
    urg_ginit,
    nullptr,
    nullptr,
    nullptr,
    urg_ctor,
    urg_dtor,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &urg_api.base,
    nullptr
};

