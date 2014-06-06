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

#include "snort_types.h"
#include "detection/treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "ack";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats tcpAckPerfStats;

static PreprocStats* ack_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &tcpAckPerfStats;

    return nullptr;
}
#endif

typedef struct _TcpAckCheckData
{
    u_long tcp_ack;
} TcpAckCheckData;

class TcpAckOption : public IpsOption
{
public:
    TcpAckOption(const TcpAckCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    TcpAckCheckData config;
};

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

uint32_t TcpAckOption::hash() const
{
    uint32_t a,b,c;
    const TcpAckCheckData *data = &config;

    a = data->tcp_ack;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TcpAckOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    TcpAckOption& rhs = (TcpAckOption&)ips;
    TcpAckCheckData *left = (TcpAckCheckData*)&config;
    TcpAckCheckData *right = (TcpAckCheckData*)&rhs.config;

    if (left->tcp_ack == right->tcp_ack)
    {
        return true;
    }

    return false;
}

int TcpAckOption::eval(Packet *p)
{
    TcpAckCheckData *ackCheckData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!p->tcph)
        return rval; /* if error appeared when tcp header was processed,
               * test fails automagically */
    PREPROC_PROFILE_START(tcpAckPerfStats);

    if(ackCheckData->tcp_ack == p->tcph->th_ack)
    {
        rval = DETECTION_OPTION_MATCH;
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpAckPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void ack_parse(char *data, TcpAckCheckData *ds_ptr)
{
    char **ep = NULL;

    ds_ptr->tcp_ack = strtoul(data, ep, 0);
    ds_ptr->tcp_ack = htonl(ds_ptr->tcp_ack);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Ack set to %lX\n", ds_ptr->tcp_ack););
}

static IpsOption* ack_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    TcpAckCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    ack_parse(data, &ds_ptr);

    return new TcpAckOption(ds_ptr);
}

static void ack_dtor(IpsOption* p)
{
    delete p;
}

static void ack_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &tcpAckPerfStats, ack_get_profile);
#endif
}

static const IpsApi ack_api =
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
    ack_ginit,
    nullptr,
    nullptr,
    nullptr,
    ack_ctor,
    ack_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ack_api.base,
    nullptr
};
#else
const BaseApi* ips_ack = &ack_api.base;
#endif

