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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "snort_types.h"
#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "util.h"
#include "snort_debug.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "seq";

#ifdef PERF_PROFILING
static THREAD_LOCAL ProfileStats tcpSeqPerfStats;

static ProfileStats* seq_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &tcpSeqPerfStats;

    return nullptr;
}
#endif

typedef struct _TcpSeqCheckData
{
    u_long tcp_seq;

} TcpSeqCheckData;

class TcpSeqOption : public IpsOption
{
public:
    TcpSeqOption(const TcpSeqCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    TcpSeqCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t TcpSeqOption::hash() const
{
    uint32_t a,b,c;
    const TcpSeqCheckData *data = &config;

    a = data->tcp_seq;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TcpSeqOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    TcpSeqOption& rhs = (TcpSeqOption&)ips;
    TcpSeqCheckData *left = (TcpSeqCheckData*)&config;
    TcpSeqCheckData *right = (TcpSeqCheckData*)&rhs.config;

    if (left->tcp_seq == right->tcp_seq)
    {
        return true;
    }

    return false;
}

int TcpSeqOption::eval(Cursor&, Packet *p)
{
    TcpSeqCheckData *tcpSeqCheckData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!p->tcph)
        return rval; /* if error appeared when tcp header was processed,
               * test fails automagically */

    PREPROC_PROFILE_START(tcpSeqPerfStats);

    if(tcpSeqCheckData->tcp_seq == p->tcph->th_seq)
    {
        rval = DETECTION_OPTION_MATCH;
    }
#ifdef DEBUG_MSGS
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpSeqPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void seq_parse(char *data, TcpSeqCheckData *ds_ptr)
{
    char **ep = NULL;

    ds_ptr->tcp_seq = strtoul(data, ep, 0);
    ds_ptr->tcp_seq = htonl(ds_ptr->tcp_seq);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Seq set to %lX\n", ds_ptr->tcp_seq););

}

static IpsOption* seq_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    TcpSeqCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    seq_parse(data, &ds_ptr);
    return new TcpSeqOption(ds_ptr);
}

static void seq_dtor(IpsOption* p)
{
    delete p;
}

static void seq_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, seq_get_profile);
#endif
}

static const IpsApi seq_api =
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
    seq_ginit,
    nullptr,
    nullptr,
    nullptr,
    seq_ctor,
    seq_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &seq_api.base,
    nullptr
};
#else
const BaseApi* ips_seq = &seq_api.base;
#endif

