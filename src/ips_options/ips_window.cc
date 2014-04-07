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
#include <string.h>
#include <ctype.h>

#include "snort_types.h"
#include "treenodes.h"
#include "decode.h"
#include "parser.h"
#include "util.h"
#include "snort_debug.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "window";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats tcpWinPerfStats;

static PreprocStats* win_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &tcpWinPerfStats;

    return nullptr;
}
#endif

typedef struct _TcpWinCheckData
{
    uint16_t tcp_win;
    uint8_t not_flag;

} TcpWinCheckData;

class TcpWinOption : public IpsOption
{
public:
    TcpWinOption(const TcpWinCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    TcpWinCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t TcpWinOption::hash() const
{
    uint32_t a,b,c;
    const TcpWinCheckData *data = &config;

    a = data->tcp_win;
    b = data->not_flag;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TcpWinOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    TcpWinOption& rhs = (TcpWinOption&)ips;
    TcpWinCheckData *left = (TcpWinCheckData*)&config;
    TcpWinCheckData *right = (TcpWinCheckData*)&rhs.config;

    if ((left->tcp_win == right->tcp_win) &&
        (left->not_flag == right->not_flag))
    {
        return true;
    }

    return false;
}

int TcpWinOption::eval(Packet *p)
{
    TcpWinCheckData *tcpWinCheckData = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!p->tcph)
        return rval;

    PREPROC_PROFILE_START(tcpWinPerfStats);

    if((tcpWinCheckData->tcp_win == p->tcph->th_win) ^ (tcpWinCheckData->not_flag))
    {
        rval = DETECTION_OPTION_MATCH;
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpWinPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void window_parse(char *data, TcpWinCheckData* ds_ptr)
{
    int win_size = 0;
    char *endTok;
    char *start;

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }

    if(data[0] == '!')
    {
        ds_ptr->not_flag = 1;
        start = &data[1];
    }
    else
    {
        start = &data[0];
    }

    if(strchr(start, (int) 'x') == NULL && strchr(start, (int)'X') == NULL)
    {
        win_size = SnortStrtolRange(start, &endTok, 10, 0, UINT16_MAX);
        if ((endTok == start) || (*endTok != '\0'))
        {
            ParseError("Invalid parameter '%s' to 'window' (not a "
                    "number?) ", data);
        }
    }
    else
    {
        /* hex? */
        start = strchr(data,(int)'x');
        if(!start)
        {
            start = strchr(data,(int)'X');
        }
        if (start)
        {
            win_size = SnortStrtolRange(start+1, &endTok, 16, 0, UINT16_MAX);
        }
        if (!start || (endTok == start+1) || (*endTok != '\0'))
        {
            ParseError("=> Invalid parameter '%s' to 'window' (not a "
                    "number?) ", data);
        }
    }

    ds_ptr->tcp_win = htons((uint16_t)win_size);

#ifdef DEBUG_MSGS
    DebugMessage(DEBUG_PLUGIN,"TCP Window set to 0x%X\n", ds_ptr->tcp_win);
#endif
}

static IpsOption* window_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    TcpWinCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    window_parse(data, &ds_ptr);
    return new TcpWinOption(ds_ptr);
}

static void window_dtor(IpsOption* p)
{
    delete p;
}

static void window_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &tcpWinPerfStats, win_get_profile);
#endif
}

static const IpsApi window_api =
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
    window_ginit,
    nullptr,
    nullptr,
    nullptr,
    window_ctor,
    window_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &window_api.base,
    nullptr
};
#else
const BaseApi* ips_window = &window_api.base;
#endif

