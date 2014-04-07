/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2002-2013 Sourcefire, Inc.
 ** Author: Martin Roesch
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
#include <string.h>
#include <ctype.h>

#include "snort_types.h"
#include "detection/treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "sfhashfcn.h"
#include "stream5/stream_api.h"
#include "fpdetect.h"
#include "snort.h"
#include "profiler.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"

static const char* s_name = "flow";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats flowCheckPerfStats;

static PreprocStats* fc_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &flowCheckPerfStats;

    return nullptr;
}
#endif

#define ONLY_STREAM   0x01
#define ONLY_FRAG     0x02
#define IGNORE_STREAM 0x01
#define IGNORE_FRAG   0x02

struct FlowCheckData
{
    uint8_t from_server;
    uint8_t from_client;
    uint8_t ignore_reassembled;
    uint8_t only_reassembled;
    uint8_t stateless;
    uint8_t established;
    uint8_t unestablished;
};        

class FlowCheckOption : public IpsOption
{
public:
    FlowCheckOption(const FlowCheckData& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_FLOW)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

private:
    FlowCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t FlowCheckOption::hash() const
{
    uint32_t a,b,c;
    const FlowCheckData *data = &config;

    a = data->from_server || data->from_client << 16;
    b = data->ignore_reassembled || data->only_reassembled << 16;
    c = data->stateless || data->established << 16;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    a += data->unestablished;
    final(a,b,c);

    return c;
}

bool FlowCheckOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FlowCheckOption& rhs = (FlowCheckOption&)ips;
    FlowCheckData *left = (FlowCheckData *)&config;
    FlowCheckData *right = (FlowCheckData *)&rhs.config;

    if (( left->from_server == right->from_server) &&
        ( left->from_client == right->from_client) &&
        ( left->ignore_reassembled == right->ignore_reassembled) &&
        ( left->only_reassembled == right->only_reassembled) &&
        ( left->stateless == right->stateless) &&
        ( left->established == right->established) &&
        ( left->unestablished == right->unestablished))
    {
        return true;
    }

    return false;
}

int FlowCheckOption::eval(Packet *p)
{
    FlowCheckData *fcd = &config;
    PROFILE_VARS;

    PREPROC_PROFILE_START(flowCheckPerfStats);

    /* Check established/unestablished first */
    if (ScStateful())
    {
        if ((fcd->established == 1) && !(p->packet_flags & PKT_STREAM_EST))
        {
            /*
            ** This option requires an established connection and it isn't
            ** in that state yet, so no match.
            */
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
        else if ((fcd->unestablished == 1) && (p->packet_flags & PKT_STREAM_EST))
        {
            /*
            **  We're looking for an unestablished stream, and this is
            **  established, so don't continue processing.
            */
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    /* Now check from client */
    if (fcd->from_client)
    {
        if (ScStateful())
        {
            if (!(p->packet_flags & PKT_FROM_CLIENT) &&
                (p->packet_flags & PKT_FROM_SERVER))
            {
                /* No match on from_client */
                PREPROC_PROFILE_END(flowCheckPerfStats);
                return DETECTION_OPTION_NO_MATCH;
            }
        }
    }

    /* And from server */
    if (fcd->from_server)
    {
        if (ScStateful())
        {
            if (!(p->packet_flags & PKT_FROM_SERVER) &&
                (p->packet_flags & PKT_FROM_CLIENT))
            {
                /* No match on from_server */
                PREPROC_PROFILE_END(flowCheckPerfStats);
                return DETECTION_OPTION_NO_MATCH;
            }
        }
    }

    /* ...ignore_reassembled */
    if (fcd->ignore_reassembled & IGNORE_STREAM)
    {
        if (p->packet_flags & PKT_REBUILT_STREAM)
        {
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    if (fcd->ignore_reassembled & IGNORE_FRAG)
    {
        if (p->packet_flags & PKT_REBUILT_FRAG)
        {
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    /* ...only_reassembled */
    if (fcd->only_reassembled & ONLY_STREAM)
    {
        if ( !(p->packet_flags & PKT_REBUILT_STREAM)
            && !PacketHasFullPDU(p)
        ) {
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    if (fcd->only_reassembled & ONLY_FRAG)
    {
        if (!(p->packet_flags & PKT_REBUILT_FRAG))
        {
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    PREPROC_PROFILE_END(flowCheckPerfStats);
    return DETECTION_OPTION_MATCH;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

int OtnFlowFromServer( OptTreeNode * otn )
{
    FlowCheckData* fcd =
        (FlowCheckData*)get_rule_type_data(otn, RULE_OPTION_TYPE_FLOW);

    if(fcd )
    {
        if( fcd->from_server ) return 1;
    }
    return 0;
}
int OtnFlowFromClient( OptTreeNode * otn )
{
    FlowCheckData* fcd =
        (FlowCheckData*)get_rule_type_data(otn, RULE_OPTION_TYPE_FLOW);

    if(fcd )
    {
        if( fcd->from_client ) return 1;
    }
    return 0;
}
int OtnFlowIgnoreReassembled( OptTreeNode * otn )
{
    FlowCheckData* fcd =
        (FlowCheckData*)get_rule_type_data(otn, RULE_OPTION_TYPE_FLOW);

    if( fcd )
    {
        if( fcd->ignore_reassembled ) return 1;
    }
    return 0;
}
int OtnFlowOnlyReassembled( OptTreeNode * otn )
{
    FlowCheckData* fcd =
        (FlowCheckData*)get_rule_type_data(otn, RULE_OPTION_TYPE_FLOW);

    if( fcd )
    {
        if( fcd->only_reassembled ) return 1;
    }
    return 0;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void flow_parse(char *data, FlowCheckData* fcd, OptTreeNode *otn)
{
    char *token, *str, *p;

    str = SnortStrdup(data);

    p = str;

    /* nuke leading whitespace */
    while(isspace((int)*p)) p++;

    char* lasts = nullptr;
    token = strtok_r(p, ",", &lasts);

    while(token)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                    "parsed %s,(%d)\n", token,strlen(token)););

        while(isspace((int)*token))
            token++;

        if(!strcasecmp(token, "to_server"))
        {
            fcd->from_client = 1;
        }
        else if(!strcasecmp(token, "to_client"))
        {
            fcd->from_server = 1;
        }
        else if(!strcasecmp(token, "from_server"))
        {
            fcd->from_server = 1;
        }
        else if(!strcasecmp(token, "from_client"))
        {
            fcd->from_client = 1;
        }
        else if(!strcasecmp(token, "stateless"))
        {
            fcd->stateless = 1;
            otn->stateless = 1;
        }
        else if(!strcasecmp(token, "established"))
        {
            fcd->established = 1;
            otn->established = 1;
        }
        else if(!strcasecmp(token, "not_established"))
        {
            fcd->unestablished = 1;
            otn->unestablished = 1;
        }
        else if(!strcasecmp(token, "no_stream"))
        {
            fcd->ignore_reassembled |= IGNORE_STREAM;
        }
        else if(!strcasecmp(token, "only_stream"))
        {
            fcd->only_reassembled |= ONLY_STREAM;
        }
        else if(!strcasecmp(token, "no_frag"))
        {
            fcd->ignore_reassembled |= IGNORE_FRAG;
        }
        else if(!strcasecmp(token, "only_frag"))
        {
            fcd->only_reassembled |= ONLY_FRAG;
        }
        else
        {
            ParseError("Unknown Flow Option: '%s'", token);

        }


        token = strtok_r(NULL, ",", &lasts);
    }
    free(str);

    if(fcd->from_client && fcd->from_server)
    {
        ParseError("Can't use both from_client and flow_from server");
    }

    if((fcd->ignore_reassembled & IGNORE_STREAM) && (fcd->only_reassembled & ONLY_STREAM))
    {
        ParseError("Can't use no_stream and only_stream");
    }

    if((fcd->ignore_reassembled & IGNORE_FRAG) && (fcd->only_reassembled & ONLY_FRAG))
    {
        ParseError("Can't use no_frag and only_frag");
    }

    if(otn->stateless && (fcd->from_client || fcd->from_server))
    {
        ParseError("Can't use flow: stateless option with other options");
    }

    if(otn->stateless && otn->established)
    {
        ParseError("Can't specify established and stateless "
                   "options in same rule");
    }

    if(otn->stateless && otn->unestablished)
    {
        ParseError("Can't specify unestablished and stateless "
                   "options in same rule");
    }

    if(otn->established && otn->unestablished)
    {
        ParseError("Can't specify unestablished and established "
                   "options in same rule");
    }
}

static IpsOption* flow_ctor(
    SnortConfig*, char *data, OptTreeNode *otn)
{
    FlowCheckData fcd;
    memset(&fcd, 0, sizeof(fcd));
    flow_parse(data, &fcd, otn);

    if (otn->proto == IPPROTO_ICMP)
    {
        if ((fcd.only_reassembled != ONLY_FRAG) && (fcd.ignore_reassembled != IGNORE_FRAG))
        {
            ParseError("Cannot check flow connection for ICMP traffic");
        }
    }
    return new FlowCheckOption(fcd);
}

static void flow_dtor(IpsOption* p)
{
    delete p;
}

static void flow_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &flowCheckPerfStats, fc_get_profile);
#endif
}

static const IpsApi flow_api =
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
    flow_ginit,
    nullptr,
    nullptr,
    nullptr,
    flow_ctor,
    flow_dtor,
    nullptr
};

const BaseApi* ips_flow = &flow_api.base;

