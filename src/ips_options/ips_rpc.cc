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
#include <rpc/rpc.h>

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

static const char* s_name = "rpc";

#ifdef PERF_PROFILING
static THREAD_LOCAL ProfileStats rpcCheckPerfStats;

static ProfileStats* rpc_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &rpcCheckPerfStats;

    return nullptr;
}
#endif

// This is driven by 64-bit Solaris which doesn't define _LONG
#ifndef IXDR_GET_LONG
    #define IXDR_GET_LONG IXDR_GET_INT32
#endif

typedef struct _RpcCheckData
{
    u_long program; /* RPC program number */
    u_long vers; /* RPC program version */
    u_long proc; /* RPC procedure number */
    int flags; /* Which of the above fields have been specified */

} RpcCheckData;

#define RPC_CHECK_PROG 1
#define RPC_CHECK_VERS 2
#define RPC_CHECK_PROC 4

class RpcOption : public IpsOption
{
public:
    RpcOption(const RpcCheckData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    RpcCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t RpcOption::hash() const
{
    uint32_t a,b,c;
    const RpcCheckData *data = &config;

    a = data->program;
    b = data->vers;
    c = data->proc;

    mix(a,b,c);

    a += data->flags;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool RpcOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    RpcOption& rhs = (RpcOption&)ips;
    RpcCheckData *left = (RpcCheckData*)&config;
    RpcCheckData *right = (RpcCheckData*)&rhs.config;

    if ((left->program == right->program) &&
        (left->vers == right->vers) &&
        (left->proc == right->proc) &&
        (left->flags == right->flags))
    {
        return true;
    }

    return false;
}

int RpcOption::eval(Cursor&, Packet *p)
{
    RpcCheckData *ds_ptr = &config;
    unsigned char* c=(unsigned char*)p->data;
    u_long rpcvers, prog, vers, proc;
    enum msg_type direction;
    int rval = DETECTION_OPTION_NO_MATCH;
#ifdef DEBUG_MSGS
    int i;
#endif
    PROFILE_VARS;

    if(!p->iph_api || (IsTCP(p) && !p->tcph)
       || (IsUDP(p) && !p->udph))
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(rpcCheckPerfStats);

    if( IsTCP(p) )
    {
        /* offset to rpc_msg */
        c+=4;
        /* Fail if the packet is too short to match */
        if(p->dsize<28)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RPC packet too small"););
            PREPROC_PROFILE_END(rpcCheckPerfStats);
            return rval;
        }
    }
    else
    { /* must be UDP */
        /* Fail if the packet is too short to match */
        if(p->dsize<24)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RPC packet too small"););
            PREPROC_PROFILE_END(rpcCheckPerfStats);
            return rval;
        }
    }

#ifdef DEBUG_MSGS
    DebugMessage(DEBUG_PLUGIN,"<---xid---> <---dir---> <---rpc--->"
                              " <---prog--> <---vers--> <---proc-->\n");
    for(i=0; i<24; i++)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%02X ",c[i]););
    }
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"\n"););
#endif

    /* Read xid */
    (void)IXDR_GET_LONG (c);

    /* Read direction : CALL or REPLY */
    direction = IXDR_GET_ENUM (c, enum msg_type);

    /* We only look at calls */
    if(direction != CALL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RPC packet not a call"););
        PREPROC_PROFILE_END(rpcCheckPerfStats);
        return rval;
    }

    /* Read the RPC message version */
    rpcvers = IXDR_GET_LONG (c);

    /* Fail if it is not right */
    if(rpcvers != RPC_MSG_VERSION)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC msg version invalid"););
        PREPROC_PROFILE_END(rpcCheckPerfStats);
        return rval;
    }

    /* Read the program number, version, and procedure */
    prog = IXDR_GET_LONG (c);
    vers = IXDR_GET_LONG (c);
    proc = IXDR_GET_LONG (c);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC decoded to: %lu %lu %lu\n",
                            prog,vers,proc););

    DEBUG_WRAP(
           DebugMessage(DEBUG_PLUGIN, "RPC matching on: %d %d %d\n",
                ds_ptr->flags & RPC_CHECK_PROG,ds_ptr->flags & RPC_CHECK_VERS,
                ds_ptr->flags & RPC_CHECK_PROC););
    if(!(ds_ptr->flags & RPC_CHECK_PROG) ||
       ds_ptr->program == prog)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC program matches"););
        if(!(ds_ptr->flags & RPC_CHECK_VERS) ||
           ds_ptr->vers == vers)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC version matches"););
            if(!(ds_ptr->flags & RPC_CHECK_PROC) ||
               ds_ptr->proc == proc)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC proc matches"););
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Yippee! Found one!"););
                rval = DETECTION_OPTION_MATCH;
            }
        }
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(rpcCheckPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

void rpc_parse(char *data, RpcCheckData *ds_ptr)
{
    char *tmp = NULL;

    ds_ptr->flags=0;

    /* advance past whitespace */
    while(isspace((int)*data)) data++;

    if(*data != '*')
    {
        ds_ptr->program = strtoul(data,&tmp,0);
        ds_ptr->flags|=RPC_CHECK_PROG;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set RPC program to %lu\n", ds_ptr->program););
    }
    else
    {
        ParseError("Invalid applicaion number in rpc rule option");
        return;
    }

    if(*tmp == '\0') return;

    data=++tmp;
    if(*data != '*')
    {
        ds_ptr->vers = strtoul(data,&tmp,0);
        ds_ptr->flags|=RPC_CHECK_VERS;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set RPC vers to %lu\n", ds_ptr->vers););
    }
    else
    {
        tmp++;
    }
    if(*tmp == '\0') return;
    data=++tmp;
    if(*data != '*')
    {
        ds_ptr->proc = strtoul(data,&tmp,0);
        ds_ptr->flags|=RPC_CHECK_PROC;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Set RPC proc to %lu\n", ds_ptr->proc););
    }
}

static IpsOption* rpc_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    RpcCheckData ds_ptr;
    memset(&ds_ptr, 0, sizeof(ds_ptr));
    rpc_parse(data, &ds_ptr);
    return new RpcOption(ds_ptr);
}

static void rpc_dtor(IpsOption* p)
{
    delete p;
}

static void rpc_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, rpc_get_profile);
#endif
}

static const IpsApi rpc_api =
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
    1, PROTO_BIT__TCP|PROTO_BIT__UDP,
    rpc_ginit,
    nullptr,
    nullptr,
    nullptr,
    rpc_ctor,
    rpc_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &rpc_api.base,
    nullptr
};
#else
const BaseApi* ips_rpc = &rpc_api.base;
#endif

