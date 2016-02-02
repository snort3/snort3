//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/rpc.h>

#include "protocols/packet.h"
#include "parser/parser.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "hash/sfhashfcn.h"
#include "profiler/profiler.h"
#include "detection/treenodes.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

#define s_name "rpc"

static THREAD_LOCAL ProfileStats rpcCheckPerfStats;

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
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RpcCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t RpcOption::hash() const
{
    uint32_t a,b,c;
    const RpcCheckData* data = &config;

    a = data->program;
    b = data->vers;
    c = data->proc;

    mix(a,b,c);

    a += data->flags;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool RpcOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    RpcOption& rhs = (RpcOption&)ips;
    RpcCheckData* left = (RpcCheckData*)&config;
    RpcCheckData* right = (RpcCheckData*)&rhs.config;

    if ((left->program == right->program) &&
        (left->vers == right->vers) &&
        (left->proc == right->proc) &&
        (left->flags == right->flags))
    {
        return true;
    }

    return false;
}

int RpcOption::eval(Cursor&, Packet* p)
{
    Profile profile(rpcCheckPerfStats);

    RpcCheckData* ds_ptr = &config;

    if (!(p->is_tcp() || p->is_udp()))
        return DETECTION_OPTION_NO_MATCH;

    auto c = p->data;

    if ( p->is_tcp() )
    {
        /* offset to rpc_msg */
        c+=4;
        /* Fail if the packet is too short to match */
        if (p->dsize<28)
        {
            DebugMessage(DEBUG_IPS_OPTION, "RPC packet too small");
            return DETECTION_OPTION_NO_MATCH;
        }
    }
    else
    { /* must be UDP
         Fail if the packet is too short to match */
        if (p->dsize<24)
        {
            DebugMessage(DEBUG_IPS_OPTION, "RPC packet too small");
            return DETECTION_OPTION_NO_MATCH;
        }
    }

#ifdef DEBUG_MSGS
    DebugMessage(DEBUG_IPS_OPTION,"<---xid---> <---dir---> <---rpc--->"
        " <---prog--> <---vers--> <---proc-->\n");
    for (int i = 0; i < 24; i++)
    {
        DebugFormat(DEBUG_IPS_OPTION, "%02X ",c[i]);
    }

    DebugMessage(DEBUG_IPS_OPTION,"\n");
#endif

    /* Read xid */
    (void)IXDR_GET_LONG (c);

    /* Read direction : CALL or REPLY */
    enum msg_type direction = IXDR_GET_ENUM (c, enum msg_type);

    /* We only look at calls */
    if (direction != CALL)
    {
        DebugMessage(DEBUG_IPS_OPTION, "RPC packet not a call");
        return DETECTION_OPTION_NO_MATCH;
    }

    /* Read the RPC message version */
    u_long rpcvers = IXDR_GET_LONG (c);

    /* Fail if it is not right */
    if (rpcvers != RPC_MSG_VERSION)
    {
        DebugMessage(DEBUG_IPS_OPTION,"RPC msg version invalid");
        return DETECTION_OPTION_NO_MATCH;
    }

    /* Read the program number, version, and procedure */
    u_long prog = IXDR_GET_LONG (c);
    u_long vers = IXDR_GET_LONG (c);
    u_long proc = IXDR_GET_LONG (c);

    DebugFormat(DEBUG_IPS_OPTION,"RPC decoded to: %lu %lu %lu\n",
        prog,vers,proc);

    DebugFormat(DEBUG_IPS_OPTION, "RPC matching on: %d %d %d\n",
        ds_ptr->flags & RPC_CHECK_PROG,ds_ptr->flags & RPC_CHECK_VERS,
        ds_ptr->flags & RPC_CHECK_PROC);

    if (!(ds_ptr->flags & RPC_CHECK_PROG) ||
        ds_ptr->program == prog)
    {
        DebugMessage(DEBUG_IPS_OPTION,"RPC program matches");
        if (!(ds_ptr->flags & RPC_CHECK_VERS) ||
            ds_ptr->vers == vers)
        {
            DebugMessage(DEBUG_IPS_OPTION,"RPC version matches");
            if (!(ds_ptr->flags & RPC_CHECK_PROC) ||
                ds_ptr->proc == proc)
            {
                DebugMessage(DEBUG_IPS_OPTION,"RPC proc matches");
                DebugMessage(DEBUG_IPS_OPTION, "Yippee! Found one!");
                return DETECTION_OPTION_MATCH;
            }
        }
    }
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_IPS_OPTION,"RPC not equal\n");
    }

    /* if the test isn't successful, return 0 */
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~app", Parameter::PT_STRING, nullptr, nullptr,
      "application number" },

    { "~ver", Parameter::PT_STRING, nullptr, nullptr,
      "version number or * for any" },

    { "~proc", Parameter::PT_STRING, nullptr, nullptr,
      "procedure number or * for any" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check SUNRPC CALL parameters"

class RpcModule : public Module
{
public:
    RpcModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &rpcCheckPerfStats; }

    RpcCheckData data;
};

bool RpcModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool RpcModule::set(const char*, Value& v, SnortConfig*)
{
    char* end;

    if ( v.is("~app") )
    {
        data.program = strtoul(v.get_string(), &end, 0);
        data.flags |= RPC_CHECK_PROG;
    }
    else if ( v.is("~ver") )
    {
        data.vers = strtoul(v.get_string(), &end, 0);
        data.flags |= RPC_CHECK_VERS;
    }
    else if ( v.is("~proc") )
    {
        data.proc = strtoul(v.get_string(), &end, 0);
        data.flags |= RPC_CHECK_PROC;
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new RpcModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* rpc_ctor(Module* p, OptTreeNode*)
{
    RpcModule* m = (RpcModule*)p;
    return new RpcOption(m->data);
}

static void rpc_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi rpc_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP|PROTO_BIT__UDP,
    nullptr,
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

