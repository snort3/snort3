//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_rpc.cc author Al Lewis <allewi>@cisco.com
// based on work by Martin Roesch <roesch@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "rpc"

static THREAD_LOCAL ProfileStats rpcCheckPerfStats;

struct RpcCheckData
{
    uint32_t program;
    uint32_t version;
    uint32_t procedure;
    uint32_t flags; // which fields to check
};

#define RPC_CHECK_VERSION   0x1
#define RPC_CHECK_PROCEDURE 0x2

class RpcOption : public IpsOption
{
public:
    RpcOption(const RpcCheckData& c) : IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint32_t get_int(const uint8_t*&);
    bool check_rpc_call(const uint8_t*&);
    bool check_version(uint32_t);
    bool check_procedure(uint32_t);
    bool check_program (uint32_t);
    bool is_match(Packet*);
    bool is_valid(Packet*);

    static const uint32_t RPC_MSG_VERSION = 2;
    static const uint32_t CALL = 0;

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
    b = data->version;
    c = data->procedure;

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

    const RpcOption& rhs = (const RpcOption&)ips;
    const RpcCheckData* left = &config;
    const RpcCheckData* right = &rhs.config;

    if ((left->program == right->program) &&
        (left->version == right->version) &&
        (left->procedure == right->procedure) &&
        (left->flags == right->flags))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus RpcOption::eval(Cursor&, Packet* p)
{
    Profile profile(rpcCheckPerfStats);

    if ( !is_valid(p) )
        return NO_MATCH;

    if ( is_match(p) )
        return MATCH;

    return NO_MATCH;
}

// check if there is a detection match
bool RpcOption::is_match(Packet* p)
{
    const uint8_t* packet_data = p->data;

    if ( p->is_tcp() )
        packet_data += 4;  // skip unused frag header

    packet_data += 4;  // skip unused xid

    // read direction .. CALL or REPLY etc..
    uint32_t message_type =  get_int(packet_data);

    uint32_t version = get_int(packet_data);

    if ( version != RPC_MSG_VERSION )
        return false;

    if ( message_type == CALL )
        return check_rpc_call(packet_data);

    return false;
}

// get a 32-bit int from the current location and increment to next int position
uint32_t RpcOption::get_int(const uint8_t*& data)
{
    uint32_t value = extract_32bits(data);
    data += 4;
    return value;
}

// check if the packet type and size are valid
bool RpcOption::is_valid(Packet* p)
{
    if ( p->is_tcp() )
        return p->dsize >= 28;

    else if ( p->is_udp() )
        return p->dsize >= 24;

    return false;
}

// compare values in rpc call
bool RpcOption::check_rpc_call(const uint8_t*& packet_data)
{
    // get the program number
    uint32_t program = get_int(packet_data);

    if ( !check_program(program) )
        return false;

    // get the program version number
    uint32_t version = get_int(packet_data);

    if ( !check_version(version) )
        return false;

    // get the procedure number
    uint32_t procedure = get_int(packet_data);

    if ( !check_procedure(procedure) )
        return false;

    // if nothing fails, return a match
    return true;
}

bool RpcOption::check_program(uint32_t program)
{
    return config.program == program;
}

bool RpcOption::check_version(uint32_t version)
{
    if ( config.flags & RPC_CHECK_VERSION )
        return config.version == version;

    return true;
}

bool RpcOption::check_procedure(uint32_t procedure)
{
    if ( config.flags & RPC_CHECK_PROCEDURE )
        return config.procedure == procedure;

    return true;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~app", Parameter::PT_INT, nullptr, nullptr,
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

    bool set(Value&, uint32_t& field, int flag);

    Usage get_usage() const override
    { return DETECT; }

public:
    RpcCheckData data;
};

bool RpcModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool RpcModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~app") )
        data.program = (uint32_t)v.get_long();

    else if ( v.is("~ver") )
        return set(v, data.version, RPC_CHECK_VERSION);

    else if ( v.is("~proc") )
        return set(v, data.procedure, RPC_CHECK_PROCEDURE);

    else
        return false;

    return true;
}

bool RpcModule::set(Value& v, uint32_t& field, int flag)
{
    if ( flag and !strcmp(v.get_string(), "*") )
        return true;

    errno = 0;
    char* end = nullptr;
    int64_t num = (int64_t)strtol(v.get_string(), &end, 0);

    if ( *end or errno or num < 0 or num > 0xFFFFFFFF )
        return false;

    field = (uint32_t)num;
    data.flags |= flag;
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
#else
const BaseApi* ips_rpc[] =
#endif
{
    &rpc_api.base,
    nullptr
};

