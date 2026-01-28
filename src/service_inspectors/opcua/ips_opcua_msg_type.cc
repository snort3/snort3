//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// ips_opcua_msg_type.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "opcua_session.h"

using namespace snort;

static const char* s_name = "opcua_msg_type";

//-------------------------------------------------------------------------
// msg_type lookup
//-------------------------------------------------------------------------

struct OpcuaMsgTypeMap
{
    const char* name;
    OpcuaMsgType type;
};

static OpcuaMsgTypeMap opcua_msg_type_map[] =
{
    { "hel" ,OPCUA_MSG_HEL },
    { "HEL" ,OPCUA_MSG_HEL },
    { "hello" ,OPCUA_MSG_HEL },
    { "ack" ,OPCUA_MSG_ACK },
    { "ACK" ,OPCUA_MSG_ACK },
    { "acknowledge" ,OPCUA_MSG_ACK },
    { "err" ,OPCUA_MSG_ERR },
    { "ERR" ,OPCUA_MSG_ERR },
    { "error" ,OPCUA_MSG_ERR },
    { "rhe" ,OPCUA_MSG_RHE },
    { "RHE" ,OPCUA_MSG_RHE },
    { "reverse_hello" ,OPCUA_MSG_RHE },
    { "opn" ,OPCUA_MSG_OPN },
    { "OPN" ,OPCUA_MSG_OPN },
    { "open_secure_channel" ,OPCUA_MSG_OPN },
    { "msg" ,OPCUA_MSG_MSG },
    { "MSG" ,OPCUA_MSG_MSG },
    { "message" ,OPCUA_MSG_MSG },
    { "clo" ,OPCUA_MSG_CLO },
    { "CLO" ,OPCUA_MSG_CLO },
    { "close_secure_channel" ,OPCUA_MSG_CLO },
};

static bool get_msg_type(const char* s, OpcuaMsgType& t)
{
    constexpr size_t max = (sizeof(opcua_msg_type_map) / sizeof(OpcuaMsgTypeMap));

    for (size_t i = 0; i < max; ++i)
    {
        if (strcmp(s, opcua_msg_type_map[i].name) == 0)
        {
            t = opcua_msg_type_map[i].type;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// msg_type option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats opcua_msg_type_prof;

class OpcuaMsgTypeOption: public IpsOption
{
public:
    OpcuaMsgTypeOption(OpcuaMsgType v) :
        IpsOption(s_name)
    {
        msg_type = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    OpcuaMsgType msg_type;
};

uint32_t OpcuaMsgTypeOption::hash() const
{
    uint32_t a = (uint32_t)msg_type, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool OpcuaMsgTypeOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const OpcuaMsgTypeOption& rhs = (const OpcuaMsgTypeOption&) ips;
    return (msg_type == rhs.msg_type);
}

IpsOption::EvalStatus OpcuaMsgTypeOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(opcua_msg_type_prof);

    if ( !p->flow || !p->is_full_pdu() )
    {
        return NO_MATCH;
    }

    OpcuaFlowData* opcuafd = (OpcuaFlowData*) p->flow->get_flow_data(OpcuaFlowData::inspector_id);
    if ( !opcuafd )
    {
        return NO_MATCH;
    }

    OpcuaPacketDataDirectionType direction;
    if ( p->is_from_client() )
    {
        direction = OPCUA_PACKET_DATA_DIRECTION_CLIENT;
    }
    else if ( p->is_from_server() )
    {
        direction = OPCUA_PACKET_DATA_DIRECTION_SERVER;
    }
    else
    {
        return NO_MATCH;
    }

    const OpcuaSessionData* ssn_data = opcuafd->get_ssn_data_by_direction(direction);
    if ( ssn_data == nullptr )
    {
        return NO_MATCH;
    }

    if ( ssn_data->msg_type == msg_type )
    {
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "message type to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check the OPC UA message type"

class OpcuaMsgTypeModule: public Module
{
public:
    OpcuaMsgTypeModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &opcua_msg_type_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    OpcuaMsgType msg_type = OPCUA_MSG_UNDEFINED;
};

bool OpcuaMsgTypeModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    OpcuaMsgType t;

    if ( get_msg_type(v.get_string(), t) )
    {
        msg_type = t;
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new OpcuaMsgTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    const OpcuaMsgTypeModule* mod = (const OpcuaMsgTypeModule*) m;
    return new OpcuaMsgTypeOption(mod->msg_type);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
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
    0,
    PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_opcua_msg_type = &ips_api.base;

