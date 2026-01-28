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

// ips_opcua_node_namespace_index.cc author Jared Rittle <jared.rittle@cisco.com>

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

static const char* s_name = "opcua_node_namespace_index";

//-------------------------------------------------------------------------
// node_namespace_index option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats opcua_node_namespace_index_prof;

class OpcuaNodeNamespaceIndexOption: public IpsOption
{
public:
    OpcuaNodeNamespaceIndexOption(uint8_t v) :
        IpsOption(s_name)
    {
        node_namespace_index = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t node_namespace_index;
};

uint32_t OpcuaNodeNamespaceIndexOption::hash() const
{
    uint32_t a = (uint32_t) node_namespace_index, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool OpcuaNodeNamespaceIndexOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const OpcuaNodeNamespaceIndexOption& rhs = (const OpcuaNodeNamespaceIndexOption&) ips;
    return (node_namespace_index == rhs.node_namespace_index);
}

IpsOption::EvalStatus OpcuaNodeNamespaceIndexOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(opcua_node_namespace_index_prof);

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

    if ( ssn_data->msg_type == OPCUA_MSG_MSG && ssn_data->node_namespace_index == node_namespace_index )
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
      "message node namespace index to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check the OPC UA message node namespace index"

class OpcuaNodeNamespaceIndexModule: public Module
{
public:
    OpcuaNodeNamespaceIndexModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &opcua_node_namespace_index_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint8_t node_namespace_index = OPCUA_DEFAULT_NAMESPACE_INDEX;
};

bool OpcuaNodeNamespaceIndexModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    unsigned long n;
    if (v.strtoul(n))
    {
        node_namespace_index = static_cast<uint8_t>(n);
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new OpcuaNodeNamespaceIndexModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    const OpcuaNodeNamespaceIndexModule* mod = (const OpcuaNodeNamespaceIndexModule*) m;
    return new OpcuaNodeNamespaceIndexOption(mod->node_namespace_index);
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

const BaseApi* ips_opcua_node_namespace_index = &ips_api.base;

