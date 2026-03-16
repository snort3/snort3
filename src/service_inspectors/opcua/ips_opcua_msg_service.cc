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

// ips_opcua_msg_service.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include <unordered_map>

#include "opcua_session.h"

using namespace snort;

static const char* s_name = "opcua_msg_service";

//-------------------------------------------------------------------------
// msg_service lookup
//-------------------------------------------------------------------------

static const std::unordered_map<std::string, OpcuaMsgServiceType> opcua_msg_service_map =
{
    { "ServiceFault", OPCUA_MSG_SERVICE_SERVICE_FAULT },
    { "FindServersRequest", OPCUA_MSG_SERVICE_FIND_SERVERS_REQUEST },
    { "FindServersResponse", OPCUA_MSG_SERVICE_FIND_SERVERS_RESPONSE },
    { "GetEndpointsRequest", OPCUA_MSG_SERVICE_GET_ENDPOINTS_REQUEST },
    { "GetEndpointsResponse", OPCUA_MSG_SERVICE_GET_ENDPOINTS_RESPONSE },
    { "RegisterServerRequest", OPCUA_MSG_SERVICE_REGISTER_SERVER_REQUEST },
    { "RegisterServerResponse", OPCUA_MSG_SERVICE_REGISTER_SERVER_RESPONSE },
    { "OpenSecureChannelRequest", OPCUA_MSG_SERVICE_OPEN_SECURE_CHANNEL_REQUEST },
    { "OpenSecureChannelResponse", OPCUA_MSG_SERVICE_OPEN_SECURE_CHANNEL_RESPONSE },
    { "CloseSecureChannelRequest", OPCUA_MSG_SERVICE_CLOSE_SECURE_CHANNEL_REQUEST },
    { "CloseSecureChannelResponse", OPCUA_MSG_SERVICE_CLOSE_SECURE_CHANNEL_RESPONSE },
    { "CreateSessionRequest", OPCUA_MSG_SERVICE_CREATE_SESSION_REQUEST },
    { "CreateSessionResponse", OPCUA_MSG_SERVICE_CREATE_SESSION_RESPONSE },
    { "ActivateSessionRequest", OPCUA_MSG_SERVICE_ACTIVATE_SESSION_REQUEST },
    { "ActivateSessionResponse", OPCUA_MSG_SERVICE_ACTIVATE_SESSION_RESPONSE },
    { "CloseSessionRequest", OPCUA_MSG_SERVICE_CLOSE_SESSION_REQUEST },
    { "CloseSessionResponse", OPCUA_MSG_SERVICE_CLOSE_SESSION_RESPONSE },
    { "CancelRequest", OPCUA_MSG_SERVICE_CANCEL_REQUEST },
    { "CancelResponse", OPCUA_MSG_SERVICE_CANCEL_RESPONSE },
    { "AddNodesRequest", OPCUA_MSG_SERVICE_ADD_NODES_REQUEST },
    { "AddNodesResponse", OPCUA_MSG_SERVICE_ADD_NODES_RESPONSE },
    { "AddReferencesRequest", OPCUA_MSG_SERVICE_ADD_REFERENCES_REQUEST },
    { "AddReferencesResponse", OPCUA_MSG_SERVICE_ADD_REFERENCES_RESPONSE },
    { "DeleteNodesRequest", OPCUA_MSG_SERVICE_DELETE_NODES_REQUEST },
    { "DeleteNodesResponse", OPCUA_MSG_SERVICE_DELETE_NODES_RESPONSE },
    { "DeleteReferencesRequest", OPCUA_MSG_SERVICE_DELETE_REFERENCES_REQUEST },
    { "DeleteReferencesResponse", OPCUA_MSG_SERVICE_DELETE_REFERENCES_RESPONSE },
    { "BrowseRequest", OPCUA_MSG_SERVICE_BROWSE_REQUEST },
    { "BrowseResponse", OPCUA_MSG_SERVICE_BROWSE_RESPONSE },
    { "BrowseNextRequest", OPCUA_MSG_SERVICE_BROWSE_NEXT_REQUEST },
    { "BrowseNextResponse", OPCUA_MSG_SERVICE_BROWSE_NEXT_RESPONSE },
    { "TranslateBrowsePathsToNodeIdsRequest", OPCUA_MSG_SERVICE_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_REQUEST },
    { "TranslateBrowsePathsToNodeIdsResponse", OPCUA_MSG_SERVICE_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_RESPONSE },
    { "RegisterNodesRequest", OPCUA_MSG_SERVICE_REGISTER_NODES_REQUEST },
    { "RegisterNodesResponse", OPCUA_MSG_SERVICE_REGISTER_NODES_RESPONSE },
    { "UnregisterNodesRequest", OPCUA_MSG_SERVICE_UNREGISTER_NODES_REQUEST },
    { "UnregisterNodesResponse", OPCUA_MSG_SERVICE_UNREGISTER_NODES_RESPONSE },
    { "QueryFirstRequest", OPCUA_MSG_SERVICE_QUERY_FIRST_REQUEST },
    { "QueryFirstResponse", OPCUA_MSG_SERVICE_QUERY_FIRST_RESPONSE },
    { "QueryNextRequest", OPCUA_MSG_SERVICE_QUERY_NEXT_REQUEST },
    { "QueryNextResponse", OPCUA_MSG_SERVICE_QUERY_NEXT_RESPONSE },
    { "ReadRequest", OPCUA_MSG_SERVICE_READ_REQUEST },
    { "ReadResponse", OPCUA_MSG_SERVICE_READ_RESPONSE },
    { "HistoryReadRequest", OPCUA_MSG_SERVICE_HISTORY_READ_REQUEST },
    { "HistoryReadResponse", OPCUA_MSG_SERVICE_HISTORY_READ_RESPONSE },
    { "WriteRequest", OPCUA_MSG_SERVICE_WRITE_REQUEST },
    { "WriteResponse", OPCUA_MSG_SERVICE_WRITE_RESPONSE },
    { "HistoryUpdateRequest", OPCUA_MSG_SERVICE_HISTORY_UPDATE_REQUEST },
    { "HistoryUpdateResponse", OPCUA_MSG_SERVICE_HISTORY_UPDATE_RESPONSE },
    { "CallMethodRequest", OPCUA_MSG_SERVICE_CALL_METHOD_REQUEST },
    { "CallRequest", OPCUA_MSG_SERVICE_CALL_REQUEST },
    { "CallResponse", OPCUA_MSG_SERVICE_CALL_RESPONSE },
    { "MonitoredItemCreateRequest", OPCUA_MSG_SERVICE_MONITORED_ITEM_CREATE_REQUEST },
    { "CreateMonitoredItemsRequest", OPCUA_MSG_SERVICE_CREATE_MONITORED_ITEMS_REQUEST },
    { "CreateMonitoredItemsResponse", OPCUA_MSG_SERVICE_CREATE_MONITORED_ITEMS_RESPONSE },
    { "MonitoredItemModifyRequest", OPCUA_MSG_SERVICE_MONITORED_ITEM_MODIFY_REQUEST },
    { "ModifyMonitoredItemsRequest", OPCUA_MSG_SERVICE_MODIFY_MONITORED_ITEMS_REQUEST },
    { "ModifyMonitoredItemsResponse", OPCUA_MSG_SERVICE_MODIFY_MONITORED_ITEMS_RESPONSE },
    { "SetMonitoringModeRequest", OPCUA_MSG_SERVICE_SET_MONITORING_MODE_REQUEST },
    { "SetMonitoringModeResponse", OPCUA_MSG_SERVICE_SET_MONITORING_MODE_RESPONSE },
    { "SetTriggeringRequest", OPCUA_MSG_SERVICE_SET_TRIGGERING_REQUEST },
    { "SetTriggeringResponse", OPCUA_MSG_SERVICE_SET_TRIGGERING_RESPONSE },
    { "DeleteMonitoredItemsRequest", OPCUA_MSG_SERVICE_DELETE_MONITORED_ITEMS_REQUEST },
    { "DeleteMonitoredItemsResponse", OPCUA_MSG_SERVICE_DELETE_MONITORED_ITEMS_RESPONSE },
    { "CreateSubscriptionRequest", OPCUA_MSG_SERVICE_CREATE_SUBSCRIPTION_REQUEST },
    { "CreateSubscriptionResponse", OPCUA_MSG_SERVICE_CREATE_SUBSCRIPTION_RESPONSE },
    { "ModifySubscriptionRequest", OPCUA_MSG_SERVICE_MODIFY_SUBSCRIPTION_REQUEST },
    { "ModifySubscriptionResponse", OPCUA_MSG_SERVICE_MODIFY_SUBSCRIPTION_RESPONSE },
    { "SetPublishingModeRequest", OPCUA_MSG_SERVICE_SET_PUBLISHING_MODE_REQUEST },
    { "SetPublishingModeResponse", OPCUA_MSG_SERVICE_SET_PUBLISHING_MODE_RESPONSE },
    { "PublishRequest", OPCUA_MSG_SERVICE_PUBLISH_REQUEST },
    { "PublishResponse", OPCUA_MSG_SERVICE_PUBLISH_RESPONSE },
    { "RepublishRequest", OPCUA_MSG_SERVICE_REPUBLISH_REQUEST },
    { "RepublishResponse", OPCUA_MSG_SERVICE_REPUBLISH_RESPONSE },
    { "TransferSubscriptionsRequest", OPCUA_MSG_SERVICE_TRANSFER_SUBSCRIPTIONS_REQUEST },
    { "TransferSubscriptionsResponse", OPCUA_MSG_SERVICE_TRANSFER_SUBSCRIPTIONS_RESPONSE },
    { "DeleteSubscriptionsRequest", OPCUA_MSG_SERVICE_DELETE_SUBSCRIPTIONS_REQUEST },
    { "DeleteSubscriptionsResponse", OPCUA_MSG_SERVICE_DELETE_SUBSCRIPTIONS_RESPONSE },
    { "FindServersOnNetworkRequest", OPCUA_MSG_SERVICE_FIND_SERVERS_ON_NETWORK_REQUEST },
    { "FindServersOnNetworkResponse", OPCUA_MSG_SERVICE_FIND_SERVERS_ON_NETWORK_RESPONSE },
    { "RegisterServer2Request", OPCUA_MSG_SERVICE_REGISTER_SERVER2_REQUEST },
    { "RegisterServer2Response", OPCUA_MSG_SERVICE_REGISTER_SERVER2_RESPONSE },
    { "SessionlessInvokeRequestType", OPCUA_MSG_SERVICE_SESSIONLESS_INVOKE_REQUEST_TYPE },
    { "SessionlessInvokeResponseType", OPCUA_MSG_SERVICE_SESSIONLESS_INVOKE_RESPONSE_TYPE },
};

static bool get_msg_service(std::string s, OpcuaMsgServiceType& t)
{
    auto it = opcua_msg_service_map.find(s);
    if (it != opcua_msg_service_map.end())
    {
        t = it->second;
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// msg_service option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats opcua_msg_service_prof;

class OpcuaMsgServiceOption: public IpsOption
{
public:
    OpcuaMsgServiceOption(OpcuaMsgServiceType v) :
        IpsOption(s_name)
    {
        msg_service = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    OpcuaMsgServiceType msg_service;
};

uint32_t OpcuaMsgServiceOption::hash() const
{
    uint32_t a = (uint32_t)msg_service, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool OpcuaMsgServiceOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const OpcuaMsgServiceOption& rhs = (const OpcuaMsgServiceOption&) ips;
    return (msg_service == rhs.msg_service);
}

IpsOption::EvalStatus OpcuaMsgServiceOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(opcua_msg_service_prof);

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

    // the concept of a msg_service only exists in the MSG pdu type
    if ( ssn_data->msg_type == OPCUA_MSG_MSG )
    {
        // this rule option only works on default service types, so the namespace index must be zero
        // custom combinations can use other rule options
        if ( ssn_data->node_namespace_index == OPCUA_DEFAULT_NAMESPACE_INDEX )
        {
            if ( msg_service == ssn_data->node_id )
            {
               return MATCH;
            }
        }
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "message service to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check the OPC UA message service"

class OpcuaMsgServiceModule: public Module
{
public:
    OpcuaMsgServiceModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &opcua_msg_service_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    OpcuaMsgServiceType msg_service = OPCUA_MSG_SERVICE_UNDEFINED;
};

bool OpcuaMsgServiceModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    OpcuaMsgServiceType t;

    if ( get_msg_service(v.get_string(), t) )
    {
        msg_service = t;
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new OpcuaMsgServiceModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    const OpcuaMsgServiceModule* mod = (const OpcuaMsgServiceModule*) m;
    return new OpcuaMsgServiceOption(mod->msg_service);
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
        PLUGIN_SO_RELOAD,
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

const BaseApi* ips_opcua_msg_service = &ips_api.base;

