//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// stream_ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_ha.h"

#include <unordered_map>

#include "flow/flow_key.h"
#include "managers/inspector_manager.h"
#include "stream/stream.h"

using namespace snort;

// HA Session flags helper macros
#define HA_IGNORED_SESSION_FLAGS \
    (SSNFLAG_COUNTED_INITIALIZE | SSNFLAG_COUNTED_ESTABLISH | SSNFLAG_COUNTED_CLOSING)
#define HA_CRITICAL_SESSION_FLAGS \
    (SSNFLAG_DROP_CLIENT | SSNFLAG_DROP_SERVER | SSNFLAG_RESET)
#define HA_TCP_MAJOR_SESSION_FLAGS \
    (SSNFLAG_ESTABLISHED)

typedef std::unordered_map<int,ProtocolHA*> ProtocolMap;
static THREAD_LOCAL ProtocolMap* proto_map = nullptr;

static ProtocolHA* get_protocol_ha(PktType pkt_type)
{
    assert( proto_map );

    auto search = proto_map->find((int)pkt_type);
    if( search == proto_map->end() )
        return nullptr;

    return search->second;
}

static void protocol_deactivate_session(Flow* flow)
{
    ProtocolHA* protocol_ha = get_protocol_ha(flow->pkt_type);
    if ( protocol_ha )
        protocol_ha->deactivate_session(flow);
}

static Flow* protocol_create_session(FlowKey* key)
{
    ProtocolHA* protocol_ha = get_protocol_ha(key->pkt_type);
    return protocol_ha ?  protocol_ha->create_session(key) : nullptr;
}

static bool is_client_lower(Flow* flow)
{
    if (flow->client_ip.fast_lt6(flow->server_ip))
        return true;

    if (flow->server_ip.fast_lt6(flow->client_ip))
        return false;

    switch (flow->key->pkt_type)
    {
        case PktType::TCP:
        case PktType::UDP:
            if (flow->client_port < flow->server_port)
                return true;
            break;
        default:
            break;
    }
    return false;
}

bool StreamHAClient::consume(Flow*& flow, FlowKey* key, HAMessage* msg)
{
    assert(key);
    assert(msg);

    // Is the message long enough to have our content?
    if ( ((unsigned)(msg->content_length()) - (unsigned)(msg->cursor - msg->content())) <
        sizeof(SessionHAContent) )
        return false;

    SessionHAContent* hac = (SessionHAContent*)msg->cursor;
    msg->cursor += sizeof(SessionHAContent);

    // If flow is missing, we need to create a new one.
    if ( flow == nullptr )
    {
        // A nullptr indicates that the protocol has no handler
        if ( (flow = protocol_create_session(key)) == nullptr )
            return false;

        BareDataEvent event;
        DataBus::publish(STREAM_HA_NEW_FLOW_EVENT, event, flow);

        flow->ha_state->clear(FlowHAState::NEW);
        int family = (hac->flags & SessionHAContent::FLAG_IP6) ? AF_INET6 : AF_INET;
        if ( hac->flags & SessionHAContent::FLAG_LOW )
        {
            flow->server_ip.set(flow->key->ip_l, family);
            flow->client_ip.set(flow->key->ip_h, family);
            flow->server_port = flow->key->port_l;
            flow->client_port = flow->key->port_h;
        }
        else
        {
            flow->client_ip.set(flow->key->ip_l, family);
            flow->server_ip.set(flow->key->ip_h, family);
            flow->client_port = flow->key->port_l;
            flow->server_port = flow->key->port_h;
        }
    }

    flow->ssn_state = hac->ssn_state;
    flow->flow_state = hac->flow_state;

    if ( !flow->ha_state->check_any(FlowHAState::STANDBY) )
    {
        protocol_deactivate_session(flow);
        flow->ha_state->add(FlowHAState::STANDBY);
    }

    return true;
}

bool StreamHAClient::produce(Flow* flow, HAMessage* msg)
{
    assert(flow);
    assert(msg);

    // Check for buffer overflows
    if ( (int)(msg->cursor - msg->content()) <= (int)(msg->content_length() -
        sizeof(SessionHAContent)) )
    {
        SessionHAContent* hac = (SessionHAContent*)msg->cursor;

        memcpy(&(hac->ssn_state),&(flow->ssn_state),sizeof(LwState));
        hac->flow_state = flow->flow_state;
        hac->flags = 0;
        msg->cursor += sizeof(SessionHAContent);

        if ( !is_client_lower(flow) )
            hac->flags |= SessionHAContent::FLAG_LOW;

        hac->flags |= SessionHAContent::FLAG_IP6;
        return true;
    }
    else
        return false;
}

static void update_flags(Flow* flow)
{
    /* Session creation for non-TCP sessions is a major change.  TCP sessions
     * hold off until they are established. */
    if (flow->ha_state->check_any(FlowHAState::NEW_SESSION))
    {
        flow->ha_state->clear(FlowHAState::NEW_SESSION);
        flow->ha_state->add(FlowHAState::MODIFIED);
        if (flow->key->pkt_type != PktType::TCP)
            flow->ha_state->add(FlowHAState::MAJOR);
    }
    else
    {
        LwState* old_state = &(flow->previous_ssn_state);
        LwState* cur_state = &(flow->ssn_state);
        uint32_t session_diff =
            ( old_state->session_flags ^ cur_state->session_flags ) &
            ~HA_IGNORED_SESSION_FLAGS;

        if( session_diff )
        {
            flow->ha_state->add(FlowHAState::MODIFIED);
            if( flow->key->pkt_type == PktType::TCP &&
                ( session_diff & HA_TCP_MAJOR_SESSION_FLAGS ) )
                flow->ha_state->add(FlowHAState::MAJOR);
            if( session_diff & HA_CRITICAL_SESSION_FLAGS )
                flow->ha_state->add(FlowHAState::CRITICAL);
        }

        if( old_state->ignore_direction != cur_state->ignore_direction )
        {
            flow->ha_state->add(FlowHAState::MODIFIED);
            /* If we have started ignoring both directions, that means we'll probably
            * try to whitelist the session.  This is a critical change since we
            * probably won't see another packet on the session if we're using
            * a DAQ module that fully supports the WHITELIST verdict. */
            if( cur_state->ignore_direction == SSN_DIR_BOTH )
                flow->ha_state->add(FlowHAState::CRITICAL);
        }

        if( ( old_state->ipprotocol != cur_state->ipprotocol ) ||
            ( old_state->snort_protocol_id != cur_state->snort_protocol_id ) ||
            ( old_state->direction != cur_state->direction ) )
        {
            flow->ha_state->add(FlowHAState::MODIFIED);
        }

    }

    /*  Receiving traffic on a session that's in standby is a major change. */
    if (flow->ha_state->check_any(FlowHAState::STANDBY))
    {
        flow->ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
        flow->ha_state->clear(FlowHAState::STANDBY);
    }
}

bool StreamHAClient::is_update_required(Flow* flow)
{
    assert(flow);
    assert(flow->ha_state);

    update_flags(flow);

    if ( !flow->ha_state->check_any(FlowHAState::MODIFIED) )
        return false;

    // We are only sending MAJOR and CRITICAL updates
    if ( !flow->ha_state->check_any(FlowHAState::MAJOR | FlowHAState::CRITICAL) )
        return false;

    /* Ensure that a new flow has lived long enough for anyone to care about it
        and that we're not overrunning the synchronization threshold. */
    if ( flow->ha_state->sync_interval_elapsed() )
        return true;
    else
        return flow->ha_state->check_any(FlowHAState::CRITICAL);
}

bool StreamHAClient::is_delete_required(Flow*)
{
    return true;
}

ProtocolHA::ProtocolHA(PktType protocol)
{
    if ( proto_map == nullptr )
        proto_map = new ProtocolMap;

    proto_map->insert(std::make_pair((int)protocol, this));
}

ProtocolHA::~ProtocolHA()
{
    assert( proto_map );

    for( auto map : *proto_map )
    {
        if ( map.second == this )
        {
            proto_map->erase(map.first);
            break;
        }
    }

    if ( proto_map->empty() )
    {
        delete proto_map;
    }
}

void ProtocolHA::process_deletion(Flow* flow)
{
    HighAvailabilityManager::process_deletion(flow);
}

THREAD_LOCAL StreamHAClient* StreamHAManager::ha_client = nullptr;

void StreamHAManager::tinit()
{
    if ( HighAvailabilityManager::active() )
        ha_client = new StreamHAClient();
}

void StreamHAManager::tterm()
{
    if ( ha_client )
        delete ha_client;
}
