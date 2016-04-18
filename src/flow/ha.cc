//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
// ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#include "ha.h"

#include <assert.h>
#include <functional>
#include <unordered_map>

#include "flow.h"
#include "flow_key.h"
#include "ha_module.h"
#include "main/snort_debug.h"
#include "packet_io/sfdaq.h"
#include "profiler/profiler.h"
#include "side_channel/side_channel.h"
#include "time/packet_time.h"

static const uint8_t ha_message_version = 3;

// define message size and content constants.
static const uint8_t key_size_ip6 = sizeof(FlowKey);
static const uint8_t key_size_ip4 = sizeof(FlowKey)-24;

static const uint8_t key_type_ip6 = 1;
static const uint8_t key_type_ip4 = 2;

typedef std::unordered_map<FlowHAClientHandle, FlowHAClient*> ClientMap;

THREAD_LOCAL SimpleStats ha_stats;
THREAD_LOCAL ProfileStats ha_perf_stats;

static THREAD_LOCAL HighAvailability* ha;
PortBitSet* HighAvailabilityManager::ports = nullptr;
bool HighAvailabilityManager::use_daq_channel = false;
struct timeval FlowHAState::min_session_lifetime;
uint8_t FlowHAClient::s_handle_counter = 0;

static THREAD_LOCAL ClientMap* client_map;
static THREAD_LOCAL FlowHAClient* s_session_client;

static inline bool is_ip6_key(const FlowKey* key)
{
    return (key->ip_l[0] || key->ip_l[1] || key->ip_l[2] != htonl(0xFFFF) ||
           key->ip_h[0] || key->ip_h[1] || key->ip_h[2] != htonl(0xFFFF));
}

FlowHAState::FlowHAState()
{
    state = INITIAL_STATE;
    pending = NONE_PENDING;
}

void FlowHAState::set_pending(FlowHAClientHandle handle)
{
    pending |= (uint16_t)handle;
}

bool FlowHAState::check_pending(FlowHAClientHandle handle)
{
    return ((pending & (uint16_t)handle) != 0);
}

void FlowHAState::clear_pending(FlowHAClientHandle handle)
{
    pending &= ~((uint16_t)handle);
}

void FlowHAState::set(uint8_t new_state)
{
    state |= (new_state & STATUS_MASK);
}

void FlowHAState::set(uint8_t new_state, uint8_t new_priority)
{
    state |= (new_state & STATUS_MASK);
    state |= (new_priority & PRIORITY_MASK);
}

void FlowHAState::clear(uint8_t old_state)
{
    state &= ~(old_state & STATUS_MASK);
}

void FlowHAState::clear(uint8_t old_state, uint8_t old_priority)
{
    state &= ~(old_state & STATUS_MASK);
    state &= ~(old_priority & PRIORITY_MASK);
}

bool FlowHAState::check(uint8_t state_mask)
{
    return (state & state_mask) != 0;
}

bool FlowHAState::is_critical()
{
    return ((state & CRITICAL) != 0);
}

bool FlowHAState::is_major()
{
    return ((state & MAJOR) != 0);
}

void FlowHAState::config_lifetime(struct timeval min_lifetime)
{
    min_session_lifetime = min_lifetime;
}

bool FlowHAState::old_enough()
{
    struct timeval pkt_time;

    packet_gettimeofday(&pkt_time);

    return ( ( pkt_time.tv_sec > next_update.tv_sec ) ||
           ( ( pkt_time.tv_sec == next_update.tv_sec ) &&
           ( pkt_time.tv_usec > next_update.tv_usec ) ) );
}

void FlowHAState::set_next_update()
{
    next_update.tv_usec += min_session_lifetime.tv_usec;
    if (next_update.tv_usec > 1000000)
    {
        next_update.tv_usec -= 1000000;
        next_update.tv_sec++;
    }
    next_update.tv_sec += min_session_lifetime.tv_sec;
}

void FlowHAState::initialize_update_time()
{
    packet_gettimeofday(&next_update);
}

FlowHAClient::FlowHAClient(bool session_client)
{
    DebugMessage(DEBUG_HA,"FlowHAClient::FlowHAClient()\n");
    if ( session_client )
    {
        handle = SESSION_HA_CLIENT;
        s_session_client = this;
    }
    else
    {
        assert(s_handle_counter != MAX_CLIENTS);
        handle = (1 << s_handle_counter);
        s_handle_counter += 1;
    }
}

// Write the key type, key length, and key into the message.
// Does not use the message cursor coming in.
// Leave the message cursor just after the key. Return
// the key length.
static uint8_t write_flow_key(Flow* flow, HAMessage* msg)
{
    HAMessageHeader* hdr = (HAMessageHeader*)msg->content();
    msg->cursor = (uint8_t*)hdr + sizeof(HAMessageHeader);
    const FlowKey* key = flow->key;
    assert(key);

    if (is_ip6_key(flow->key) )
    {
        hdr->key_type = key_type_ip6;
        memcpy(msg->cursor, key, key_size_ip6);
        msg->cursor = (uint8_t*)hdr + key_size_ip6;
        return key_size_ip6;
    }
    else
    {
        hdr->key_type = key_type_ip4;
        memcpy(msg->cursor, &key->ip_l[3], sizeof(key->ip_l[3]));
        msg->cursor += sizeof(key->ip_l[3]);
        memcpy(msg->cursor, &key->ip_h[3], sizeof(key->ip_h[3]));
        msg->cursor += sizeof(key->ip_h[3]);
        memcpy(msg->cursor, ((uint8_t*)key) + 32, key_size_ip4 - 8);
        msg->cursor += key_size_ip4 - 8;

        return key_size_ip4;
    }
}

// Regardless of the message cursor, extract the key and
// return the key length.  Position the cursor just after the key.
static uint8_t read_flow_key(FlowKey* key, HAMessage* msg)
{
    assert(key);
    HAMessageHeader* hdr = (HAMessageHeader*)msg->content();
    msg->cursor = (uint8_t*)hdr + sizeof(HAMessageHeader);

    if ( hdr->key_type == key_type_ip6 )
    {
        memcpy(key, msg->cursor, key_size_ip6);
        msg->cursor += key_size_ip6;
        return key_size_ip6;
    }
    else if ( hdr->key_type == key_type_ip4 )
    {
        /* Lower IPv4 address */
        memcpy(&key->ip_l[3], msg->cursor, sizeof(key->ip_l[3]));
        key->ip_l[0] = key->ip_l[1] = 0;
        key->ip_l[2] = htonl(0xFFFF);
        msg->cursor += sizeof(key->ip_l[3]);
        /* Higher IPv4 address */
        memcpy(&key->ip_h[3], msg->cursor, sizeof(key->ip_h[3]));
        key->ip_h[0] = key->ip_h[1] = 0;
        key->ip_h[2] = htonl(0xFFFF);
        msg->cursor += sizeof(key->ip_h[3]);
        /* The remainder of the key */
        memcpy(((uint8_t*)key) + 32, msg->cursor, key_size_ip4 - 8);
        msg->cursor += key_size_ip4 - 8;
        return key_size_ip4;
    }
    else
        return 0;
}

static inline uint8_t key_size(Flow* flow)
{
    assert(flow->key);
    return is_ip6_key(flow->key) ? key_size_ip6 : key_size_ip4;
}

static uint16_t calculate_msg_header_length(Flow* flow)
{
    return sizeof(HAMessageHeader) + key_size(flow);
}

// Calculate the UPDATE message content length based on the
// set of active clients.  The Session client is always present.
static uint16_t calculate_update_msg_content_length(Flow* flow)
{
    uint16_t length = s_session_client->get_message_size();
    DebugFormat(DEBUG_HA,"HighAvailability::calculate_update_msg_content_length(): length: %d\n",
        length);

    // Iterating through the hash map is OK to determine length.
    for (auto& iter : * client_map )
        if ( flow->ha_state->check_pending(iter.first) )
        {
            length += iter.second->get_message_size();
            DebugFormat(DEBUG_HA,
                "HighAvailability::calculate_update_msg_content_length(): length: %d\n", length);
        }

    return length;
}

// Write the HA header and key sections.  Position the cursor
// at the beginning of the content section.
static void write_msg_header(Flow* flow, HAEvent event, uint16_t content_length, HAMessage* msg)
{
    HAMessageHeader* hdr = (HAMessageHeader*)msg->content();
    hdr->event = (uint8_t)event;
    hdr->version = ha_message_version;
    hdr->total_length = content_length;
    write_flow_key(flow, msg);  // set cursor to just beyond key
}

static void write_update_msg_content(Flow* flow, HAMessage* msg)
{
    //  Always have the session portion
    s_session_client->produce(flow,msg);

    // Since I'm not sure that the hash map is deterministic, I'll
    // step through the clients in order
    for ( int i=0; i<FlowHAClient::s_handle_counter; i++ )
    {
        FlowHAClientHandle handle = 1<<i;
        if ( flow->ha_state->check_pending(handle) )
            client_map->find(handle)->second->produce(flow,msg);
    }
}

HighAvailability::HighAvailability(PortBitSet* ports, bool)
{
    SCPort port;
    using namespace std::placeholders;
    DebugMessage(DEBUG_HA,"HighAvailability::HighAvailability()\n");

    // If we have ports, configure the side channel
    if ( ports != nullptr )
        for ( port = 0; port < ports->size(); port++ )
            if ( ports->test(port) )
            {
                sc = SideChannelManager::get_side_channel(port);
                if (sc)
                {
                    // We need a duplex channel
                    if (sc->get_direction() != Connector::CONN_DUPLEX)
                    {
                        // Otherwise indicate that we don't have a sidechannel
                        sc = nullptr;
                        break;
                    }
                    sc->set_default_port(port);
                    sc->register_receive_handler(
                        std::bind(&HighAvailability::receive_handler, this, _1));
                }
                break;
            }

    client_map = new ClientMap;

    // Only looking for side channel processing - FIXIT-H
}

HighAvailability::~HighAvailability()
{
    DebugMessage(DEBUG_HA,"HighAvailability::~HighAvailability()\n");

    if ( sc )
    {
        sc->unregister_receive_handler();
    }

    delete client_map;
}

void HighAvailability::receive_handler(SCMessage* msg)
{
    assert(msg);

    DebugFormat(DEBUG_HA,"HighAvailability::receive_handler: port: %d, length: %d\n",
        msg->hdr->port, msg->content_length);
    if ( msg->sc )
        msg->sc->discard_message(msg);
}

void HighAvailability::process_update(Flow* flow, const DAQ_PktHdr_t* pkthdr)
{
    DebugMessage(DEBUG_HA,"HighAvailability::process_update()\n");

    // Only looking for side channel processing - FIXIT-H
    if ( !sc || !flow )
        return;

    const uint16_t header_len = calculate_msg_header_length(flow);
    const uint16_t content_len = calculate_update_msg_content_length(flow);

    SCMessage* sc_msg = sc->alloc_transmit_message((uint32_t)(header_len+content_len));
    assert(sc_msg);
    HAMessage ha_msg(sc_msg);

    write_msg_header(flow, HA_UPDATE_EVENT, content_len, &ha_msg);
    write_update_msg_content(flow, &ha_msg);
    sc->transmit_message(sc_msg);
}

void HighAvailability::process_deletion(Flow* flow)
{
    DebugMessage(DEBUG_HA,"HighAvailability::process_deletion()\n");

    // No need to send message if we already have, we are in standby, or
    // we have just been created and haven't yet sent an update
    if ( flow->ha_state->check(FlowHAState::CREATED |
        FlowHAState::DELETED |
        FlowHAState::STANDBY))
        return;

    // Deletion messages only use the side channel
    if ( !sc )
        return;

    const uint32_t msg_len = calculate_msg_header_length(flow);
    SCMessage* sc_msg = sc->alloc_transmit_message(msg_len);
    HAMessage ha_msg(sc_msg);

    // No content, only header+key
    write_msg_header(flow, HA_DELETE_EVENT, 0, &ha_msg);

    sc->transmit_message(sc_msg);

    flow->ha_state->set(FlowHAState::DELETED);
}

void HighAvailability::process_receive()
{
    if ( sc != nullptr )
        sc->process(0);
}

// Called by the configuration parsing activity in the main thread.
bool HighAvailabilityManager::instantiate(PortBitSet* mod_ports, bool mod_use_daq_channel)
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::instantiate()\n");
    ports = mod_ports;
#ifdef HAVE_DAQ_EXT_MODFLOW
    use_daq_channel = mod_use_daq_channel;
#else
    if ( mod_use_daq_channel )
        return false;
#endif
    return true;
}

// Called prior to the starts of configuration in the main thread.
void HighAvailabilityManager::pre_config_init()
{
    DebugFormat(DEBUG_HA,"HighAvailabilityManager::pre_config_init(): key size: %d\n",
        sizeof(FlowKey));
    ports = nullptr;
}

// Called within the packet thread prior to packet processing
void HighAvailabilityManager::thread_init()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::thread_init()\n");
    // create a a thread local instance iff we are configured to operate.
    if ( (ports != nullptr) || use_daq_channel )
        ha = new HighAvailability(ports,use_daq_channel);
    else
        ha = nullptr;
}

// Called in the packet thread at run-down
void HighAvailabilityManager::thread_term()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::thread_term()\n");
    if ( ha != nullptr )
    {
        delete ha;
        ha = nullptr;
    }
}

void HighAvailabilityManager::process_update(Flow* flow, const DAQ_PktHdr_t* pkthdr)
{
    if ( (ha != nullptr) && (pkthdr != nullptr) && (flow != nullptr) )
        ha->process_update(flow,pkthdr);
}

// Deletion messages only contain session content
void HighAvailabilityManager::process_deletion(Flow* flow)
{
    if ( ha != nullptr )
        ha->process_deletion(flow);
}

void HighAvailabilityManager::process_receive()
{
    if ( ha != nullptr )
        ha->process_receive();
}

// Called in the packet threads to determine whether or not HA is active
bool HighAvailabilityManager::active()
{
    return (ha != nullptr);
}

