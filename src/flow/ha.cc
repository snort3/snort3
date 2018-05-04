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
// ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ha.h"

#include <array>

#include "framework/counts.h"
#include "log/messages.h"
#include "profiler/profiler_defs.h"
#include "stream/stream.h"
#include "time/packet_time.h"

#include "flow.h"
#include "flow_key.h"

using namespace snort;

static const uint8_t HA_MESSAGE_VERSION = 3;

// define message size and content constants.
static const uint8_t KEY_SIZE_IP6 = sizeof(FlowKey);
// ip4 key is smaller by 2*(ip6-addr-size - ip4-addr-size) or 2*(16 - 4) = 24
static const uint8_t KEY_SIZE_IP4 = sizeof(FlowKey)-24;

static const suseconds_t USEC_PER_SEC = 1000000;

enum
{
    KEY_TYPE_IP6 = 1,
    KEY_TYPE_IP4 = 2
};

typedef std::array<FlowHAClient*, MAX_CLIENTS> ClientMap;

THREAD_LOCAL SimpleStats ha_stats;
THREAD_LOCAL ProfileStats ha_perf_stats;

static THREAD_LOCAL HighAvailability* ha;
PortBitSet* HighAvailabilityManager::ports = nullptr;
bool HighAvailabilityManager::use_daq_channel = false;
THREAD_LOCAL bool HighAvailabilityManager::shutting_down = false;
struct timeval FlowHAState::min_session_lifetime;
struct timeval FlowHAState::min_sync_interval;
uint8_t s_handle_counter = 1; // stream client (index == 0) always exists

// The [0] entry contains the stream client (always present)
// Entries [1] to [MAX_CLIENTS-1] contain the optional clients
static THREAD_LOCAL ClientMap* s_client_map;

static inline bool is_ip6_key(const FlowKey* key)
{
    return (key->ip_l[0] || key->ip_l[1] || key->ip_l[2] != htonl(0xFFFF) ||
           key->ip_h[0] || key->ip_h[1] || key->ip_h[2] != htonl(0xFFFF));
}

FlowHAState::FlowHAState()
{
    state = INITIAL_STATE;
    state |= (NEW | NEW_SESSION);
    pending = NONE_PENDING;

    // Set the initial update time to now+min_session_lifetime
    packet_gettimeofday(&next_update);
    next_update.tv_usec += min_session_lifetime.tv_usec;
    if (next_update.tv_usec > USEC_PER_SEC)
    {
        next_update.tv_usec -= USEC_PER_SEC;
        next_update.tv_sec++;
    }
    next_update.tv_sec += min_session_lifetime.tv_sec;
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
    state = new_state;
}

void FlowHAState::add(uint8_t new_state)
{
    state |= new_state;
}

void FlowHAState::clear(uint8_t old_state)
{
    state &= ~old_state;
}

bool FlowHAState::check_any(uint8_t state_mask)
{
    return (state & state_mask) != 0;
}

void FlowHAState::config_timers(struct timeval min_lifetime, struct timeval min_interval)
{
    min_session_lifetime = min_lifetime;
    min_sync_interval = min_interval;
}

bool FlowHAState::sync_interval_elapsed()
{
    struct timeval pkt_time;

    packet_gettimeofday(&pkt_time);

    return ( ( pkt_time.tv_sec > next_update.tv_sec ) ||
           ( ( pkt_time.tv_sec == next_update.tv_sec ) &&
           ( pkt_time.tv_usec > next_update.tv_usec ) ) );
}

void FlowHAState::set_next_update()
{
    next_update.tv_usec += min_sync_interval.tv_usec;
    if (next_update.tv_usec > USEC_PER_SEC)
    {
        next_update.tv_usec -= USEC_PER_SEC;
        next_update.tv_sec++;
    }
    next_update.tv_sec += min_sync_interval.tv_sec;
}

void FlowHAState::reset()
{
    state = INITIAL_STATE;
    pending = NONE_PENDING;
}

FlowHAClient::FlowHAClient(uint8_t length, bool session_client)
{
    if ( !s_client_map )
        return;

    header.length = length;

    if ( session_client )
    {
        handle = SESSION_HA_CLIENT;
        header.client = SESSION_HA_CLIENT_INDEX;
        (*s_client_map)[0] = this;
    }
    else
    {
        if ( s_handle_counter >= MAX_CLIENTS )
        {
            ErrorMessage("Attempting to register too many FlowHAClients\n");
            return;
        }

        header.client = s_handle_counter;
        handle = (1 << (s_handle_counter-1));
        (*s_client_map)[s_handle_counter] = this;
        s_handle_counter += 1;
    }
}

bool FlowHAClient::fit(HAMessage* msg, uint8_t size)
{
    return ( (int)(msg->cursor - msg->content()) < (int)(msg->content_length() - size) );
}

bool FlowHAClient::place(HAMessage* msg, uint8_t* data, uint8_t length)
{
    if ( fit(msg, length) )
    {
        memcpy(msg->cursor,data,(size_t)length);
        msg->cursor += length;
        return true;
    }
    else
        return false;
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

    if ( is_ip6_key(flow->key) )
    {
        hdr->key_type = KEY_TYPE_IP6;
        memcpy(msg->cursor, key, KEY_SIZE_IP6);
        msg->cursor += KEY_SIZE_IP6;

        return KEY_SIZE_IP6;
    }

    hdr->key_type = KEY_TYPE_IP4;
    memcpy(msg->cursor, &key->ip_l[3], sizeof(key->ip_l[3]));
    msg->cursor += sizeof(key->ip_l[3]);
    memcpy(msg->cursor, &key->ip_h[3], sizeof(key->ip_h[3]));
    msg->cursor += sizeof(key->ip_h[3]);
    memcpy(msg->cursor, ((const uint8_t*)key) + 32, KEY_SIZE_IP4 - 8);
    msg->cursor += KEY_SIZE_IP4 - 8;

    return KEY_SIZE_IP4;
}

// Regardless of the message cursor, extract the key and
// return the key length.  Position the cursor just after the key.
static uint8_t read_flow_key(FlowKey* key, HAMessage* msg)
{
    assert(key);
    HAMessageHeader* hdr = (HAMessageHeader*)msg->content();
    msg->cursor = (uint8_t*)hdr + sizeof(HAMessageHeader);

    if ( hdr->key_type == KEY_TYPE_IP6 )
    {
        memcpy(key, msg->cursor, KEY_SIZE_IP6);
        msg->cursor += KEY_SIZE_IP6;

        return KEY_SIZE_IP6;
    }
    else if ( hdr->key_type == KEY_TYPE_IP4 )
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
        memcpy(((uint8_t*)key) + 32, msg->cursor, KEY_SIZE_IP4 - 8);
        msg->cursor += KEY_SIZE_IP4 - 8;

        return KEY_SIZE_IP4;
    }
    else
        return 0;
}

static inline uint8_t key_size(Flow* flow)
{
    assert(flow->key);
    return is_ip6_key(flow->key) ? KEY_SIZE_IP6 : KEY_SIZE_IP4;
}

static uint16_t calculate_msg_header_length(Flow* flow)
{
    return sizeof(HAMessageHeader) + key_size(flow);
}

// Calculate the UPDATE message content length based on the
// set of active clients.  The Session client is always present.
static uint16_t calculate_update_msg_content_length(Flow* flow)
{
    assert(s_client_map);
    assert((*s_client_map)[0]);

    uint16_t length = 0;

    for (int i=0; i<s_handle_counter; i++)
    {
        // Don't check 'i' against SESSION_HA_CLIENT_INDEX (==0), as this creates a false positive with cppcheck
        if ( (i == 0 ) || flow->ha_state->check_pending(1<<(i-1)) )
        {
            assert((*s_client_map)[i]);
            length += ((*s_client_map)[i]->get_message_size() + sizeof(HAClientHeader));
        }
    }

    return length;
}

// Write the HA header and key sections.  Position the cursor
// at the beginning of the content section.
static void write_msg_header(Flow* flow, HAEvent event, uint16_t content_length, HAMessage* msg)
{
    HAMessageHeader* hdr = (HAMessageHeader*)msg->content();
    hdr->event = (uint8_t)event;
    hdr->version = HA_MESSAGE_VERSION;
    hdr->total_length = content_length;
    write_flow_key(flow, msg);  // set cursor to just beyond key
}

static void write_update_msg_client( FlowHAClient* client, Flow* flow, HAMessage* msg)
{
    assert(client);
    assert(msg);

    client->place(msg,(uint8_t*)&(client->header),(uint8_t)sizeof(client->header));
    client->produce(flow, msg);
}

static void write_update_msg_content(Flow* flow, HAMessage* msg)
{
    assert(s_client_map);

    for ( int i=0; i<s_handle_counter; i++ )
    {
        // Don't check 'i' against SESSION_HA_CLIENT_INDEX (==0), as this creates a false positive with cppcheck
        if ( (i == 0) || flow->ha_state->check_pending(1<<(i-1)) )
            write_update_msg_client((*s_client_map)[i],flow, msg);
    }
}

static void consume_receive_delete_message(HAMessage* msg)
{
    FlowKey key;
    (void)read_flow_key(&key, msg);
    Stream::delete_flow(&key);
}

static void consume_receive_update_message(HAMessage* msg)
{
    FlowKey key;
    (void)read_flow_key(&key, msg);
    // flow will be nullptr if/when the session does not exist in the caches
    Flow* flow = Stream::get_flow(&key);

    assert(s_client_map);

    // pointer to the last byte in the message
    uint8_t* content_end = msg->content() + msg->content_length() - 1;

    while( msg->cursor <= content_end )
    {
        // do we have sufficient message left to be able to have an HAClientHeader?
        if ( (int)(content_end - msg->cursor + 1) < (int)sizeof( HAClientHeader ) )
        {
            ErrorMessage("Consuming HA Update message - no HAClientHeader\n");
            break;
        }

        HAClientHeader* header = (HAClientHeader*)msg->cursor;
        msg->cursor += sizeof( HAClientHeader ); // step to the client content

        if ( (header->client >= s_handle_counter) ||
            ((*s_client_map)[header->client] == nullptr)  )
        {
            ErrorMessage("Consuming HA Update message - invalid client index\n");
            break;
        }

        if ( (content_end - msg->cursor + 1) < header->length )
        {
            ErrorMessage("Consuming HA Update message - message too short\n");
            break;
        }

        // If the Flow does not exist in the caches, flow will be nullptr
        // upon entry into this message processing loop.  Since the session
        // client is always the first segment of the message, the consume()
        // invocation for the session client will create the flow.  This
        // flow can in turn be used by subsequent FlowHAClient's.
        if ( !(*s_client_map)[header->client]->consume(flow,&key,msg) )
        {
            ErrorMessage("Consuming HA Update message - error from client consume()\n");
            break;
        }
    }
}

static void consume_receive_message(HAMessage* msg)
{
    HAMessageHeader* hdr = (HAMessageHeader*)msg->content();

    if ( hdr->version != HA_MESSAGE_VERSION)
        return;

    switch ( hdr->event )
    {
        case HA_DELETE_EVENT:
        {
            consume_receive_delete_message(msg);
            break;
        }
        case HA_UPDATE_EVENT:
        {
            consume_receive_update_message(msg);
            break;
        }
        default:
            break;
    }
}

HighAvailability::HighAvailability(PortBitSet* ports, bool)
{
    using namespace std::placeholders;

    // If we have ports, configure the side channel
    if ( ports != nullptr )
    {
        for ( SCPort port = 0; port < ports->size(); port++ )
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
    }
    s_client_map = new ClientMap;
    for ( int i=0; i<MAX_CLIENTS; i++ )
        (*s_client_map)[i] = nullptr;

    // Only looking for side channel processing - FIXIT-H
}

HighAvailability::~HighAvailability()
{
    if ( sc )
    {
        sc->unregister_receive_handler();
    }

    delete s_client_map;
}

void HighAvailability::receive_handler(SCMessage* sc_msg)
{
    assert(sc_msg);

    // SC received messages must have reference back to SideChannel object
    assert(sc_msg->sc);

    HAMessage ha_msg(sc_msg);
    consume_receive_message(&ha_msg);

    sc_msg->sc->discard_message(sc_msg);
}

void HighAvailability::process_update(Flow* flow, const DAQ_PktHdr_t* pkthdr)
{
    // Only looking for side channel processing - FIXIT-H
    UNUSED(pkthdr); // until we add DAQ communications channel
    if ( !sc || !flow )
        return;

    // We must have the map array and the session client
    assert(s_client_map);
    assert((*s_client_map)[0]);

    if ( !(*s_client_map)[0]->is_update_required(flow) &&
        ( !flow->ha_state->check_pending(ALL_CLIENTS) ||
            flow->ha_state->check_any(FlowHAState::NEW) ) )
        return;

    const uint16_t header_len = calculate_msg_header_length(flow);
    const uint16_t content_len = calculate_update_msg_content_length(flow);

    SCMessage* sc_msg = sc->alloc_transmit_message((uint32_t)(header_len+content_len));
    assert(sc_msg);
    HAMessage ha_msg(sc_msg);

    write_msg_header(flow, HA_UPDATE_EVENT, content_len, &ha_msg);
    write_update_msg_content(flow, &ha_msg);
    sc->transmit_message(sc_msg);

    flow->ha_state->clear(FlowHAState::NEW | FlowHAState::MODIFIED |
        FlowHAState::MAJOR | FlowHAState::CRITICAL);
    flow->ha_state->clear_pending(ALL_CLIENTS);
    flow->ha_state->set_next_update();
}

void HighAvailability::process_deletion(Flow* flow)
{
    // No need to send message if we already have, we are in standby, or
    // we have just been created and haven't yet sent an update
    if ( flow->ha_state->check_any(FlowHAState::NEW |
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

    flow->ha_state->add(FlowHAState::DELETED);
}

void HighAvailability::process_receive()
{
    if ( sc != nullptr )
        sc->process(DISPATCH_ALL_RECEIVE);
}

// Called by the configuration parsing activity in the main thread.
bool HighAvailabilityManager::instantiate(PortBitSet* mod_ports, bool mod_use_daq_channel,
        struct timeval* min_session_lifetime, struct timeval* min_sync_interval)
{
    ports = mod_ports;
    FlowHAState::config_timers(*min_session_lifetime, *min_sync_interval);
    use_daq_channel = mod_use_daq_channel;

    return true;
}

// Called prior to the starts of configuration in the main thread.
void HighAvailabilityManager::pre_config_init()
{
    ports = nullptr;
}

// Called within the packet thread prior to packet processing
void HighAvailabilityManager::thread_init()
{
    // create a a thread local instance iff we are configured to operate.
    if ( (ports != nullptr) || use_daq_channel )
        ha = new HighAvailability(ports,use_daq_channel);
    else
        ha = nullptr;
}

void HighAvailabilityManager::thread_term_beginning()
{
    shutting_down = true;
}

// Called in the packet thread at run-down
void HighAvailabilityManager::thread_term()
{
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
    if ( (ha != nullptr) && !shutting_down )
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

void HighAvailabilityManager::set_modified(Flow* flow)
{
    if ( (ha != nullptr) && (flow != nullptr) && (flow->ha_state != nullptr) )
        flow->ha_state->add(FlowHAState::MODIFIED);
}

bool HighAvailabilityManager::in_standby(Flow* flow)
{
    if ( (ha != nullptr) && (flow != nullptr) && (flow->ha_state != nullptr) )
        return flow->ha_state->check_any(FlowHAState::STANDBY);
    else
        return false;
}
