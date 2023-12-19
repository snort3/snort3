//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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
// ha.cc authors Ed Borgoyn <eborgoyn@cisco.com>, Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ha.h"

#include "framework/counts.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq_instance.h"
#include "protocols/packet.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "time/packet_time.h"

#include "flow.h"
#include "flow_key.h"
#include "ha_module.h"
#include "session.h"

using namespace snort;

enum HAEvent
{
    HA_DELETE_EVENT = 1,
    HA_UPDATE_EVENT = 2
};

struct __attribute__((__packed__)) HAMessageHeader
{
    uint8_t event;
    uint8_t version;
    uint16_t total_length;
    uint8_t key_type;
};

struct __attribute__((__packed__)) HAClientHeader
{
    uint8_t client;
    uint8_t length;
};

// One client for each mask bit plus one 'automatic' session client
//   client handle = (1<<(client_index-1)
//   session client has handle of 0 and index of 0
static constexpr uint8_t MAX_CLIENTS = 17;

// HighAvailability is the thread-local state/configuration instantiated for each packet thread.
typedef std::array<FlowHAClient*, MAX_CLIENTS> ClientMap;
class HighAvailability
{
public:
    HighAvailability(PortBitSet*,bool);
    ~HighAvailability();

    void process_update(Flow*, Packet*);
    void process_deletion(Flow&);
    void process_receive();

    Flow* process_daq_import(Packet&, FlowKey&);

    // The [0] entry contains the stream client (always present)
    // Entries [1] to [MAX_CLIENTS-1] contain the optional clients
    ClientMap client_map = { };
    uint8_t handle_counter = 1; // stream client (index == 0) always exists
    bool shutting_down = false;

private:
    SideChannel* sc = nullptr;
    bool use_daq_channel;
};

static constexpr uint8_t HA_MESSAGE_VERSION = 4;

// define message size and content constants.
static constexpr uint8_t KEY_SIZE_IP6 = sizeof(FlowKey);
// ip4 key is smaller by 2*(ip6_addr_size - ip4_addr_size) or 2 * (16 - 4) = 24
static constexpr uint8_t KEY_SIZE_IP4 = sizeof(FlowKey)-24;

enum
{
    KEY_TYPE_IP6 = 1,
    KEY_TYPE_IP4 = 2
};

static constexpr FlowHAClientHandle SESSION_HA_CLIENT = 0x0000;
static constexpr uint8_t SESSION_HA_CLIENT_INDEX = 0;

PortBitSet* HighAvailabilityManager::ports = nullptr;
bool HighAvailabilityManager::use_daq_channel = false;

struct timeval FlowHAState::min_session_lifetime;
struct timeval FlowHAState::min_sync_interval;

static THREAD_LOCAL HighAvailability* ha;

static inline bool is_ip6_key(const FlowKey* key)
{
    return (key->ip_l[0] || key->ip_l[1] || key->ip_l[2] != htonl(0xFFFF) ||
           key->ip_h[0] || key->ip_h[1] || key->ip_h[2] != htonl(0xFFFF));
}

FlowHAState::FlowHAState()
{
    // Set the initial update time to now+min_session_lifetime
    packet_gettimeofday(&next_update);
    timeradd(&next_update, &min_session_lifetime, &next_update);
}

void FlowHAState::set_pending(FlowHAClientHandle handle)
{
    pending |= handle;
}

bool FlowHAState::check_pending(FlowHAClientHandle handle)
{
    return ((pending & handle) != 0);
}

void FlowHAState::clear_pending(FlowHAClientHandle handle)
{
    pending &= ~handle;
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

void FlowHAState::init_next_update()
{
    packet_gettimeofday(&next_update);
    timeradd(&next_update, &min_session_lifetime, &next_update);
}

void FlowHAState::set_next_update()
{
    timeradd(&next_update, &min_sync_interval, &next_update);
}

void FlowHAState::reset()
{
    state = INITIAL_STATE;
    pending = NONE_PENDING;
    init_next_update();
}

FlowHAClient::FlowHAClient(uint8_t length, bool session_client) : max_length(length)
{
    if (!ha)
        return;

    if (session_client)
    {
        index = SESSION_HA_CLIENT_INDEX;
        handle = SESSION_HA_CLIENT;
        ha->client_map[0] = this;
    }
    else
    {
        if (ha->handle_counter >= MAX_CLIENTS)
        {
            ErrorMessage("Attempting to register too many FlowHAClients\n");
            return;
        }

        index = ha->handle_counter;
        handle = (1 << (index - 1));
        ha->client_map[index] = this;
        ha->handle_counter++;
    }
}

// Write the key type, key length, and key into the message.
// Return the type of key written so it can be stored in the message header.
static uint8_t write_flow_key(const Flow& flow, HAMessage& msg)
{
    const FlowKey* key = flow.key;
    assert(key);

    if (is_ip6_key(flow.key))
    {
        memcpy(msg.cursor, key, KEY_SIZE_IP6);
        msg.advance_cursor(KEY_SIZE_IP6);

        return KEY_TYPE_IP6;
    }

    memcpy(msg.cursor, &key->ip_l[3], sizeof(key->ip_l[3]));
    msg.advance_cursor(sizeof(key->ip_l[3]));
    memcpy(msg.cursor, &key->ip_h[3], sizeof(key->ip_h[3]));
    msg.advance_cursor(sizeof(key->ip_h[3]));
    memcpy(msg.cursor, ((const uint8_t*) key) + 32, KEY_SIZE_IP4 - 8);
    msg.advance_cursor(KEY_SIZE_IP4 - 8);

    return KEY_TYPE_IP4;
}

// Extract the key and return the key length.  Position the cursor just after the key.
static uint8_t read_flow_key(HAMessage& msg, const HAMessageHeader* hdr, FlowKey& key)
{
    if (hdr->key_type == KEY_TYPE_IP6)
    {
        if (!msg.fits(KEY_SIZE_IP6))
        {
            ha_stats.truncated_msgs++;
            return 0;
        }

        memcpy(&key, msg.cursor, KEY_SIZE_IP6);
        msg.advance_cursor(KEY_SIZE_IP6);

        return KEY_SIZE_IP6;
    }
    else if (hdr->key_type == KEY_TYPE_IP4)
    {
        if (!msg.fits(KEY_SIZE_IP4))
        {
            ha_stats.truncated_msgs++;
            return 0;
        }

        /* Lower IPv4 address */
        memcpy(&key.ip_l[3], msg.cursor, sizeof(key.ip_l[3]));
        key.ip_l[0] = key.ip_l[1] = 0;
        key.ip_l[2] = htonl(0xFFFF);
        msg.advance_cursor(sizeof(key.ip_l[3]));
        /* Higher IPv4 address */
        memcpy(&key.ip_h[3], msg.cursor, sizeof(key.ip_h[3]));
        key.ip_h[0] = key.ip_h[1] = 0;
        key.ip_h[2] = htonl(0xFFFF);
        msg.advance_cursor(sizeof(key.ip_h[3]));
        /* The remainder of the key */
        memcpy(((uint8_t*) &key) + 32, msg.cursor, KEY_SIZE_IP4 - 8);
        msg.advance_cursor(KEY_SIZE_IP4 - 8);

        return KEY_SIZE_IP4;
    }

    ha_stats.unknown_key_type++;
    return 0;
}

static inline uint8_t key_size(Flow& flow)
{
    assert(flow.key);
    return is_ip6_key(flow.key) ? KEY_SIZE_IP6 : KEY_SIZE_IP4;
}

static uint16_t calculate_msg_header_length(Flow& flow)
{
    return sizeof(HAMessageHeader) + key_size(flow);
}

// Calculate the UPDATE message content length based on the
// set of active clients.  The Session client is always present.
static uint16_t calculate_update_msg_content_length(Flow& flow, bool full)
{
    assert(ha->client_map[0]);

    uint16_t length = 0;

    for (int i = 0; i < ha->handle_counter; i++)
    {
        // Don't check 'i' against SESSION_HA_CLIENT_INDEX (==0), as this creates a false positive with cppcheck
        if ((i == 0) || full || flow.ha_state->check_pending(1 << (i - 1)))
        {
            assert(ha->client_map[i]);
            length += (ha->client_map[i]->get_message_size(flow) + sizeof(HAClientHeader));
        }
    }

    return length;
}

// Write the HA header and key sections.  Position the cursor
// at the beginning of the content section.
static void write_msg_header(const Flow& flow, HAEvent event, uint16_t content_length, HAMessage& msg)
{
    HAMessageHeader* hdr = (HAMessageHeader*) msg.cursor;
    hdr->event = (uint8_t) event;
    hdr->version = HA_MESSAGE_VERSION;
    hdr->total_length = content_length;
    msg.advance_cursor(sizeof(HAMessageHeader));
    hdr->key_type = write_flow_key(flow, msg);
}

static uint16_t update_msg_header_length(const HAMessage& msg)
{
    HAMessageHeader* hdr = (HAMessageHeader*) msg.buffer;
    hdr->total_length = msg.cursor_position();
    return hdr->total_length;
}

static void write_update_msg_client(FlowHAClient* client, Flow& flow, HAMessage& msg)
{
    assert(client);

    if (!msg.fits(sizeof(HAClientHeader)))
        return;

    // Preemptively insert the client header.  If production fails, roll back the message cursor
    // to its original position.
    uint8_t* original_cursor = msg.cursor;
    HAClientHeader* header = (HAClientHeader*) original_cursor;
    header->client = client->index;
    msg.advance_cursor(sizeof(HAClientHeader));
    if (!client->produce(flow, msg))
    {
        msg.reset_cursor(original_cursor);
        return;
    }
    assert(msg.cursor >= (original_cursor + sizeof(HAClientHeader)));
    header->length = (uint32_t) (msg.cursor - original_cursor - sizeof(HAClientHeader));
}

static void write_update_msg_content(Flow& flow, HAMessage& msg, bool full)
{
    for (int i = 0; i < ha->handle_counter; i++)
    {
        // Don't check 'i' against SESSION_HA_CLIENT_INDEX (==0), as this creates a false positive with cppcheck
        if ((i == 0) || full || flow.ha_state->check_pending(1 << (i - 1)))
            write_update_msg_client(ha->client_map[i], flow, msg);
    }
}

static void consume_ha_delete_message(HAMessage&, const FlowKey& key)
{
    Stream::delete_flow(&key);
}

static Flow* consume_ha_update_message(HAMessage& msg, const FlowKey& key, Packet* p)
{
    // flow will be nullptr if/when the session does not exist in the caches
    bool no_flow_found = false;
    Flow* flow = Stream::get_flow(&key);
    if (!flow)
    {
        no_flow_found = true;
        ha_stats.update_msgs_recv_no_flow++;
    }

    // pointer to one past the last byte in the message
    const uint8_t* content_end = msg.buffer + msg.buffer_length;

    while (msg.cursor < content_end)
    {
        // do we have sufficient message left to be able to have an HAClientHeader?
        if (!msg.fits(sizeof(HAClientHeader)))
        {
            ErrorMessage("Consuming HA Update message - no HAClientHeader\n");
            ha_stats.truncated_msgs++;
            break;
        }

        HAClientHeader* header = (HAClientHeader*) msg.cursor;
        if ((header->client >= ha->handle_counter) || (ha->client_map[header->client] == nullptr))
        {
            ErrorMessage("Consuming HA Update message - invalid client index\n");
            ha_stats.unknown_client_idx++;
            break;
        }
        msg.advance_cursor(sizeof(HAClientHeader)); // step to the client content

        if (!msg.fits(header->length))
        {
            ErrorMessage("Consuming HA Update message - message too short\n");
            ha_stats.truncated_msgs++;
            break;
        }

        // If the Flow does not exist in the caches, flow will be nullptr
        // upon entry into this message processing loop.  Since the session
        // client is always the first segment of the message, the consume()
        // invocation for the session client will create the flow.  This
        // flow can in turn be used by subsequent FlowHAClient's.
        if (!ha->client_map[header->client]->consume(flow, &key, msg, header->length))
        {
            ErrorMessage("Consuming HA Update message - error from client consume()\n");
            ha_stats.client_consume_errors++;
            break;
        }
    }

    if (msg.cursor == content_end)
        ha_stats.update_msgs_consumed++;

    if( p && no_flow_found && flow && flow->session )
    {
        flow->session->setup(p);
        flow->set_direction(p);
        flow->set_client_initiate(p);

        if (p->is_from_client())
        {
            flow->client_intf = p->pkth->ingress_index;
            flow->server_intf = p->pkth->egress_index;
            flow->client_group = p->pkth->ingress_group;
            flow->server_group = p->pkth->egress_group;
        }
        else
        {
            flow->client_intf = p->pkth->egress_index;
            flow->server_intf = p->pkth->ingress_index;
            flow->client_group = p->pkth->egress_group;
            flow->server_group = p->pkth->ingress_group;
        }
    }

    return flow;
}

static Flow* consume_ha_message(HAMessage& msg,
    FlowKey* packet_key = nullptr, Packet* p = nullptr)
{
    ha_stats.msgs_recv++;

    if (!msg.fits(sizeof(HAMessageHeader)))
    {
        ha_stats.truncated_msgs++;
        return nullptr;
    }

    const HAMessageHeader* hdr = (HAMessageHeader*) msg.cursor;

    if (hdr->version != HA_MESSAGE_VERSION)
    {
        ha_stats.msg_version_mismatch++;
        return nullptr;
    }

    if (hdr->total_length != msg.buffer_length)
    {
        ha_stats.msg_length_mismatch++;
        return nullptr;
    }

    msg.advance_cursor(sizeof(HAMessageHeader));

    FlowKey key;
    if (read_flow_key(msg, hdr, key) == 0)
        return nullptr;

    if (packet_key and !FlowKey::is_equal(packet_key, &key))
    {
        ha_stats.key_mismatch++;
        return nullptr;
    }

    Flow* flow = nullptr;
    switch (hdr->event)
    {
        case HA_DELETE_EVENT:
        {
            consume_ha_delete_message(msg, key);
            ha_stats.delete_msgs_consumed++;
            break;
        }
        case HA_UPDATE_EVENT:
        {
            flow = consume_ha_update_message(msg, key, p);
            ha_stats.update_msgs_recv++;
            break;
        }
    }

    return flow;
}

static void ha_sc_receive_handler(SCMessage* sc_msg)
{
    assert(sc_msg);

    // SC received messages must have reference back to SideChannel object
    assert(sc_msg->sc);

    HAMessage ha_msg(sc_msg->content, sc_msg->content_length);
    consume_ha_message(ha_msg);

    sc_msg->sc->discard_message(sc_msg);
}

HighAvailability::HighAvailability(PortBitSet* ports, bool daq_channel)
{
    using namespace std::placeholders;

    // If side channel ports were configured, find the first matching side channel to associate with
    if (ports != nullptr)
    {
        for (SCPort port = 0; port < ports->size(); port++)
        {
            if (!ports->test(port))
                continue;

            sc = SideChannelManager::get_side_channel(port);
            if (sc)
            {
                // We require a duplex channel
                if (sc->get_direction() != Connector::CONN_DUPLEX)
                {
                    sc = nullptr;
                    continue;
                }
                sc->set_default_port(port);
                sc->register_receive_handler(ha_sc_receive_handler);
            }
            break;
        }
    }
    use_daq_channel = daq_channel;
}

HighAvailability::~HighAvailability()
{
    if (sc)
        sc->unregister_receive_handler();
}

static void send_sc_update_message(Flow& flow, SideChannel& sc)
{
    const uint16_t header_len = calculate_msg_header_length(flow);
    const uint16_t content_len = calculate_update_msg_content_length(flow, false);

    SCMessage* sc_msg = sc.alloc_transmit_message((uint32_t) (header_len + content_len));
    assert(sc_msg);
    HAMessage ha_msg(sc_msg->content, sc_msg->content_length);

    write_msg_header(flow, HA_UPDATE_EVENT, header_len + content_len, ha_msg);
    write_update_msg_content(flow, ha_msg, false);
    update_msg_header_length(ha_msg);
    sc.transmit_message(sc_msg);
}

static void send_daq_update_message(Flow& flow, Packet& p)
{
    static THREAD_LOCAL uint8_t daq_io_buffer[UINT16_MAX];

    HAMessage ha_msg(daq_io_buffer, sizeof(daq_io_buffer));

    write_msg_header(flow, HA_UPDATE_EVENT, 0, ha_msg);
    write_update_msg_content(flow, ha_msg, true);
    uint32_t len = update_msg_header_length(ha_msg);

    DIOCTL_FlowHAState fhs;
    fhs.msg = p.daq_msg;
    fhs.data = daq_io_buffer;
    fhs.length = len;

    p.daq_instance->ioctl(DIOCTL_SET_FLOW_HA_STATE, &fhs, sizeof(fhs));

    ha_stats.daq_stores++;
}

void HighAvailability::process_update(Flow* flow, Packet* p)
{
    if (!flow)
        return;

    // We must have the map array and the session client
    assert(client_map[0]);

    if ( !client_map[0]->is_update_required(flow) &&
        ( !flow->ha_state->check_pending(ALL_CLIENTS) ||
            flow->ha_state->check_any(FlowHAState::NEW) ) )
        return;

    if (sc)
        send_sc_update_message(*flow, *sc);

    if (use_daq_channel && p && p->daq_msg)
        send_daq_update_message(*flow, *p);

    flow->ha_state->clear(FlowHAState::NEW | FlowHAState::MODIFIED |
        FlowHAState::MAJOR | FlowHAState::CRITICAL);
    flow->ha_state->clear_pending(ALL_CLIENTS);
    flow->ha_state->set_next_update();
}

static void send_sc_deletion_message(Flow& flow, SideChannel& sc)
{
    const uint32_t msg_len = calculate_msg_header_length(flow);
    SCMessage* sc_msg = sc.alloc_transmit_message(msg_len);
    HAMessage ha_msg(sc_msg->content, sc_msg->content_length);

    // No content, only header+key
    write_msg_header(flow, HA_DELETE_EVENT, msg_len, ha_msg);

    sc.transmit_message(sc_msg);
}

void HighAvailability::process_deletion(Flow& flow)
{
    // No need to send message if we already have, we are in standby, or
    // we have just been created and haven't yet sent an update
    if (flow.ha_state->check_any(FlowHAState::NEW | FlowHAState::DELETED | FlowHAState::STANDBY))
        return;

    // Only produce deletion messages when using a side channel
    if (sc)
        send_sc_deletion_message(flow, *sc);

    flow.ha_state->add(FlowHAState::DELETED);
}

void HighAvailability::process_receive()
{
    if (sc)
        sc->process(DISPATCH_ALL_RECEIVE);
}

Flow* HighAvailability::process_daq_import(Packet& p, FlowKey& key)
{
    Flow* flow = nullptr;

    if (use_daq_channel && p.pkth->flags & DAQ_PKT_FLAG_HA_STATE_AVAIL)
    {
        DIOCTL_FlowHAState fhs;
        fhs.msg = p.daq_msg;

        if (p.daq_instance->ioctl(DIOCTL_GET_FLOW_HA_STATE, &fhs, sizeof(fhs)) == DAQ_SUCCESS)
        {
            HAMessage ha_msg(fhs.data, fhs.length);
            flow = consume_ha_message(ha_msg, &key, &p);
            ha_stats.daq_imports++;
            // Validate that the imported flow matches up with the given flow key.
            if (flow)
            {
                if (Flow::FlowState::INSPECT < flow->flow_state)
                {
                    flow->disable_inspection();
                    p.disable_inspect = true;
                }
                // Clear the standby bit so that we don't immediately trigger a new data store
                // FIXIT-L streamline the consume process so this doesn't have to be done here
                flow->ha_state->clear(FlowHAState::STANDBY);
            }
        }
    }

    return flow;
}

void HighAvailabilityManager::reset_config()
{
    if (ports)
    {
        delete ports;
        ports = nullptr;
    }
}

void HighAvailabilityManager::term()
{
    reset_config();
}

// Called within the main thread after the initial configuration has been read
void HighAvailabilityManager::configure(HighAvailabilityConfig* config)
{
    if (!config)
    {
        reset_config();
        return;
    }

    if (config->ports)
        ports = new PortBitSet(*config->ports);
    else if (ports)
    {
        delete ports;
        ports = nullptr;
    }

    FlowHAState::config_timers(config->min_session_lifetime, config->min_sync_interval);

    use_daq_channel = config->daq_channel;
}

// Called within the packet thread prior to packet processing
void HighAvailabilityManager::thread_init()
{
    // create a a thread local instance iff we are configured to operate.
    if (ports || use_daq_channel)
        ha = new HighAvailability(ports, use_daq_channel);
    else
        ha = nullptr;
}

void HighAvailabilityManager::thread_term_beginning()
{
    if (ha)
        ha->shutting_down = true;
}

// Called in the packet thread at run-down
void HighAvailabilityManager::thread_term()
{
    if (ha)
    {
        delete ha;
        ha = nullptr;
    }
}

void HighAvailabilityManager::process_update(Flow* flow, Packet* p)
{
    if (ha && flow && !p->active->get_tunnel_bypass())
        ha->process_update(flow, p);
}

// Deletion messages only contain session content
void HighAvailabilityManager::process_deletion(Flow& flow)
{
    if (ha && !ha->shutting_down)
        ha->process_deletion(flow);
}

void HighAvailabilityManager::process_receive()
{
    if (ha)
        ha->process_receive();
}

// Called in the packet threads to determine whether or not HA is active
bool HighAvailabilityManager::active()
{
    return (ha != nullptr);
}

void HighAvailabilityManager::set_modified(Flow* flow)
{
    if (ha && flow && flow->ha_state)
        flow->ha_state->add(FlowHAState::MODIFIED);
}

bool HighAvailabilityManager::in_standby(Flow* flow)
{
    if (ha && flow && flow->ha_state)
        return flow->ha_state->check_any(FlowHAState::STANDBY);

    return false;
}

Flow* HighAvailabilityManager::import(Packet& p, FlowKey& key)
{
    if (!ha)
        return nullptr;

    return ha->process_daq_import(p, key);
}
