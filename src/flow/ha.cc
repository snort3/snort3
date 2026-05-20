//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <cstring>
#include <map>
#include <string>

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

// Maximum number of HA clients.  Each client occupies one bit in the 16-bit
// pending mask.  The session client is identified by HAClientInfo::is_session,
// not by a reserved handle value.
static constexpr uint8_t MAX_CLIENTS = 16;

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

    ClientMap client_map = { };
    FlowHAClient* session_client = nullptr;
    uint8_t handle_counter = 0;
    bool shutting_down = false;

private:
    SideChannel* sc = nullptr;
    bool use_daq_channel;
};


// Ensure to increment both versions simultaneously to maintain consistency
#ifndef DISABLE_TENANT_ID
static constexpr uint8_t HA_MESSAGE_VERSION = 5;
#else
static constexpr uint8_t HA_MESSAGE_VERSION = 6;
#endif

// define message size and content constants.
static constexpr uint8_t KEY_SIZE_IP6 = sizeof(FlowKey);
// ip4 key is smaller by 2*(ip6_addr_size - ip4_addr_size) or 2 * (16 - 4) = 24
static constexpr uint8_t KEY_SIZE_IP4 = sizeof(FlowKey)-24;

enum
{
    KEY_TYPE_IP6 = 1,
    KEY_TYPE_IP4 = 2
};

static std::string make_ha_client_name(const char* mod_name, const char* suffix)
{
    if (!suffix || !*suffix)
        return mod_name;
    return std::string(mod_name) + "_" + suffix;
}

// Process-global name-to-index registry.  std::map keeps keys sorted.
// Reload mutates this on the main thread; readers (FlowHAClient ctor) only run
// during thread_reinit which the reload driver sequences after the writer phase
// completes, so no concurrent access is possible.
static constexpr uint8_t HA_INDEX_UNASSIGNED = 0xFF;
struct HAClientInfo
{
    uint8_t index = HA_INDEX_UNASSIGNED;
    FlowHAClientHandle handle = 0;
    bool is_session = false;
};
static std::map<std::string, HAClientInfo> ha_client_name_map;
static bool ha_indices_finalized = false;

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

FlowHAClient::FlowHAClient(uint8_t length, const char* mod_name, const char* suffix)
    : max_length(length)
{
    if (!ha)
        return;

    const std::string client_name = make_ha_client_name(mod_name, suffix);

    if (!ha_indices_finalized)
    {
        ErrorMessage("FlowHAClient: '%s' constructed before "
            "finalize_ha_client_indices()\n", client_name.c_str());
        return;
    }
    auto it = ha_client_name_map.find(client_name);
    if (it == ha_client_name_map.end())
    {
        ErrorMessage("FlowHAClient: '%s' not registered in HA client registry\n",
            client_name.c_str());
        return;
    }

    index = it->second.index;
    handle = it->second.handle;
    ha->client_map[index] = this;

    if (it->second.is_session)
        ha->session_client = this;

    // upper bound for produce/consume iteration; tinit() order may differ from index order.
    if (index >= ha->handle_counter)
        ha->handle_counter = index + 1;
}

FlowHAClient::~FlowHAClient()
{
    if (ha and ha->client_map[index] == this)
    {
        ha->client_map[index] = nullptr;
        if (ha->session_client == this)
            ha->session_client = nullptr;
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
    memcpy(msg.cursor, (reinterpret_cast<const uint8_t*>(key)) + 32, KEY_SIZE_IP4 - 8);
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
        memcpy((reinterpret_cast<uint8_t*>(&key)) + 32, msg.cursor, KEY_SIZE_IP4 - 8);
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
// set of active clients.  The session client is always present.
static uint16_t calculate_update_msg_content_length(Flow& flow, bool full)
{
    if (!ha->session_client)
        return 0;

    uint16_t length = 0;

    for (int i = 0; i < ha->handle_counter; i++)
    {
        FlowHAClient* client = ha->client_map[i];
        if (!client)
            continue;
        if (client == ha->session_client or full or flow.ha_state->check_pending(client->handle))
            length += (client->get_message_size(flow) + sizeof(HAClientHeader));
    }

    return length;
}

// Write the HA header and key sections.  Position the cursor
// at the beginning of the content section.
static void write_msg_header(const Flow& flow, HAEvent event, uint16_t content_length, HAMessage& msg)
{
    HAMessageHeader* hdr = reinterpret_cast<HAMessageHeader*>(msg.cursor);
    hdr->event = (uint8_t) event;
    hdr->version = HA_MESSAGE_VERSION;
    hdr->total_length = content_length;
    msg.advance_cursor(sizeof(HAMessageHeader));
    hdr->key_type = write_flow_key(flow, msg);
}

static uint16_t update_msg_header_length(const HAMessage& msg)
{
    HAMessageHeader* hdr = reinterpret_cast<HAMessageHeader*>(msg.buffer);
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
    HAClientHeader* header = reinterpret_cast<HAClientHeader*>(original_cursor);
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
    // Session client must be first in the message so the consumer can create the flow
    if (ha->session_client)
        write_update_msg_client(ha->session_client, flow, msg);

    for (int i = 0; i < ha->handle_counter; i++)
    {
        FlowHAClient* client = ha->client_map[i];
        if (!client or client == ha->session_client)
            continue;
        if (full or flow.ha_state->check_pending(client->handle))
            write_update_msg_client(client, flow, msg);
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

        HAClientHeader* header = reinterpret_cast<HAClientHeader*>(msg.cursor);
        if ((header->client >= ha->handle_counter) || (ha->client_map[header->client] == nullptr))
        {
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
            ha_stats.client_consume_errors++;
            break;
        }
    }

    if (msg.cursor == content_end)
        ha_stats.update_msgs_consumed++;

    if( p && no_flow_found && flow && flow->session )
    {
        p->flow = flow;
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

    const HAMessageHeader* hdr = reinterpret_cast<HAMessageHeader*>(msg.cursor);

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
        for (unsigned port = 0; port < ports->size(); port++)
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

    write_msg_header(flow, HA_UPDATE_EVENT, sc_msg->content_length, ha_msg);
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

    // Flow may have been created before HA was enabled (e.g. HA enabled via reload)
    if (!flow->ha_state)
        return;

    // We must have the session client
    if (!session_client)
        return;

    if ( !session_client->is_update_required(flow) and
        ( !flow->ha_state->check_pending(ALL_CLIENTS) or
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
    assert(sc_msg);

    HAMessage ha_msg(sc_msg->content, sc_msg->content_length);

    // No content, only header+key
    write_msg_header(flow, HA_DELETE_EVENT, msg_len, ha_msg);

    sc.transmit_message(sc_msg);
}

void HighAvailability::process_deletion(Flow& flow)
{
    // Flow may have been created before HA was enabled (e.g. HA enabled via reload)
    if (!flow.ha_state)
        return;

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

void HighAvailabilityManager::register_ha_client(const char* mod_name, const char* suffix,
    bool is_session)
{
    if (ha_indices_finalized)
        return;
    const std::string name = make_ha_client_name(mod_name, suffix);
    auto [it, inserted] = ha_client_name_map.emplace(name, HAClientInfo{});
    if (!inserted)
    {
        ErrorMessage("HighAvailabilityManager::register_ha_client: "
            "duplicate HA client name '%s' (two inspectors using the same "
            "mod_name/suffix pair); ignoring second registration\n", name.c_str());
        return;
    }
    it->second.is_session = is_session;
}

void HighAvailabilityManager::finalize_ha_client_indices()
{
    // 16 bits in FlowHAClientHandle pending mask, one bit per client.
    if (ha_client_name_map.size() > MAX_CLIENTS)
    {
        ErrorMessage("HighAvailabilityManager::finalize_ha_client_indices: "
            "too many HA clients registered (%zu > MAX_CLIENTS=%u)\n",
            ha_client_name_map.size(), MAX_CLIENTS);
        return;
    }
    // Exactly one client must be the session client (creates the flow on consume).
    unsigned session_count = 0;
    for (const auto& [name, info] : ha_client_name_map)
        if (info.is_session)
            ++session_count;
    if (session_count != 1)
    {
        ErrorMessage("HighAvailabilityManager::finalize_ha_client_indices: "
            "expected exactly one session HA client, found %u\n", session_count);
        return;
    }

    uint8_t next_index = 0;
    uint8_t next_bit = 0;
    // std::map iterates in sorted key order, giving deterministic index assignment
    for (auto& [name, info] : ha_client_name_map)
    {
        info.index = next_index++;
        info.handle = static_cast<FlowHAClientHandle>(1u << next_bit++);
    }
    ha_indices_finalized = true;
}

#ifdef UNIT_TEST
uint8_t HighAvailabilityManager::get_ha_client_index(const char* mod_name, const char* suffix)
{
    const std::string name = make_ha_client_name(mod_name, suffix);
    auto it = ha_client_name_map.find(name);
    if (it == ha_client_name_map.end())
    {
        ErrorMessage("HighAvailabilityManager::get_ha_client_index: "
            "'%s' not registered\n", name.c_str());
        return HA_INDEX_UNASSIGNED;
    }
    return it->second.index;
}
#endif

void HighAvailabilityManager::reset_config()
{
    if (ports)
    {
        delete ports;
        ports = nullptr;
    }
    use_daq_channel = false;
}

void HighAvailabilityManager::term()
{
    reset_config();
    ha_client_name_map.clear();
    ha_indices_finalized = false;
}

void HighAvailabilityManager::configure(HighAvailabilityConfig* config)
{
    // Reset registry for this configuration cycle
    ha_client_name_map.clear();
    ha_indices_finalized = false;
    if (!config)
    {
        reset_config();
        return;
    }

    if (config->ports)
    {
        delete ports;
        ports = new PortBitSet(*config->ports);
    }
    else if (ports)
    {
        delete ports;
        ports = nullptr;
    }

    FlowHAState::config_timers(config->min_session_lifetime, config->min_sync_interval);

    use_daq_channel = config->daq_channel;
}

void HighAvailabilityManager::thread_init()
{
    if ( configured() )
        ha = new HighAvailability(ports, use_daq_channel);
}

void HighAvailabilityManager::thread_reinit()
{
    // Per-plugin FlowHAClient instances are torn down/recreated by each plugin's
    // own ReloadSwapper, which runs after this one in FIFO order.
    if (ha)
    {
        delete ha;
        ha = nullptr;
    }

    if (configured())
    {
        ha = new HighAvailability(ports, use_daq_channel);
    }
}

void HighAvailabilityManager::thread_term_beginning()
{
    if (ha)
        ha->shutting_down = true;
}

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
    // Gate on the per-thread `ha` only; configured() reads process-global state
    // that the main thread can mutate mid-reload, before tswap.
    if (!ha or !flow or !p or !p->active)
        return;

    if (!p->active->get_tunnel_bypass())
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

bool HighAvailabilityManager::active()
{
    return (ha != nullptr);
}

bool HighAvailabilityManager::configured()
{
    return (ports or use_daq_channel);
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
