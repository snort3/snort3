//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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
// mp_unix_transport.h author Oleksandr Stepanov <ostepano@cisco.com>

#ifndef UNIX_TRANSPORT_H
#define UNIX_TRANSPORT_H

#include "connectors/unixdomain_connector/unixdomain_connector.h"
#include "framework/mp_data_bus.h"
#include "main/snort_types.h"
#include "side_channel/side_channel.h"

#include <atomic>
#include <thread>
#include <condition_variable>

namespace snort
{

struct MPUnixTransportStats
{
    MPUnixTransportStats() :
        sent_events(0),
        sent_bytes(0),
        received_events(0),
        received_bytes(0),
        send_errors(0),
        successful_connections(0),
        closed_connections(0),
        connection_retries(0)
    { }
    
    PegCount sent_events;
    PegCount sent_bytes;
    PegCount received_events;
    PegCount received_bytes;
    PegCount send_errors;
    PegCount successful_connections;
    PegCount closed_connections;
    PegCount connection_retries;
};

struct MPUnixDomainTransportConfig
{
    std::string unix_domain_socket_path;
    uint16_t max_processes = 0;
    bool conn_retries = true;
    bool enable_logging = false;
    uint32_t retry_interval_seconds = 5;
    uint32_t max_retries = 5;
    uint32_t connect_timeout_seconds = 30;
    uint32_t consume_message_timeout_milliseconds = 100;
    uint32_t consume_message_batch_size = 5;
};

struct SerializeFunctionHandle
{
    std::unordered_map<unsigned, MPHelperFunctions> serialize_functions;

    MPHelperFunctions* get_function_set(unsigned event_id)
    {
        auto it = serialize_functions.find(event_id);
        if(it == serialize_functions.end())
            return nullptr;
        return &it->second;
    }
};

struct SideChannelHandle
{
    SideChannelHandle(SideChannel* sc, UnixDomainConnectorConfig* cc, const unsigned short& channel_id) :
        side_channel(sc), connector_config(cc), channel_id(channel_id)
    { }

    ~SideChannelHandle();

    SideChannel* side_channel;
    UnixDomainConnectorConfig* connector_config;
    unsigned short channel_id;
};

struct UnixAcceptorHandle
{
    UnixDomainConnectorConfig* connector_config = nullptr;
    UnixDomainConnectorListener* listener = nullptr;
};

class MPUnixDomainTransport : public MPTransport
{
    public:

    MPUnixDomainTransport(MPUnixDomainTransportConfig* c, MPUnixTransportStats& stats);
    ~MPUnixDomainTransport() override;

    bool configure(const SnortConfig*) override;
    void thread_init() override;
    void thread_term() override;
    void init_connection() override;
    bool send_to_transport(MPEventInfo& event) override;
    void register_event_helpers(const unsigned& pub_id, const unsigned& event_id, MPHelperFunctions& helper) override;
    void register_receive_handler(const TransportReceiveEventHandler& handler) override;
    void unregister_receive_handler() override;
    void enable_logging() override;
    void disable_logging() override;
    bool is_logging_enabled() override;
    void cleanup();
    MPTransportChannelStatusHandle* get_channel_status(unsigned& size) override;

    MPUnixDomainTransportConfig* get_config()
    { return config; }


    private:

    void init_side_channels();
    void cleanup_side_channels();
    void side_channel_receive_handler(SCMessage* msg);
    void handle_new_connection(UnixDomainConnector* connector, UnixDomainConnectorConfig* cfg, const unsigned short& channel_id);
    void process_messages_from_side_channels();
    void notify_process_thread();
    void connector_update_handler(UnixDomainConnector* connector, bool is_recconecting, SideChannel* side_channel);
    void MPTransportLog(const char* msg, ...);

    MPSerializeFunc get_event_serialization_function(unsigned pub_id, unsigned event_id);
    MPDeserializeFunc get_event_deserialization_function(unsigned pub_id, unsigned event_id);

    uint32_t mp_current_process_id = 0;

    TransportReceiveEventHandler transport_receive_handler = nullptr;
    MPUnixDomainTransportConfig* config = nullptr;

    std::vector<SideChannelHandle*> side_channels;
    std::vector<UnixAcceptorHandle*> accept_handlers;
    std::unordered_map<unsigned, SerializeFunctionHandle> event_helpers;

    std::atomic<bool> is_running = false;
    std::atomic<bool> is_logging_enabled_flag;
    std::atomic<bool> consume_message_received = false;

    std::thread* consume_thread = nullptr;
    std::condition_variable consume_thread_cv;

    MPUnixTransportStats& transport_stats;
};

}
#endif
