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
// mp_unix_transport.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mp_unix_transport.h"

#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "framework/mp_data_bus.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"

static std::mutex _receive_mutex;
static std::mutex _update_connectors_mutex;

#define UNIX_SOCKET_NAME_PREFIX "/snort_unix_connector_"

#define MP_TRANSPORT_LOG_LABEL "MPUnixTransport"

#define MP_TRANSPORT_LOG(msg, ...) do { \
        if (!this->is_logging_enabled_flag) \
            break; \
        LogMessage(msg, __VA_ARGS__); \
    } while (0)

namespace snort
{

#pragma pack(push, 1) 
    enum MPTransportMessageType 
    { 
        EVENT_MESSAGE = 0,
        MAX_TYPE
    };

struct MPTransportMessageHeader
{
    MPTransportMessageType type;// Type of the message 
    int32_t pub_id;             // Identifier for the module sending or receiving the message 
    int32_t event_id;           // Identifier for the specific event 
    uint16_t data_length;       // Length of the data payload 
};

struct MPTransportMessage
{
    MPTransportMessageHeader header; // Header containing metadata about the message
    char* data;                      // Placeholder for the actual data payload 
}; 
#pragma pack(pop) 

void MPUnixDomainTransport::side_channel_receive_handler(SCMessage* msg)
{
    if (transport_receive_handler and msg)
    {
        if (msg->content_length < sizeof(MPTransportMessage))
        {
            MP_TRANSPORT_LOG("%s: Incomplete message received\n", MP_TRANSPORT_LOG_LABEL);
            return;
        }

        MPTransportMessageHeader* transport_message_header = (MPTransportMessageHeader*)msg->content;
        
        if (transport_message_header->type >= MAX_TYPE)
        {
            MP_TRANSPORT_LOG("%s: Invalid message type received\n", MP_TRANSPORT_LOG_LABEL);
            return;
        }

        auto deserialize_func = get_event_deserialization_function(transport_message_header->pub_id, transport_message_header->event_id);
        if (!deserialize_func)
        {
            MP_TRANSPORT_LOG("%s: No deserialization function found for event: type %d, id %d\n", MP_TRANSPORT_LOG_LABEL, transport_message_header->type, transport_message_header->event_id);
            return;
        }

        DataEvent* internal_event = nullptr;
        (deserialize_func)((const char*)(msg->content + sizeof(MPTransportMessageHeader)), transport_message_header->data_length, internal_event);
        MPEventInfo event(internal_event, transport_message_header->event_id, transport_message_header->pub_id);

        (transport_receive_handler)(event);

        delete internal_event;
    }
    delete msg;
}

void MPUnixDomainTransport::handle_new_connection(UnixDomainConnector *connector, UnixDomainConnectorConfig* cfg)
{
    assert(connector);
    assert(cfg);

    std::lock_guard<std::mutex> guard(_update_connectors_mutex);

    auto side_channel = new SideChannel(ScMsgFormat::BINARY);
    side_channel->connector_receive = connector;
    side_channel->connector_transmit = side_channel->connector_receive;
    side_channel->register_receive_handler(std::bind(&MPUnixDomainTransport::side_channel_receive_handler, this, std::placeholders::_1));
    connector->set_message_received_handler(std::bind(&MPUnixDomainTransport::notify_process_thread, this));
    this->side_channels.push_back(new SideChannelHandle(side_channel, cfg));
    connector->set_update_handler(std::bind(&MPUnixDomainTransport::connector_update_handler, this, std::placeholders::_1, std::placeholders::_2, side_channel));
}

MPUnixDomainTransport::MPUnixDomainTransport(MPUnixDomainTransportConfig *c) : MPTransport(), 
    config(c)
{
    this->is_logging_enabled_flag = c->enable_logging;
}

MPUnixDomainTransport::~MPUnixDomainTransport()
{
    cleanup();
}

bool MPUnixDomainTransport::send_to_transport(MPEventInfo &event)
{
    auto serialize_func = get_event_serialization_function(event.pub_id, event.type);

    if (!serialize_func)
    {
        MP_TRANSPORT_LOG("%s: No serialize function found for event %d\n", MP_TRANSPORT_LOG_LABEL, event.type);
        return false;
    }

    MPTransportMessage transport_message;
    transport_message.header.type = EVENT_MESSAGE;
    transport_message.header.pub_id = event.pub_id;
    transport_message.header.event_id = event.type;

    
    (serialize_func)(event.event, transport_message.data, &transport_message.header.data_length);
    for (auto &&sc_handler : this->side_channels)
    {
        auto msg = sc_handler->side_channel->alloc_transmit_message(sizeof(MPTransportMessageHeader) + transport_message.header.data_length);
        memcpy(msg->content, &transport_message, sizeof(MPTransportMessageHeader));
        memcpy(msg->content + sizeof(MPTransportMessageHeader), transport_message.data, transport_message.header.data_length);
        auto send_result = sc_handler->side_channel->transmit_message(msg);
        if (!send_result)
        {
            MP_TRANSPORT_LOG("%s: Failed to send message to side channel\n", MP_TRANSPORT_LOG_LABEL);
        }
    }

    delete[] transport_message.data;
    
    return true;
}

void MPUnixDomainTransport::register_event_helpers(const unsigned& pub_id, const unsigned& event_id, MPHelperFunctions& helper)
{
    assert(helper.deserializer);
    assert(helper.serializer);
    
    this->event_helpers[pub_id] = SerializeFunctionHandle();
    this->event_helpers[pub_id].serialize_functions.insert({event_id, helper});
}

void MPUnixDomainTransport::register_receive_handler(const TransportReceiveEventHandler& handler)
{
    this->transport_receive_handler = handler;
}

void MPUnixDomainTransport::unregister_receive_handler()
{
    this->transport_receive_handler = nullptr;
}

void MPUnixDomainTransport::process_messages_from_side_channels()
{
    std::unique_lock<std::mutex> lock(_receive_mutex);
    do
    {
        if ( (std::cv_status::timeout == this->consume_thread_cv.wait_for(lock, std::chrono::milliseconds(config->consume_message_timeout_milliseconds)) )
            and this->consume_message_received == false )
        {
            continue;
        }

        {
            std::lock_guard<std::mutex> guard(_update_connectors_mutex);
            bool messages_left;

            do
            {
                messages_left = false;
                for (auto &&sc_handler : this->side_channels)
                {
                    messages_left |= sc_handler->side_channel->process(config->consume_message_batch_size);
                }
            } while (messages_left);
        }

        this->consume_message_received = false;

    } while (this->is_running);
}

void MPUnixDomainTransport::notify_process_thread()
{
    this->consume_thread_cv.notify_all();
    this->consume_message_received = true;
}

void MPUnixDomainTransport::connector_update_handler(UnixDomainConnector *connector, bool is_recconecting, SideChannel *side_channel)
{
    std::lock_guard<std::mutex> guard(_update_connectors_mutex);
    if (side_channel->connector_receive)
    {
        delete side_channel->connector_receive;
        side_channel->connector_receive = side_channel->connector_transmit = nullptr;
    }

    if (connector)
    {
        side_channel->connector_receive = side_channel->connector_transmit = connector;
    }
    else
    {
        if (is_recconecting == false)
        {
            MP_TRANSPORT_LOG("%s: Accepted connection interrupted, removing handle\n", MP_TRANSPORT_LOG_LABEL);
            for(auto it = this->side_channels.begin(); it != this->side_channels.end(); ++it)
            {
                if ((*it)->side_channel == side_channel)
                {
                    delete *it;
                    this->side_channels.erase(it);
                    break;
                }
            }
        }
    }
}

MPSerializeFunc MPUnixDomainTransport::get_event_serialization_function(unsigned pub_id, unsigned event_id)
{
    auto helper_it = this->event_helpers.find(pub_id);
    if (helper_it == this->event_helpers.end())
    {
        MP_TRANSPORT_LOG("%s: No available helper functions is registered for %d\n", MP_TRANSPORT_LOG_LABEL, pub_id);
        return nullptr;
    }
    auto helper_functions = helper_it->second.get_function_set(event_id);
    if (!helper_functions)
    {
        MP_TRANSPORT_LOG("%s: No serialize function found for event %d\n", MP_TRANSPORT_LOG_LABEL, event_id);
        return nullptr;
    }
    return helper_functions->serializer;
}

MPDeserializeFunc MPUnixDomainTransport::get_event_deserialization_function(unsigned pub_id, unsigned event_id)
{
    auto helper_it = this->event_helpers.find(pub_id);
    if (helper_it == this->event_helpers.end())
    {
        MP_TRANSPORT_LOG("%s: No available helper functions is registered for %d\n", MP_TRANSPORT_LOG_LABEL, pub_id);
        return nullptr;
    }
    auto helper_functions = helper_it->second.get_function_set(event_id);
    if (!helper_functions)
    {
        MP_TRANSPORT_LOG("%s: No serialize function found for event %d\n", MP_TRANSPORT_LOG_LABEL, event_id);
        return nullptr;
    }
    return helper_functions->deserializer;
}

void MPUnixDomainTransport::init_connection()
{
    init_side_channels();
}

void MPUnixDomainTransport::thread_init()
{
}

void MPUnixDomainTransport::thread_term()
{
}

bool MPUnixDomainTransport::configure(const SnortConfig *c)
{
    config->max_processes = c->max_procs;
    return true;
}

void MPUnixDomainTransport::cleanup()
{
    this->is_running = false;
    MPUnixDomainTransport::unregister_receive_handler();
    if (this->consume_thread)
    {
        this->consume_thread_cv.notify_all();
        this->consume_thread->join();
        delete this->consume_thread;
        this->consume_thread = nullptr;
    }
    cleanup_side_channels();
    for (auto &&ac_handler : this->accept_handlers)
    {
        ac_handler->listener->stop_accepting_connections();
        delete ac_handler->listener;
        delete ac_handler->connector_config;
        delete ac_handler;
    }
    this->accept_handlers.clear();
}

void MPUnixDomainTransport::init_side_channels()
{
    assert(config);
    if (config->max_processes < 2)
        return;

    auto instance_id = Snort::get_process_id();//Snort instance id
    auto max_processes = config->max_processes;

    this->is_running = true;

    for (ushort i = instance_id; i < max_processes; i++)
    {
        auto listen_path = config->unix_domain_socket_path + UNIX_SOCKET_NAME_PREFIX + std::to_string(i);
        auto unix_listener = new UnixDomainConnectorListener(listen_path.c_str());
        
        UnixDomainConnectorConfig* unix_config = new UnixDomainConnectorConfig();
        unix_config->setup = UnixDomainConnectorConfig::Setup::ANSWER;
        unix_config->async_receive = true;
        if (config->conn_retries)
        {
            unix_config->conn_retries = config->conn_retries;
            unix_config->retry_interval = config->retry_interval_seconds;
            unix_config->max_retries = config->max_retries;
            unix_config->connect_timeout_seconds = config->connect_timeout_seconds;
        }
        else
        {
            unix_config->conn_retries = false;
            unix_config->retry_interval = 0;
            unix_config->max_retries = 0;
            unix_config->connect_timeout_seconds = 0;
        }
        unix_config->paths.push_back(listen_path);

        unix_listener->start_accepting_connections( std::bind(&MPUnixDomainTransport::handle_new_connection, this, std::placeholders::_1, std::placeholders::_2), unix_config);
        
        auto unix_listener_handle = new UnixAcceptorHandle();
        unix_listener_handle->connector_config = unix_config;
        unix_listener_handle->listener = unix_listener;
        this->accept_handlers.push_back(unix_listener_handle);
    }

    for (ushort i = 1; i < instance_id; i++)
    {
        auto side_channel = new SideChannel(ScMsgFormat::BINARY);
        side_channel->register_receive_handler([this](SCMessage* msg) { this->side_channel_receive_handler(msg); });

        auto send_path = config->unix_domain_socket_path + "/" + "snort_unix_connector_" + std::to_string(i);

        UnixDomainConnectorConfig* connector_conf = new UnixDomainConnectorConfig();
        connector_conf->setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_conf->async_receive = true;
        connector_conf->conn_retries = config->conn_retries;
        connector_conf->retry_interval = config->retry_interval_seconds;
        connector_conf->max_retries = config->max_retries;
        connector_conf->connect_timeout_seconds = config->connect_timeout_seconds;
        connector_conf->paths.push_back(send_path);

        auto connector = unixdomain_connector_tinit_call(*connector_conf, send_path.c_str(), 0, std::bind(&MPUnixDomainTransport::connector_update_handler, this, std::placeholders::_1, std::placeholders::_2, side_channel));

        if (connector)
            connector->set_message_received_handler(std::bind(&MPUnixDomainTransport::notify_process_thread, this));

        side_channel->connector_receive = connector;
        side_channel->connector_transmit = side_channel->connector_receive;
        this->side_channels.push_back( new SideChannelHandle(side_channel, connector_conf));
    }

    this->consume_thread = new std::thread(&MPUnixDomainTransport::process_messages_from_side_channels, this);
}
void MPUnixDomainTransport::cleanup_side_channels()
{
    std::lock_guard<std::mutex> guard(_update_connectors_mutex);

    for (uint i = 0; i < this->side_channels.size(); i++)
    {
        auto side_channel = this->side_channels[i];
        delete side_channel;
    }

    this->side_channels.clear();
}

SideChannelHandle::~SideChannelHandle()
{
    if (side_channel)
    {
        if (side_channel->connector_receive)
            delete side_channel->connector_receive;

        delete side_channel;
    }
    
    if (connector_config)
        delete connector_config;
}
void MPUnixDomainTransport::enable_logging()
{
    this->is_logging_enabled_flag = true;
}

void MPUnixDomainTransport::disable_logging()
{
    this->is_logging_enabled_flag = false;
}

bool MPUnixDomainTransport::is_logging_enabled()
{
    return this->is_logging_enabled_flag;
}

};
