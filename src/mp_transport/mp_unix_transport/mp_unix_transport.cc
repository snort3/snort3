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
#include <sys/stat.h>
#include <unistd.h>
#include <shared_mutex>

#include "framework/mp_data_bus.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"

static std::mutex _receive_mutex;
static std::shared_mutex _connection_update_mutex;

#define UNIX_SOCKET_NAME_PREFIX "/snort_unix_connector_"
#define MP_TRANSPORT_LOG_LABEL "MPUnixTransportDbg"

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
            MPTransportLog("Incomplete message received\n");
            return;
        }

        MPTransportMessageHeader* transport_message_header = (MPTransportMessageHeader*)msg->content;
        
        if (transport_message_header->type >= MAX_TYPE)
        {
            MPTransportLog("Invalid message type received\n");
            return;
        }

        auto deserialize_func = get_event_deserialization_function(transport_message_header->pub_id, transport_message_header->event_id);
        if (!deserialize_func)
        {
            MPTransportLog("No deserialization function found for event: type %d, id %d\n", transport_message_header->type, transport_message_header->event_id);
            return;
        }

        DataEvent* internal_event = nullptr;
        (deserialize_func)((const char*)(msg->content + sizeof(MPTransportMessageHeader)), transport_message_header->data_length, internal_event);
        MPEventInfo event(std::shared_ptr<DataEvent> (internal_event), transport_message_header->event_id, transport_message_header->pub_id);

        (transport_receive_handler)(event);
        dynamic_transport_stats.received_events++;
        dynamic_transport_stats.received_bytes += sizeof(MPTransportMessageHeader) + transport_message_header->data_length;
    }
    delete msg;
}

void MPUnixDomainTransport::handle_new_connection(UnixDomainConnector *connector, UnixDomainConnectorConfig* cfg, const unsigned short& channel_id)
{
    assert(connector);
    assert(cfg);

    std::lock_guard<std::shared_mutex> guard(_connection_update_mutex);

    if(!this->is_running.load())
        return;

    dynamic_transport_stats.successful_connections++;

    auto side_channel = new SideChannel(ScMsgFormat::BINARY);
    side_channel->connector_receive = connector;
    side_channel->connector_transmit = side_channel->connector_receive;
    side_channel->register_receive_handler(std::bind(&MPUnixDomainTransport::side_channel_receive_handler, this, std::placeholders::_1));
    connector->set_message_received_handler(std::bind(&MPUnixDomainTransport::notify_process_thread, this));
    this->side_channels.push_back(new SideChannelHandle(side_channel, cfg, channel_id+this->side_channels.size()-mp_current_process_id+1));
    connector->set_update_handler(std::bind(&MPUnixDomainTransport::connector_update_handler, this, std::placeholders::_1, std::placeholders::_2, side_channel));
    connector->start_receive_thread();
}

MPUnixDomainTransport::MPUnixDomainTransport(MPUnixDomainTransportConfig *c, MPUnixTransportStats& stats) : MPTransport(), 
    config(c), transport_stats(stats)
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
        dynamic_transport_stats.send_errors++;
        MPTransportLog("No serialize function found for event %d\n", event.type);
        return false;
    }

    MPTransportMessage transport_message;
    transport_message.header.type = EVENT_MESSAGE;
    transport_message.header.pub_id = event.pub_id;
    transport_message.header.event_id = event.type;
    

    (serialize_func)(event.event.get(), transport_message.data, &transport_message.header.data_length);
    {
        std::shared_lock<std::shared_mutex> guard(_connection_update_mutex);

        for (auto &&sc_handler : this->side_channels)
        {
            auto msg = sc_handler->side_channel->alloc_transmit_message(sizeof(MPTransportMessageHeader) + transport_message.header.data_length);
            memcpy(msg->content, &transport_message, sizeof(MPTransportMessageHeader));
            memcpy(msg->content + sizeof(MPTransportMessageHeader), transport_message.data, transport_message.header.data_length);
            auto send_result = sc_handler->side_channel->transmit_message(msg);
            if (!send_result)
            {
                MPTransportLog("Failed to send message to side channel\n");
                dynamic_transport_stats.send_errors++;
            }
            else
            {
                dynamic_transport_stats.sent_events++;
                dynamic_transport_stats.sent_bytes += sizeof(MPTransportMessageHeader) + transport_message.header.data_length;
            }
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
    this->event_helpers[pub_id].serialize_functions.insert({event_id, std::move(helper)});
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
            std::shared_lock<std::shared_mutex> guard(_connection_update_mutex);
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

void MPUnixDomainTransport::connector_update_handler(UnixDomainConnector *connector, bool is_reconecting, SideChannel *side_channel)
{
    if (this->is_running == false)
        return;
    std::lock_guard<std::shared_mutex> guard(_connection_update_mutex);
    
    if (side_channel->connector_receive)
    {
        delete side_channel->connector_receive;
        side_channel->connector_receive = side_channel->connector_transmit = nullptr;
    }

    if (connector)
    {
        connector->set_message_received_handler(std::bind(&MPUnixDomainTransport::notify_process_thread, this));
        side_channel->connector_receive = side_channel->connector_transmit = connector;
        connector->start_receive_thread();
        this->dynamic_transport_stats.successful_connections++;
    }
    else
    {
        if (is_reconecting == false)
        {
            MPTransportLog("Accepted connection interrupted, removing handle\n");
            for(auto it = this->side_channels.begin(); it != this->side_channels.end(); ++it)
            {
                if ((*it)->side_channel == side_channel)
                {
                    delete *it;
                    this->side_channels.erase(it);
                    break;
                }
            }
            this->dynamic_transport_stats.closed_connections++;
        }
        else
        {
            this->dynamic_transport_stats.connection_retries++;
        }
    }
}

void MPUnixDomainTransport::MPTransportLog(const char *msg, ...)
{
    if (!is_logging_enabled_flag)
        return;

    char buf[256];
    va_list args;
    va_start(args, msg);
    vsnprintf(buf, sizeof(buf), msg, args);
    va_end(args);

    LogMessage("%s ID=%d %s", MP_TRANSPORT_LOG_LABEL, mp_current_process_id, buf);
}

MPSerializeFunc MPUnixDomainTransport::get_event_serialization_function(unsigned pub_id, unsigned event_id)
{
    auto helper_it = this->event_helpers.find(pub_id);
    if (helper_it == this->event_helpers.end())
    {
        MPTransportLog("No available helper functions is registered for %d\n", pub_id);
        return nullptr;
    }
    auto helper_functions = helper_it->second.get_function_set(event_id);
    if (!helper_functions)
    {
        MPTransportLog("No serialize function found for event %d\n", event_id);
        return nullptr;
    }
    return helper_functions->serializer;
}

MPDeserializeFunc MPUnixDomainTransport::get_event_deserialization_function(unsigned pub_id, unsigned event_id)
{
    auto helper_it = this->event_helpers.find(pub_id);
    if (helper_it == this->event_helpers.end())
    {
        MPTransportLog("No available helper functions is registered for %d\n", pub_id);
        return nullptr;
    }
    auto helper_functions = helper_it->second.get_function_set(event_id);
    if (!helper_functions)
    {
        MPTransportLog("No serialize function found for event %d\n", event_id);
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

    if (this->is_running.load())
        return;

    auto instance_id = mp_current_process_id = Snort::get_process_id();//Snort instance id

    this->is_running = true;

    struct stat st;
    if (::stat(config->unix_domain_socket_path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
    {
        if (mkdir(config->unix_domain_socket_path.c_str(), 0755) != 0)
        {
            MPTransportLog("Failed to create directory %s\n", config->unix_domain_socket_path.c_str());
            return;
        }
    }

    if (instance_id < config->max_processes)
    {
        auto listen_path = config->unix_domain_socket_path + UNIX_SOCKET_NAME_PREFIX + std::to_string(instance_id);

        auto unix_listener = new UnixDomainConnectorListener(listen_path.c_str());
        
        UnixDomainConnectorConfig* unix_config = new UnixDomainConnectorConfig();
        unix_config->setup = UnixDomainConnectorConfig::Setup::ANSWER;
        unix_config->async_receive = false;
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

        unix_listener->start_accepting_connections( std::bind(&MPUnixDomainTransport::handle_new_connection, this, std::placeholders::_1, std::placeholders::_2, instance_id+1), unix_config);

        auto unix_listener_handle = new UnixAcceptorHandle();
        unix_listener_handle->connector_config = unix_config;
        unix_listener_handle->listener = unix_listener;
        this->accept_handlers.push_back(unix_listener_handle);
    }

    for (unsigned short i = 1; i < instance_id; i++)
    {
        auto side_channel = new SideChannel(ScMsgFormat::BINARY);
        side_channel->register_receive_handler([this](SCMessage* msg) { this->side_channel_receive_handler(msg); });

        auto send_path = config->unix_domain_socket_path + UNIX_SOCKET_NAME_PREFIX + std::to_string(i);

        UnixDomainConnectorConfig* connector_conf = new UnixDomainConnectorConfig();
        connector_conf->setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_conf->async_receive = false;
        connector_conf->conn_retries = config->conn_retries;
        connector_conf->retry_interval = config->retry_interval_seconds;
        connector_conf->max_retries = config->max_retries;
        connector_conf->connect_timeout_seconds = config->connect_timeout_seconds;
        connector_conf->paths.push_back(send_path);

        UnixDomainConnectorReconnectHelper* reconnect_helper = new UnixDomainConnectorReconnectHelper(*connector_conf, 
            std::bind(&MPUnixDomainTransport::connector_update_handler, this, std::placeholders::_1, std::placeholders::_2, side_channel));

        reconnect_helper->connect(send_path.c_str(), 0);
        
        this->side_channels.push_back( new SideChannelHandle(side_channel, connector_conf, i, reconnect_helper));
    }

    assert(!this->consume_thread);
    this->consume_thread = new std::thread(&MPUnixDomainTransport::process_messages_from_side_channels, this);
}

void MPUnixDomainTransport::cleanup_side_channels()
{
    std::lock_guard<std::shared_mutex> guard(_connection_update_mutex);

    for (uint32_t i = 0; i < this->side_channels.size(); i++)
    {
        delete this->side_channels[i];
    }

    this->side_channels.clear();
}

SideChannelHandle::~SideChannelHandle()
{
    if(reconnect_helper)
        reconnect_helper->set_reconnect_enabled(false);

    if (side_channel)
    {
        if (side_channel->connector_receive)
            delete side_channel->connector_receive;

        delete side_channel;
    }

    if(reconnect_helper)
        delete reconnect_helper;
    
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

MPUnixTransportStats MPUnixDomainTransport::get_stats_copy()
{
    std::shared_lock<std::shared_mutex> _guard(_connection_update_mutex);
    return this->transport_stats;
}

void MPUnixDomainTransport::sum_stats()
{
    std::lock_guard<std::shared_mutex> _guard(_connection_update_mutex);
    this->transport_stats = this->dynamic_transport_stats;
}

void MPUnixDomainTransport::reset_stats()
{
    std::lock_guard<std::shared_mutex> _guard(_connection_update_mutex);
    this->dynamic_transport_stats = MPUnixTransportStats();
    this->transport_stats = MPUnixTransportStats();
}

MPTransportChannelStatusHandle *MPUnixDomainTransport::get_channel_status(unsigned& size)
{
    std::shared_lock<std::shared_mutex> _guard(_connection_update_mutex);
    MPTransportChannelStatusHandle* result = new MPTransportChannelStatusHandle[this->config->max_processes-1];

    size = this->config->max_processes-1;

    for (auto &&sc_handler : this->side_channels)
    {
        unsigned short idx = sc_handler->channel_id > mp_current_process_id ? sc_handler->channel_id-2 : sc_handler->channel_id-1;
        result[idx].id = sc_handler->channel_id;
        result[idx].status = sc_handler->side_channel->connector_receive ? MPTransportChannelStatus::CONNECTED : MPTransportChannelStatus::CONNECTING;
        result[idx].name = "Snort connection to instance " + std::to_string(sc_handler->channel_id);
    }

    for(uint16_t it = 0; it < this->config->max_processes-1; it++)
    {
        if(result[it].id != 0)
            continue;
        result[it].id = it + 2 > mp_current_process_id ? it + 2 : it + 1;
        result[it].status = result[it].id > mp_current_process_id ? MPTransportChannelStatus::ACCEPTING : MPTransportChannelStatus::DISCONNECTED;
        result[it].name = "Snort connection to instance " + std::to_string(result[it].id);
    }

    return result;
}

}
