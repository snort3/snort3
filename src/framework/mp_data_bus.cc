//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// mp_data_bus.cc author Umang Sharma <umasharm@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mp_data_bus.h"

#include <algorithm>
#include <unordered_map>

#include "framework/module.h"
#include "framework/pig_pen.h"
#include "helpers/ring.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "managers/mp_transport_manager.h"
#include "managers/plugin_manager.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

void MPDataBusLog(const char* msg, ...);

uint32_t MPDataBus::mp_max_eventq_size = DEFAULT_MAX_EVENTQ_SIZE;
std::string MPDataBus::transport = DEFAULT_TRANSPORT;
bool MPDataBus::enable_debug = false;
MPTransport* MPDataBus::transport_layer = nullptr;
MPDataBusStats MPDataBus::mp_global_stats = {};
#ifdef REG_TEST
bool MPDataBus::hold_events = false;
#endif

static std::unordered_map<std::string, unsigned> mp_pub_ids;
static std::mutex mp_stats_mutex;
static uint32_t mp_current_process_id = 0;

void MPDataBusLog(const char* msg, ...)
{
    if (!MPDataBus::enable_debug)
        return;

    char buf[256];
    va_list args;
    va_start(args, msg);
    vsnprintf(buf, sizeof(buf), msg, args);
    va_end(args);

    LogMessage("MPDataBusDbg ID=%d %s", mp_current_process_id, buf);
}

//--------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

MPDataBus::MPDataBus() :
    run_thread(true),
    worker_thread(nullptr)
{
    mp_event_queue = new MPEventQueue(mp_max_eventq_size);
    start_worker_thread();
}

MPDataBus::~MPDataBus()
{
    stop_worker_thread();

    for (auto& [_, sublist] : mp_pub_sub)
    {
        for (auto* handler : sublist)
            delete handler;

        sublist.clear();
    }
    mp_pub_sub.clear();
    delete mp_event_queue;
    mp_event_queue = nullptr;
}

unsigned MPDataBus::init(int max_procs)
{
    if (max_procs <= 1)
    {
        return 1;
    }

    mp_current_process_id = Snort::get_process_id();

    transport_layer = MPTransportManager::get_transport(transport);
    if (transport_layer == nullptr)
    {
        ErrorMessage("MPDataBus: Failed to get transport layer\n");
        return 1;
    }

    transport_layer->register_receive_handler(std::bind(&MPDataBus::receive_message, this, std::placeholders::_1));
    transport_layer->init_connection();

    return 0;
}

unsigned MPDataBus::get_id(const PubKey& key)
{
    // Generate a unique hash for the publisher's name, 
    std::hash<std::string> hasher;
    unsigned unique_id = (hasher(key.publisher) % 10000);

    auto it = mp_pub_ids.find(key.publisher);

    if (it == mp_pub_ids.end())
    {
        // Map the unique hash to the publisher
        mp_pub_ids[key.publisher] = unique_id;
    }
    // Return the unique ID for the publisher
    return mp_pub_ids[key.publisher];
}

const char* MPDataBus::get_name_from_id(unsigned id)
{
    for (const auto& [name, pub_id] : mp_pub_ids)
    {
        if (pub_id == id)
        {
            return name.c_str();
        }
    }
    return nullptr;
}

bool MPDataBus::is_ready()
{
    const SnortConfig* sc = SnortConfig::get_conf();
    return sc && sc->mp_dbus;
}

void MPDataBus::subscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc or !sc->mp_dbus)
    {
        ErrorMessage("MPDataBus: MPDataBus not initialized\n");
        return;
    }

    sc->mp_dbus->_subscribe(key, eid, h);
    MPDataBusLog("Subscribed to event ID %u\n", eid);
}

void MPDataBus::unsubscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc or !sc->mp_dbus)
    {
        ErrorMessage("MPDataBus: MPDataBus not initialized\n");
        return;
    }

    sc->mp_dbus->_unsubscribe(key, eid, h);
    MPDataBusLog("Unsubscribed from event ID %u\n", eid);
}

bool MPDataBus::publish(unsigned pub_id, unsigned evt_id, std::shared_ptr<DataEvent> e, Flow*)
{
    std::shared_ptr<MPEventInfo> event_info = 
                std::make_shared<MPEventInfo>(std::move(e), MPEventType(evt_id), pub_id);

    const SnortConfig *sc = SnortConfig::get_conf();
    if (!sc or !sc->mp_dbus)
    {
        ErrorMessage("MPDataBus: MPDataBus not initialized\n");
        return false;
    }

    if (!sc->mp_dbus->_enqueue_event(std::move(event_info)))
    {
        ErrorMessage("MPDataBus: Failed to enqueue event for publisher ID %u and event ID %u\n", pub_id, evt_id);
        return false;
    }

    MPDataBusLog("Event published for publisher ID %u and event ID %u\n", pub_id, evt_id);

    return true;
}

void MPDataBus::register_event_helpers(const PubKey& key, unsigned evt_id, MPSerializeFunc& mp_serializer_helper, MPDeserializeFunc& mp_deserializer_helper)
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc or !sc->mp_dbus or !sc->mp_dbus->transport_layer)
    {
        ErrorMessage("MPDataBus: MPDataBus or transport layer not initialized\n");
        return;
    }

    unsigned pub_id = get_id(key);

    MPHelperFunctions helpers(mp_serializer_helper, mp_deserializer_helper);
    
    sc->mp_dbus->transport_layer->register_event_helpers(pub_id, evt_id, helpers);
    MPDataBusLog("Registered event helpers for event ID %u\n", evt_id);
}

// API for receiving the DataEvent and Event type from transport layer
void MPDataBus::receive_message(const MPEventInfo& event_info)
{
    DataEvent *e = event_info.event.get();
    unsigned evt_id = event_info.type;
    unsigned pub_id = event_info.pub_id;

    MPDataBusLog("Received message for publisher ID %u and event ID %u\n", pub_id, evt_id);

    auto pub_res = _publish(pub_id, evt_id, *e, nullptr);

    {
        std::lock_guard<std::mutex> lock(mp_stats_mutex);
        mp_pub_stats[pub_id].total_messages_received++;
        if(pub_res)
        {
            mp_pub_stats[pub_id].total_messages_delivered++;
        }
    }
}


//--------------------------------------------------------------------------
// private methods
//--------------------------------------------------------------------------
void MPDataBus::process_event_queue()
{
#ifdef REG_TEST
    if (hold_events)
    {
        return;
    }
#endif
    if (!mp_event_queue) {
        return;
    }

    std::unique_lock<std::mutex> u_lock(queue_mutex);

    // coverity[wait_not_in_locked_loop:FALSE]
    if( (std::cv_status::timeout == queue_cv.wait_for(u_lock, std::chrono::milliseconds(WORKER_THREAD_SLEEP))) and
        mp_event_queue->is_empty() )
        return;

    
    static std::shared_ptr<MPEventInfo> event_info;
    
    while (mp_event_queue->try_pop(event_info))
    {
        if (UNLIKELY(!transport_layer))
        {
            run_thread.store(false);
            ErrorMessage("MPDataBus: Transport layer not initialized\n");
            return;
        }
        
            MPDataBusLog("Processing event for publisher ID %u \n", event_info->pub_id);
            auto send_res = transport_layer->send_to_transport(*event_info);
            {
                std::lock_guard<std::mutex> lock(mp_stats_mutex);
                mp_pub_stats[event_info->pub_id].total_messages_published++;
                if (!send_res)
                {
                    mp_pub_stats[event_info->pub_id].total_messages_dropped++;
                }
                else
                {
                    mp_pub_stats[event_info->pub_id].total_messages_sent++;
                }
            }
        
    }
}

void MPDataBus::worker_thread_func()
{
    while (run_thread.load() ) {
        process_event_queue();
    }
}

void MPDataBus::start_worker_thread()
{
    run_thread.store(true);
    worker_thread = std::make_unique<std::thread>(&MPDataBus::worker_thread_func, this);
}

void MPDataBus::stop_worker_thread()
{
    run_thread.store(false);
    queue_cv.notify_one();

    if (worker_thread && worker_thread->joinable())
    {
        worker_thread->join();
    }

    worker_thread.reset();
}

static bool compare(const DataHandler* a, const DataHandler* b)
{
    if ( a->order and b->order )
        return a->order < b->order;

    if ( a->order )
        return true;

    return false;
}

void snort::MPDataBus::set_debug_enabled(bool flag)
{
    enable_debug = flag;
    if(transport_layer)
    {
        if(flag)
        {
            transport_layer->enable_logging();
        }
        else
        {
            transport_layer->disable_logging();
        }
    }
}

MPDataBusStats MPDataBus::get_stats_copy()
{
    sum_stats();
    {
        std::lock_guard<std::mutex> lock(mp_stats_mutex);
        return mp_global_stats;
    }
}

void MPDataBus::sum_stats()
{
    std::lock_guard<std::mutex> lock(mp_stats_mutex);

    mp_global_stats.total_messages_sent = 0;
    mp_global_stats.total_messages_received = 0;
    mp_global_stats.total_messages_dropped = 0;
    mp_global_stats.total_messages_published = 0;
    mp_global_stats.total_messages_delivered = 0;

    for(auto& [_, pub_stats] : mp_pub_stats)
    {
        mp_global_stats.total_messages_dropped += pub_stats.total_messages_dropped;
        mp_global_stats.total_messages_published += pub_stats.total_messages_published;
        mp_global_stats.total_messages_received += pub_stats.total_messages_received;
        mp_global_stats.total_messages_sent += pub_stats.total_messages_sent;
        mp_global_stats.total_messages_delivered += pub_stats.total_messages_delivered;
    }
}

void MPDataBus::reset_stats()
{
    {
        std::lock_guard<std::mutex> lock(mp_stats_mutex);

        for(auto& [_, pub_stats] : mp_pub_stats)
        {
            pub_stats.total_messages_sent = 0;
            pub_stats.total_messages_received = 0;
            pub_stats.total_messages_dropped = 0;
            pub_stats.total_messages_published = 0;
            pub_stats.total_messages_delivered = 0;
        }

        mp_global_stats.total_messages_sent = 0;
        mp_global_stats.total_messages_received = 0;
        mp_global_stats.total_messages_dropped = 0;
        mp_global_stats.total_messages_published = 0;
        mp_global_stats.total_messages_delivered = 0;
    }

    if (auto transport_module = PigPen::get_module(transport.c_str()))
        transport_module->reset_stats();
}

void MPDataBus::dump_stats(ControlConn *ctrlconn, const char *module_name)
{
    set_log_conn(ctrlconn);
    if (module_name)
    {
        auto mod_id = mp_pub_ids.find(module_name);
        if (mod_id == mp_pub_ids.end())
        {
            return;
        }
        std::lock_guard<std::mutex> lock(mp_stats_mutex);
        auto mod_stats = mp_pub_stats[mod_id->second];

        LogMessage("MPDataBus Stats for %s\n", module_name);
        show_stats(reinterpret_cast<PegCount*>(&mod_stats), mp_databus_pegs, array_size(mp_databus_pegs)-1);
    }
    else
    {
        sum_stats();
        
        show_stats(reinterpret_cast<PegCount*>(&mp_global_stats), mp_databus_pegs, array_size(mp_databus_pegs)-1);

        if (auto transport_module = PigPen::get_module(transport.c_str()))
        {
            auto transport_pegs = transport_module->get_pegs();
            if(transport_pegs)
            {
                transport_module->sum_stats(false);
                uint32_t size = 0;
                while(transport_pegs[size].type != CountType::END)
                {
                    size++;
                }
                show_stats(transport_module->get_counts(), transport_pegs, size);
            }
        }
    }
    set_log_conn(nullptr);
}

void MPDataBus::dump_events(ControlConn *ctrlconn, const char *module_name)
{
    uint32_t current_read_idx = 0;
    uint32_t ring_items = mp_event_queue->size();
    if(ring_items == 0)
    {
        if (ctrlconn)
        {
            ctrlconn->respond("No events in the event queue\n");
        }
        else
        {
            LogMessage("No events in the event queue\n");
        }
        return;
    }
    auto event_queue_buffer = mp_event_queue->get_buffer(current_read_idx);

    for (uint32_t i = current_read_idx; i <= ring_items; i++)
    {
        if(i >= mp_max_eventq_size)
        {
            i = 0;
            ring_items -= mp_max_eventq_size;
        }
        auto event_info = event_queue_buffer[i].data;
        if (event_info)
        {
            if (module_name)
            {
                if (event_info->pub_id != mp_pub_ids[module_name])
                {
                    continue;
                }
            }
            if (ctrlconn)
            {
                ctrlconn->respond("Publisher module: %s, Event ID: %u\n", get_name_from_id(event_info->pub_id), event_info->type);
            }
            else
            {
                LogMessage("Publisher module: %s, Event ID: %u\n", get_name_from_id(event_info->pub_id), event_info->type);
            }
        }
    }
}

void snort::MPDataBus::show_channel_status(ControlConn *ctrlconn)
{
    if(!transport_layer or !ctrlconn)
    {
        return;
    }

    unsigned int size = 0;
    auto transport_status = transport_layer->get_channel_status(size);
    if (size == 0)
    {
        ctrlconn->respond("No active connections\n");
        return;
    }
    std::string response;
    for (unsigned int i = 0; i < size; i++)
    {
        const auto& channel = transport_status[i];
        // coverity[missing_lock:SUPPRESS]
        response += "Channel ID: " + std::to_string(channel.id) + ", Name: " + channel.name + ", Status: " + channel.get_status_string() + "\n";
    }

    ctrlconn->respond("%s", response.c_str());
    delete[] transport_status;
}

void MPDataBus::_subscribe(unsigned pid, unsigned eid, DataHandler *h)
{
    std::pair<unsigned, unsigned> key = {pid, eid};

    SubList& subs = mp_pub_sub[key];
    subs.emplace_back(h);

    std::sort(subs.begin(), subs.end(), compare);
}

void MPDataBus::_subscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    unsigned pid = get_id(key);
    _subscribe(pid, eid, h);
}

void MPDataBus::_unsubscribe(unsigned pid, unsigned eid, DataHandler* h)
{
    std::pair<unsigned, unsigned> key = {pid, eid};

    auto it = mp_pub_sub.find(key);
    if (it == mp_pub_sub.end())
    {
        MPDataBusLog("No subscribers found for publisher ID %u and event ID %u\n", pid, eid);
        return;
    }

    SubList& subs = it->second;
    auto handler_it = std::find(subs.begin(), subs.end(), h);
    if (handler_it != subs.end())
    {
        subs.erase(handler_it);

        delete h;
        MPDataBusLog("Handler unsubscribed and deleted for publisher ID %u and event ID %u\n", pid, eid);
        
        if (subs.empty())
        {
            mp_pub_sub.erase(it);
        }
    }
}

void MPDataBus::_unsubscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    unsigned pid = get_id(key);
    _unsubscribe(pid, eid, h);
}

bool MPDataBus::_publish(unsigned pid, unsigned eid, DataEvent& e, Flow* f)
{
    std::pair<unsigned, unsigned> key = {pid, eid};

    auto it = mp_pub_sub.find(key);
    if (it == mp_pub_sub.end())
    {
        MPDataBusLog("No subscribers for publisher ID %u and event ID %u\n", pid, eid);
        return false;
    }
    const SubList& subs = it->second;

    for (auto* handler : subs)
    {
        handler->handle(e, f);
    }

    return true;
}

bool snort::MPDataBus::_enqueue_event(std::shared_ptr<MPEventInfo> ev_info)
{
    bool res = mp_event_queue != nullptr and mp_event_queue->try_push(std::move(ev_info));
    if(res) queue_cv.notify_one();
    return res;
}
