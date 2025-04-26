//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_config.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "utils/stats.h"
#include "main/snort_types.h"
#include "log/messages.h"
#include "helpers/ring.h"
#include "managers/mp_transport_manager.h"

using namespace snort;

std::condition_variable MPDataBus::queue_cv;
std::mutex MPDataBus::queue_mutex;
uint32_t MPDataBus::mp_max_eventq_size = DEFAULT_MAX_EVENTQ_SIZE;
std::string MPDataBus::transport = DEFAULT_TRANSPORT;
bool MPDataBus::enable_debug = false;
MPTransport* MPDataBus::transport_layer = nullptr;

static std::unordered_map<std::string, unsigned> mp_pub_ids;

//--------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

MPDataBus::MPDataBus() : run_thread(true)
{
    mp_event_queue = new Ring<std::shared_ptr<MPEventInfo>>(mp_max_eventq_size);
    start_worker_thread();
}

MPDataBus::~MPDataBus()
{
    stop_worker_thread();

    for (auto& [key, sublist] : mp_pub_sub)
    {
        for (auto* handler : sublist)
        {
            if (handler->cloned)
            {
                handler->cloned = false;
            }
            else
            {
                delete handler; 
            }
        }
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

    transport_layer = MPTransportManager::get_transport(transport);
    if (transport_layer == nullptr)
    {
        ErrorMessage("MPDataBus: Failed to get transport layer\n");
        return 0;
    }

    transport_layer->register_receive_handler(std::bind(&MPDataBus::receive_message, this, std::placeholders::_1));
    transport_layer->init_connection();

    return 0;
}

void MPDataBus::clone(MPDataBus& from, const char* exclude_name)
{
    from.stop_worker_thread();
    for (const auto& [key, sublist] : from.mp_pub_sub)
    {
        unsigned pid = key.first; 
        unsigned eid = key.second;

        for (auto* h : sublist)
        {
            if (!exclude_name || strcmp(exclude_name, h->module_name) != 0)
            {
                h->cloned = true;
                _subscribe(pid, eid, h);
            }
        }
    }
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

void MPDataBus::subscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    if(! SnortConfig::get_conf()->mp_dbus)
    {
        ErrorMessage("MPDataBus: MPDataBus not initialized\n");
        return;
    }

    SnortConfig::get_conf()->mp_dbus->_subscribe(key, eid, h);
    MP_DATABUS_LOG("MPDataBus: Subscribed to event ID %u\n", eid);
}

bool MPDataBus::publish(unsigned pub_id, unsigned evt_id, std::shared_ptr<DataEvent> e, Flow*)
{
    std::shared_ptr<MPEventInfo> event_info = 
                std::make_shared<MPEventInfo>(std::move(e), MPEventType(evt_id), pub_id);

    const SnortConfig *sc = SnortConfig::get_conf();

    if (sc->mp_dbus == nullptr)
    {
        ErrorMessage("MPDataBus: MPDataBus not initialized\n");
        return false;
    }

    if (sc->mp_dbus->mp_event_queue != nullptr and !sc->mp_dbus->mp_event_queue->full() and !sc->mp_dbus->mp_event_queue->put(event_info)) {
        ErrorMessage("MPDataBus: Failed to enqueue event for publisher ID %u and event ID %u\n", pub_id, evt_id);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        queue_cv.notify_one();
    }

    MP_DATABUS_LOG("MPDataBus: Event published for publisher ID %u and event ID %u\n", pub_id, evt_id);

    return true;
}

void MPDataBus::register_event_helpers(const PubKey& key, unsigned evt_id, MPSerializeFunc& mp_serializer_helper, MPDeserializeFunc& mp_deserializer_helper)
{
    if (!SnortConfig::get_conf()->mp_dbus && !SnortConfig::get_conf()->mp_dbus->transport_layer)
    {
        ErrorMessage("MPDataBus: MPDataBus or transport layer not initialized\n");
        return;
    }

    unsigned pub_id = get_id(key);

    MPHelperFunctions helpers(mp_serializer_helper, mp_deserializer_helper);
    
    SnortConfig::get_conf()->mp_dbus->transport_layer->register_event_helpers(pub_id, evt_id, helpers);
    MP_DATABUS_LOG("MPDataBus: Registered event helpers for event ID %u\n", evt_id);
}

// API for receiving the DataEvent and Event type from transport layer
void MPDataBus::receive_message(const MPEventInfo& event_info)
{
    DataEvent *e = event_info.event.get();
    unsigned evt_id = event_info.type;
    unsigned pub_id = event_info.pub_id;

    MP_DATABUS_LOG("MPDataBus: Received message for publisher ID %u and event ID %u\n", pub_id, evt_id);

    _publish(pub_id, evt_id, *e, nullptr);
}


//--------------------------------------------------------------------------
// private methods
//--------------------------------------------------------------------------
void MPDataBus::process_event_queue()
{
    if (!mp_event_queue) {
        return;
    }

    std::unique_lock<std::mutex> lock(queue_mutex);

    queue_cv.wait_for(lock, std::chrono::milliseconds(WORKER_THREAD_SLEEP), [this]() {
        return mp_event_queue != nullptr && !mp_event_queue->empty();
    });

    lock.unlock();

    while (!mp_event_queue->empty()) {
        std::shared_ptr<MPEventInfo> event_info = mp_event_queue->get(nullptr);
        if (event_info) {
            MP_DATABUS_LOG("MPDataBus: Processing event for publisher ID %u \n",
                        event_info->pub_id);

            transport_layer->send_to_transport(*event_info);
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

static bool compare(DataHandler* a, DataHandler* b)
{
    if ( a->order and b->order )
        return a->order < b->order;

    if ( a->order )
        return true;

    return false;
}

void MPDataBus::_subscribe(unsigned pid, unsigned eid, DataHandler* h)
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


void MPDataBus::_publish(unsigned pid, unsigned eid, DataEvent& e, Flow* f)
{
    std::pair<unsigned, unsigned> key = {pid, eid};

    auto it = mp_pub_sub.find(key);
    if (it == mp_pub_sub.end())
    {
        MP_DATABUS_LOG("MPDataBus: No subscribers for publisher ID %u and event ID %u\n", pid, eid);
        return;
    }
    const SubList& subs = it->second;

    for (auto* handler : subs)
    {
        handler->handle(e, f);
    }
}

