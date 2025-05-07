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
// mp_data_bus.h author Umang Sharma <umasharm@cisco.com>

#ifndef MP_DATA_BUS_H
#define MP_DATA_BUS_H

// The MPDataBus class is a multiprocess version of the DataBus class.
// It is used to publish and subscribe to DataEvents in a multiprocess environment
// and to synchronize between processes. When a Snort instance generates an event that needs
// to be synchronized with other Snort processes, it publishes the event to the MPDataBus.
// The MPDataBus then notifies all other Snort instances that have subscribed to the event
// with a transport channel.
// DataEvents are generated to synchronize between processes in a multiprocess environment.
// They can be used to notify peer Snort processes that are subscribed to relevant events.
// By using DataEvents with a publish-subscribe mechanism, modules can subscribe to events
// from peer Snort processes to communicate with each other in a multiprocess environment.

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <thread>
#include <bitset>

#include "control/control.h"
#include "framework/mp_transport.h"
#include "framework/counts.h"
#include "main/snort_types.h"
#include "data_bus.h"

#define DEFAULT_TRANSPORT "unix_transport"
#define DEFAULT_MAX_EVENTQ_SIZE 1000
#define WORKER_THREAD_SLEEP 100

template <typename T>
class Ring;

namespace snort
{
class Flow;
struct Packet;
struct SnortConfig;

struct MPDataBusStats
{
    MPDataBusStats() :
        total_messages_sent(0),
        total_messages_received(0),
        total_messages_dropped(0),
        total_messages_published(0),
        total_messages_delivered(0)
    { }

    PegCount total_messages_sent;
    PegCount total_messages_received;
    PegCount total_messages_dropped;
    PegCount total_messages_published;
    PegCount total_messages_delivered;
};

static const PegInfo mp_databus_pegs[] =
{
    { CountType::SUM, "total_messages_sent", "total messages sent" },
    { CountType::SUM, "total_messages_received", "total messages received" },
    { CountType::SUM, "total_messages_dropped", "total messages dropped" },
    { CountType::SUM, "total_messages_published", "total messages published" },
    { CountType::SUM, "total_messages_delivered", "total messages delivered" },
    { CountType::END, nullptr, nullptr },
};

typedef bool (*MPSerializeFunc)(DataEvent* event, char*& buffer, uint16_t* length);
typedef bool (*MPDeserializeFunc)(const char* buffer, uint16_t length, DataEvent*& event);

// Similar to the DataBus class, the MPDataBus class uses uses a combination of PubKey and event ID
// for event subscriptions and publishing. New MP-specific event type enums should be added to the
// appropriate header files in the pub_sub directory. For example, an <module>MPEventIds enum might
// be created in parallel to a pre-existing <module>EventIds enum. The same pub_key can be reused.
// New MP-specific DataEvent structures should similarly be populated in the pub_sub directory in a
// manner analogous to the approach used for intra-snort pub_sub.
typedef unsigned MPEventType;

struct MPEventInfo
{
    unsigned pub_id;
    MPEventType type;
    std::shared_ptr<DataEvent> event;
    MPEventInfo(std::shared_ptr<DataEvent> e, MPEventType t, unsigned id = 0)
        : pub_id(id), type(t), event(std::move(e)) {}
};

struct MPHelperFunctions {
    MPSerializeFunc serializer;
    MPDeserializeFunc deserializer;
    
    MPHelperFunctions(MPSerializeFunc s, MPDeserializeFunc d) 
        : serializer(s), deserializer(d) {}
};

struct pair_hash
{
    template <class T1, class T2>
    std::size_t operator()(const std::pair<T1, T2>& pair) const
    {
        std::hash<T1> hash1;
        std::hash<T2> hash2;
        return hash1(pair.first) ^ (hash2(pair.second) << 1);
    }
};

class SO_PUBLIC MPDataBus
{ 
public: 
    MPDataBus();
    ~MPDataBus();
    
    static uint32_t mp_max_eventq_size;
    static std::string transport;
    static bool enable_debug;
#ifdef REG_TEST
    static bool hold_events;
#endif

    static MPTransport * transport_layer;
    static MPDataBusStats mp_global_stats;
    unsigned init(int);
    void clone(MPDataBus& from, const char* exclude_name = nullptr);

    static unsigned get_id(const PubKey& key);
    static const char* get_name_from_id(unsigned id);

    static bool valid(unsigned pub_id)
    { return pub_id != 0; }

    static void subscribe(const PubKey& key, unsigned id, DataHandler* handler); 

    // API for publishing the DataEvent to the peer Snort processes
    // The user needs to pass a shared_ptr to the DataEvent object as the third argument
    // This is to ensure that the DataEvent object is not deleted before it is published
    // or consumed by the worker thread
    // and the shared_ptr will handle the memory management by reference counting
    static bool publish(unsigned pub_id, unsigned evt_id, std::shared_ptr<DataEvent> e, Flow* f = nullptr);

    // The user needs to pass the MPSerializeFunc and MPDeserializeFunc function pointers
    // to the register_event_helpers function, which will be used to serialize and deserialize
    // before publishing any events to the MPDataBus
    static void register_event_helpers(const PubKey& key, unsigned evt_id, MPSerializeFunc& mp_serializer_helper, MPDeserializeFunc& mp_deserializer_helper);
    // API for receiving the DataEvent and Event type from transport layer using EventInfo
    void receive_message(const MPEventInfo& event_info);

    Ring<std::shared_ptr<MPEventInfo>>* get_event_queue()
    { return mp_event_queue; }

    void set_debug_enabled(bool flag);

    void sum_stats();

    void dump_stats(ControlConn* ctrlconn, const char* module_name);
    void dump_events(ControlConn* ctrlconn, const char* module_name);
    void show_channel_status(ControlConn* ctrlconn);

private: 
    void _subscribe(unsigned pid, unsigned eid, DataHandler* h);
    void _subscribe(const PubKey& key, unsigned eid, DataHandler* h);

    bool _publish(unsigned pid, unsigned eid, DataEvent& e, Flow* f);
    bool _enqueue_event(std::shared_ptr<MPEventInfo> ev_info);

private:
    typedef std::vector<DataHandler*> SubList;

    std::unordered_map<std::pair<unsigned, unsigned>, SubList, pair_hash> mp_pub_sub;

    std::atomic<bool> run_thread;
    std::unique_ptr<std::thread> worker_thread;

    Ring<std::shared_ptr<MPEventInfo>>* mp_event_queue;

    std::condition_variable queue_cv;
    std::mutex queue_mutex;

    std::unordered_map<unsigned, MPDataBusStats> mp_pub_stats;

    void start_worker_thread();
    void stop_worker_thread();
    void worker_thread_func();
    void process_event_queue();
};
};

#endif

