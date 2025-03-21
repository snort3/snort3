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
#include <queue>

#include "main/snort_types.h"
#include "data_bus.h"
#include <bitset>

namespace snort
{
class Flow;
struct Packet;
struct SnortConfig;

typedef bool (*MPSerializeFunc)(const DataEvent& event, char** buffer, size_t* length);
typedef bool (*MPDeserializeFunc)(const char* buffer, size_t length, DataEvent* event);

// Similar to the DataBus class, the MPDataBus class uses uses a combination of PubKey and event ID
// for event subscriptions and publishing. New MP-specific event type enums should be added to the
// appropriate header files in the pub_sub directory. For example, an <module>MPEventIds enum might
// be created in parallel to a pre-existing <module>EventIds enum. The same pub_key can be reused.
// New MP-specific DataEvent structures should similarly be populated in the pub_sub directory in a
// manner analogous to the approach used for intra-snort pub_sub.
typedef unsigned MPEventType;

struct MPEventInfo 
{
    MPEventType type;
    unsigned pub_id;
    DataEvent event;
    MPEventInfo(const DataEvent& e, MPEventType t, unsigned id = 0)
        : type(t), pub_id(id), event(e) {}
};

struct MPHelperFunctions {
    MPSerializeFunc* serializer;
    MPDeserializeFunc* deserializer;
    
    MPHelperFunctions(MPSerializeFunc* s, MPDeserializeFunc* d) 
        : serializer(s), deserializer(d) {}
};

class SO_PUBLIC MPDataBus
{ 
public: 
    MPDataBus(); 
    ~MPDataBus();

    static unsigned init(int);
    void clone(MPDataBus& from, const char* exclude_name = nullptr);

    unsigned get_id(const PubKey& key) 
    { return DataBus::get_id(key); }

    bool valid(unsigned pub_id)
    { return pub_id != 0; }

    void subscribe(const PubKey& key, unsigned id, DataHandler* handler); 

    bool publish(unsigned pub_id, unsigned evt_id, DataEvent& e, Flow* f = nullptr); 

    void register_event_helpers(const PubKey& key, unsigned evt_id, MPSerializeFunc* mp_serializer_helper, MPDeserializeFunc* mp_deserializer_helper);

    // API for receiving the DataEvent and Event type from transport layer using EventInfo
    void receive_message(const MPEventInfo& event_info);

private: 
    void _subscribe(unsigned pid, unsigned eid, DataHandler* h);
    void _publish(unsigned pid, unsigned eid, DataEvent& e, Flow* f);

private:
    typedef std::vector<DataHandler*> SubList;
    std::vector<SubList> mp_pub_sub;
};
}

#endif

