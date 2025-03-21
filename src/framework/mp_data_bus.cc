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

using namespace snort;

static std::unordered_map<std::string, unsigned> mp_pub_ids;

//--------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

MPDataBus::MPDataBus() = default;

MPDataBus::~MPDataBus()
{
    // Clean up mp_pub_sub
    for (auto& sublist : mp_pub_sub)
    {
        for (auto* handler : sublist)
        {
            if (handler->cloned)
                handler->cloned = false;
            else
                delete handler;
        }
        sublist.clear();
    }
    mp_pub_sub.clear();
}

unsigned MPDataBus::init(int max_procs)
{
    UNUSED(max_procs);
    return 0;
}

void MPDataBus::clone(MPDataBus& from, const char* exclude_name)
{ 
    UNUSED(from);
    UNUSED(exclude_name);
}

// module subscribes to an event from a peer snort process
void MPDataBus::subscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    UNUSED(key);
    UNUSED(eid);
    UNUSED(h);
}

// publish event to all peer snort processes subscribed to the event
bool MPDataBus::publish(unsigned pub_id, unsigned evt_id, DataEvent& e, Flow* f) 
{
    // Publish implementation
    UNUSED(pub_id);
    UNUSED(evt_id);
    UNUSED(e);
    UNUSED(f);
    return true;
}

// register event helpers for serialization and deserialization of msg events
void MPDataBus::register_event_helpers(const PubKey& key, unsigned evt_id, MPSerializeFunc* mp_serializer_helper, MPDeserializeFunc* mp_deserializer_helper)
{
    UNUSED(key);
    UNUSED(evt_id);
    UNUSED(mp_serializer_helper);
    UNUSED(mp_deserializer_helper);
}

// API for receiving the DataEvent and Event type from transport layer
void MPDataBus::receive_message(const MPEventInfo& event_info)
{
    UNUSED(event_info);
}

//--------------------------------------------------------------------------
// private methods
//--------------------------------------------------------------------------

void MPDataBus::_subscribe(unsigned pid, unsigned eid, DataHandler* h)
{
    UNUSED(pid);
    UNUSED(eid);
    UNUSED(h);
}

void MPDataBus::_publish(unsigned int pid, unsigned int eid, DataEvent& e, Flow* f)
{
    UNUSED(pid);
    UNUSED(eid);
    UNUSED(e);
    UNUSED(f);
}

