//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// data_bus.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "data_bus.h"

#include <algorithm>
#include <unordered_map>

#include "main/policy.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "utils/stats.h"

using namespace snort;

static std::unordered_map<std::string, unsigned> pub_ids;
static unsigned next_event = 1;

static DataBus& get_data_bus()
{ return get_inspection_policy()->dbus; }

static DataBus& get_network_data_bus()
{ return get_network_policy()->dbus; }

class BufferEvent : public DataEvent
{
public:
    BufferEvent(const uint8_t* b, unsigned n)
    { buf = b; len = n; }

    const uint8_t* get_data(unsigned& n) override
    { n = len; return buf; }

private:
    const uint8_t* buf;
    unsigned len;
};

class PacketEvent : public DataEvent
{
public:
    PacketEvent(Packet* p)
    { packet = p; }

    const Packet* get_packet() const override
    { return packet; }

private:
    const Packet* packet;
};

//--------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

DataBus::DataBus() = default;

DataBus::~DataBus()
{
    for ( const auto& p : pub_sub )
    {
        for ( auto* h : p )
        {
            // If the object is cloned, pass the ownership to the next config.
            // When the object is no further cloned (e.g., the last config), delete it.
            if ( h->cloned )
                h->cloned = false;
            else
                delete h;
        }
    }
}

unsigned DataBus::init()
{
    unsigned id = get_id(intrinsic_pub_key);
    assert(id == 1);
    return id;
}

void DataBus::clone(DataBus& from, const char* exclude_name)
{
    for ( unsigned i = 0; i < from.pub_sub.size(); ++i )
    {
        for ( auto* h : from.pub_sub[i] )
        {
            if ( !exclude_name || strcmp(exclude_name, h->module_name) )
            {
                h->cloned = true;
                _subscribe(i, 0, h);
            }
        }
    }
}

unsigned DataBus::get_id(const PubKey& key)
{
    auto it = pub_ids.find(key.publisher);

    if ( it == pub_ids.end() )
    {
        pub_ids[key.publisher] = next_event;
        next_event += key.num_events;
    }
    return pub_ids[key.publisher];
}

// add handler to list of handlers to be notified upon
// publication of given event
void DataBus::subscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    get_data_bus()._subscribe(key, eid, h);
}

// for subscribers that need to receive events regardless of active inspection policy
void DataBus::subscribe_network(const PubKey& key, unsigned eid, DataHandler* h)
{
    get_network_data_bus()._subscribe(key, eid, h);
}

// for subscribers that need to receive events regardless of active inspection policy
void DataBus::subscribe_global(const PubKey& key, unsigned eid, DataHandler* h, SnortConfig& sc)
{
    sc.global_dbus->_subscribe(key, eid, h);
}

void DataBus::unsubscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    get_data_bus()._unsubscribe(key, eid, h);
}

void DataBus::unsubscribe_network(const PubKey& key, unsigned eid, DataHandler* h)
{
    get_network_data_bus()._unsubscribe(key, eid, h);
}

void DataBus::unsubscribe_global(const PubKey& key, unsigned eid, DataHandler* h, SnortConfig& sc)
{
    sc.global_dbus->_unsubscribe(key, eid, h);
}

// notify subscribers of event
void DataBus::publish(unsigned pid, unsigned eid, DataEvent& e, Flow* f)
{
    SnortConfig::get_conf()->global_dbus->_publish(pid, eid, e, f);

    NetworkPolicy* ni = get_network_policy();
    ni->dbus._publish(pid, eid, e, f);

    InspectionPolicy* pi = get_inspection_policy();
    pi->dbus._publish(pid, eid, e, f);
}

void DataBus::publish(unsigned pid, unsigned eid, const uint8_t* buf, unsigned len, Flow* f)
{
    BufferEvent e(buf, len);
    publish(pid, eid, e, f);
}

void DataBus::publish(unsigned pid, unsigned eid, Packet* p, Flow* f)
{
    PacketEvent e(p);
    if ( p && !f )
        f = p->flow;
    publish(pid, eid, e, f);
}

//--------------------------------------------------------------------------
// private methods
//--------------------------------------------------------------------------

static bool compare(DataHandler* a, DataHandler* b)
{
    if ( a->order and b->order )
        return a->order < b->order;

    if ( a->order )
        return true;

    return false;
}

void DataBus::_subscribe(unsigned pid, unsigned eid, DataHandler* h)
{
    unsigned idx = pid + eid;
    assert(idx < next_event);

    if ( next_event > pub_sub.size() )
        pub_sub.resize(next_event);

    SubList& subs = pub_sub[idx];
    subs.emplace_back(h);

    std::sort(subs.begin(), subs.end(), compare);
}

void DataBus::_subscribe(const PubKey& key, unsigned eid, DataHandler* h)
{
    unsigned pid = get_id(key);
    _subscribe(pid, eid, h);
}

void DataBus::_unsubscribe(const PubKey& key, unsigned eid, const DataHandler* h)
{
    unsigned pid = get_id(key);
    unsigned idx = pid + eid;
    assert(idx < pub_sub.size());

    SubList& subs = pub_sub[idx];

    for ( unsigned i = 0; i < subs.size(); i++ )
    {
        if ( subs[i] == h )
        {
            subs.erase(subs.begin() + i--);
            break;
        }
    }
}

void DataBus::_publish(unsigned pid, unsigned eid, DataEvent& e, Flow* f) const
{
    unsigned idx = pid + eid;

    // not all instances are full size
    if ( idx >= pub_sub.size() )
        return;

    const SubList& subs = pub_sub[idx];

    for ( auto* h : subs )
        h->handle(e, f);
}

