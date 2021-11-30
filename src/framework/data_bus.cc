//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

#include <algorithm>

#include "data_bus.h"

#include "main/policy.h"
#include "main/snort_config.h"
#include "protocols/packet.h"

using namespace snort;

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

    const Packet* get_packet() override
    { return packet; }

private:
    const Packet* packet;
};

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

DataBus::DataBus() = default;

DataBus::~DataBus()
{
    for ( auto& p : map )
        for ( auto* h : p.second )
        {
            // If the object is cloned, pass the ownership to the next config.
            // When the object is no further cloned (e.g., the last config), delete it.
            if ( h->cloned )
                h->cloned = false;
            else
                delete h;
        }
}

void DataBus::clone(DataBus& from, const char* exclude_name)
{
    for ( auto& p : from.map )
        for ( auto* h : p.second )
            if ( nullptr == exclude_name || 0 != strcmp(exclude_name, h->module_name) )
            {
                h->cloned = true;
                _subscribe(p.first.c_str(), h);
            }
}

// add handler to list of handlers to be notified upon
// publication of given event
void DataBus::subscribe(const char* key, DataHandler* h)
{
    get_data_bus()._subscribe(key, h);
}

// for subscribers that need to receive events regardless of active inspection policy
void DataBus::subscribe_network(const char* key, DataHandler* h)
{
    get_network_data_bus()._subscribe(key, h);
}

void DataBus::unsubscribe(const char* key, DataHandler* h)
{
    get_data_bus()._unsubscribe(key, h);
}

void DataBus::unsubscribe_network(const char* key, DataHandler* h)
{
    get_network_data_bus()._unsubscribe(key, h);
}

// notify subscribers of event
void DataBus::publish(const char* key, DataEvent& e, Flow* f)
{
    NetworkPolicy* ni = get_network_policy();
    ni->dbus._publish(key, e, f);

    InspectionPolicy* pi = get_inspection_policy();
    pi->dbus._publish(key, e, f);
}

void DataBus::publish(const char* key, const uint8_t* buf, unsigned len, Flow* f)
{
    BufferEvent e(buf, len);
    publish(key, e, f);
}

void DataBus::publish(const char* key, Packet* p, Flow* f)
{
    PacketEvent e(p);
    if ( p && !f )
        f = p->flow;
    publish(key, e, f);
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

void DataBus::_subscribe(const char* key, DataHandler* h)
{
    DataList& v = map[key];
    v.emplace_back(h);
    std::sort(v.begin(), v.end(), compare);
}

void DataBus::_unsubscribe(const char* key, DataHandler* h)
{
    DataList& v = map[key];

    for ( unsigned i = 0; i < v.size(); i++ )
        if ( v[i] == h )
            v.erase(v.begin() + i--);

    if ( v.empty() )
        map.erase(key);
}

// notify subscribers of event
void DataBus::_publish(const char* key, DataEvent& e, Flow* f)
{
    auto v = map.find(key);

    if ( v != map.end() )
    {
        for ( auto* h : v->second )
            h->handle(e, f);
    }
}

