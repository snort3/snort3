//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/policy.h"
#include "main/snort_config.h"
#include "protocols/packet.h"

using namespace snort;

static DataBus& get_data_bus()
{ return snort::get_inspection_policy()->dbus; }

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
            delete h;
}

// add handler to list of handlers to be notified upon
// publication of given event
void DataBus::subscribe(const char* key, DataHandler* h)
{
    get_data_bus()._subscribe(key, h);
}

// for subscribers that need to receive events regardless of active inspection policy
void DataBus::subscribe_default(const char* key, DataHandler* h)
{
    get_default_inspection_policy(SnortConfig::get_conf())->dbus._subscribe(key, h);
}

void DataBus::unsubscribe(const char* key, DataHandler* h)
{
    get_data_bus()._unsubscribe(key, h);
}

void DataBus::unsubscribe_default(const char* key, DataHandler* h)
{
    get_default_inspection_policy(SnortConfig::get_conf())->dbus._unsubscribe(key, h);
}

// notify subscribers of event
void DataBus::publish(const char* key, DataEvent& e, Flow* f)
{
    InspectionPolicy* pi = snort::get_inspection_policy();
    pi->dbus._publish(key, e, f);

    // also publish to default policy to notify control subscribers such as appid
    InspectionPolicy* di = snort::get_default_inspection_policy(SnortConfig::get_conf());

    // of course, only when current is not default
    if ( di != pi )
        di->dbus._publish(key, e, f);
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

void DataBus::publish(const char* key, void* user, int type, const uint8_t* data)
{
    DaqMetaEvent e(user, type, data);
    publish(key, e, nullptr);
}

//--------------------------------------------------------------------------
// private methods
//--------------------------------------------------------------------------

void DataBus::_subscribe(const char* key, DataHandler* h)
{
    DataList& v = map[key];
    v.push_back(h);
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

