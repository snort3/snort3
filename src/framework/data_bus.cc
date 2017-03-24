//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
#include "protocols/packet.h"

DataBus& get_data_bus()
{ return get_inspection_policy()->dbus; }

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

DataBus::DataBus() { }

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
    DataList& v = map[key];
    v.push_back(h);
}

// notify subscribers of event
void DataBus::publish(const char* key, DataEvent& e, Flow* f)
{
    DataList& v = map[key];

    for ( auto* h : v )
        h->handle(e, f);
}

void DataBus::publish(const char* key, const uint8_t* buf, unsigned len, Flow* f)
{
    BufferEvent e(buf, len);
    publish(key, e, f);
}

void DataBus::publish(const char* key, Packet* p, Flow* f)
{
    PacketEvent e(p);
    if ( !f )
        f = p->flow;
    publish(key, e, f);
}

