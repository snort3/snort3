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
// data_bus.h author Russ Combs <rucombs@cisco.com>

#ifndef DATA_BUS_H
#define DATA_BUS_H

// DataEvents are the product of inspection, not detection.  They can be
// used to implement flexible processing w/o hardcoding the logic to call
// specific functions under specific conditions.  By using DataEvents with
// a publish-subscribe mechanism, it is possible to add custom processing
// at arbitrary points, eg when service is identified, or when a URI is
// available, or when a flow clears.

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "main/snort_types.h"

namespace snort
{
class Flow;
struct Packet;
struct SnortConfig;

struct PubKey
{
    const char* publisher;
    unsigned num_events;
};

class DataEvent
{
public:
    virtual ~DataEvent() = default;

    virtual const Packet* get_packet() const
    { return nullptr; }

    virtual const uint8_t* get_data()
    { return nullptr; }

    virtual const uint8_t* get_data(unsigned& len)
    { len = 0; return nullptr; }

    virtual const uint8_t* get_normalized_data(unsigned& len)
    { return get_data(len); }

protected:
    DataEvent() = default;
};

class BareDataEvent final : public DataEvent
{
public:
    BareDataEvent() = default;
    ~BareDataEvent() override = default;
};

class DataHandler
{
public:
    virtual ~DataHandler() = default;

    virtual void handle(DataEvent&, Flow*) { }
    const char* module_name;
    bool cloned;

    // order is desired position in the call sequence of handlers: 1 = first, 0 = last
    // the sequence among subscribers with the same order is not specified
    unsigned order = 0;

protected:
    DataHandler(std::nullptr_t) = delete;
    DataHandler(const char* mod_name) : module_name(mod_name), cloned(false) { }
};

class SO_PUBLIC DataBus
{
public:
    DataBus();
    ~DataBus();

    // configure time methods - main thread only
    static unsigned init();
    void clone(DataBus& from, const char* exclude_name = nullptr);

    // publishers must register their key and use given id to publish
    static unsigned get_id(const PubKey&);

    static bool valid(unsigned pub_id)
    { return pub_id != 0; }

    // FIXIT-L ideally these would not be static or would take an inspection policy*
    static void subscribe(const PubKey&, unsigned id, DataHandler*);
    static void subscribe_network(const PubKey&, unsigned id, DataHandler*);
    static void subscribe_global(const PubKey&, unsigned id, DataHandler*, SnortConfig&);

    // FIXIT-L these should be called during cleanup
    static void unsubscribe(const PubKey&, unsigned id, DataHandler*);
    static void unsubscribe_network(const PubKey&, unsigned id, DataHandler*);
    static void unsubscribe_global(const PubKey&, unsigned id, DataHandler*, SnortConfig&);

    // runtime methods
    static void publish(unsigned pub_id, unsigned evt_id, DataEvent&, Flow* = nullptr);

    // convenience methods
    static void publish(unsigned pub_id, unsigned evt_id, const uint8_t*, unsigned, Flow* = nullptr);
    static void publish(unsigned pub_id, unsigned evt_id, Packet*, Flow* = nullptr);
    static void publish_to_all_network_policies(unsigned pub_id, unsigned evt_id);

private:
    void _subscribe(unsigned pub_id, unsigned evt_id, DataHandler*);
    void _subscribe(const PubKey&, unsigned evt_id, DataHandler*);
    void _unsubscribe(const PubKey&, unsigned evt_id, const DataHandler*);
    void _publish(unsigned pub_id, unsigned evt_id, DataEvent&, Flow*) const;

private:
    typedef std::vector<DataHandler*> SubList;
    std::vector<SubList> pub_sub;
};
}

#endif

