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
// data_bus.h author Russ Combs <rucombs@cisco.com>

#ifndef DATA_BUS_H
#define DATA_BUS_H

// DataEvents are the product of inspection, not detection.  They can be
// used to implement flexible processing w/o hardcoding the logic to call
// specific functions under specific conditions.  By using DataEvents with
// a publish-subscribe mechanism, it is possible to add custom processing
// at arbitrary points, eg when service is identified, or when a URI is
// available, or when a flow clears.

#include <map>
#include <string>
#include <vector>

#include "main/snort_types.h"

// FIXIT-P evaluate perf; focus is on correctness
typedef std::vector<class DataHandler*> DataList;
typedef std::map<std::string, DataList> DataMap;

class Flow;
struct Packet;

class DataEvent
{
public:
    virtual ~DataEvent() { }

    virtual const Packet* get_packet()
    { return nullptr; }

    virtual const uint8_t* get_data(unsigned& len)
    { len = 0; return nullptr; }

    virtual const uint8_t* get_normalized_data(unsigned& len)
    { return get_data(len); }

protected:
    DataEvent() { }
};

class DataHandler
{
public:
    virtual ~DataHandler() { }

    virtual void handle(DataEvent&, Flow*) { }

protected:
    DataHandler() { }
};

class SO_PUBLIC DataBus
{
public:
    DataBus();
    ~DataBus();

    void subscribe(const char* key, DataHandler*);
    void publish(const char* key, DataEvent&, Flow* = nullptr);

    // convenience methods
    void publish(const char* key, const uint8_t*, unsigned, Flow* = nullptr);
    void publish(const char* key, Packet*, Flow* = nullptr);

private:
    DataMap map;
};

// FIXIT-L this should be in snort_confg.h or similar but that
// requires refactoring to work as installed header
SO_PUBLIC DataBus& get_data_bus();

// common data events
#define PACKET_EVENT "detection.packet"

#endif

