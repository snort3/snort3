//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
// cip_events.h author Jian Wu <jiawu2@cisco.com>

#ifndef CIP_EVENTS_H
#define CIP_EVENTS_H

// This event conveys data published by the CIP service inspector to be consumed
// by data bus subscribers

#include <list>

#include "framework/data_bus.h"

struct CipEventIds { enum : unsigned { DATA, num_ids }; };

const snort::PubKey cip_pub_key { "cip", CipEventIds::num_ids };

namespace snort
{
struct Packet;
struct SfIp;
}

struct CipEventData;

class SO_PUBLIC CipEvent : public snort::DataEvent
{
public:
    CipEvent(const snort::Packet*, const CipEventData*);

    const snort::Packet* get_packet() const override
    { return p; }

    const CipEventData* get_event_data()
    { return event_data; }	    
private:
    const snort::Packet* p;
    const CipEventData* event_data;
};

#endif
