//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// expect_events.h author Steven Baigal <sbaigal@cisco.com>

#ifndef EXPECT_EVENTS_H
#define EXPECT_EVENTS_H

// This event conveys data published by the expcted sessions to be consumed
// by data bus subscribers

#include <list>

#include "framework/data_bus.h"

#define EXPECT_EVENT_TYPE_EARLY_SESSION_CREATE_KEY "expect_event_type_early_session_create"

struct Packet;
class FlowData;
struct ExpectFlow;

class ExpectEvent : public DataEvent
{
public:
    ExpectEvent(const Packet* ctrl_packet, ExpectFlow* ef, const FlowData* fd)
    {
        p = ctrl_packet;
        expect_flow = ef;
        flow_data = fd;
    }

    const Packet* get_packet() override
    { return p; }

    ExpectFlow* get_expect_flow()
    { return expect_flow; }

    const FlowData* get_flow_data()
    { return flow_data; }

private:
    const Packet* p;
    ExpectFlow* expect_flow;
    const FlowData* flow_data;
};

#endif
