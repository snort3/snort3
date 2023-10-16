//--------------------------------------------------------------------------
// Copyright (C) 2017-2023 Cisco and/or its affiliates. All rights reserved.
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

// This event conveys data published by the expected sessions to be consumed
// by data bus subscribers

#include <list>
#include <vector>

#include "pub_sub/intrinsic_event_ids.h"

#define EXPECT_EVENT_TYPE_EARLY_SESSION_CREATE_KEY "expect_event_type_early_session_create"

namespace snort
{
struct ExpectFlow;
class FlowData;
struct Packet;
}

class ExpectEvent : public snort::DataEvent
{
public:
    ExpectEvent(const snort::Packet* ctrl_packet, snort::ExpectFlow* ef,
        const snort::FlowData* fd)
    {
        p = ctrl_packet;
        expect_flow = ef;
        flow_data = fd;
    }

    const snort::Packet* get_packet() const override
    { return p; }

    snort::ExpectFlow* get_expect_flow()
    { return expect_flow; }

    const snort::FlowData* get_flow_data()
    { return flow_data; }

private:
    const snort::Packet* p;
    snort::ExpectFlow* expect_flow;
    const snort::FlowData* flow_data;
};

#define EXPECT_EVENT_TYPE_HANDLE_FLOWS "expect.handle_flows"

class ExpectedFlowsEvent : public snort::DataEvent
{
public:
    ExpectedFlowsEvent(std::vector<snort::ExpectFlow*>& expected_flows, const snort::Packet& p)
        : expected_flows(expected_flows), pkt(p)
    { }

    std::vector<snort::ExpectFlow*>& get_expected_flows()
    { return expected_flows; }

    const snort::Packet* get_packet() const override
    { return &pkt; }

private:
    std::vector<snort::ExpectFlow*>& expected_flows;
    const snort::Packet& pkt;
};

#endif
