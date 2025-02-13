//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// active_events.h author davis mcpherson <davmcphe@cisco.com>
// Active action events published to notify clients of state change in
// the active action for the packet

#ifndef ACTIVE_EVENTS_H
#define ACTIVE_EVENTS_H

#include <framework/data_bus.h>
#include <packet_io/active.h>

namespace snort
{
struct Packet;

class SO_PUBLIC ActiveEvent : public DataEvent
{
public:
    ActiveEvent
        (const Active::ActiveActionType current, const Active::ActiveActionType previous, const Packet* p)
        : current_action(current), previous_action(previous), pkt(p)
    { }

    Active::ActiveActionType get_current_action() const
    { return current_action; }

    Active::ActiveActionType get_previous_action() const
    { return previous_action; }

    const Packet* get_packet() const override
    { return pkt; }

private:
    const Active::ActiveActionType current_action;
    const Active::ActiveActionType previous_action;
    const Packet* pkt;
};
}
#endif

