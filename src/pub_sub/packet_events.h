//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// packet_events.h author Ron Dempster <rdempste@cisco.com>

#ifndef PACKET_EVENTS_H
#define PACKET_EVENTS_H

#include "pub_sub/intrinsic_event_ids.h"

// A retry packet is being processed

namespace snort
{

class RetryPacketEvent : public DataEvent
{
public:
    explicit RetryPacketEvent(const Packet* p) : pkt(p)
    { }

    const Packet* get_packet() const override
    { return pkt; }

    void set_still_pending()
    { still_pending = true; }

    bool is_still_pending() const
    { return still_pending; }

private:
    const Packet* pkt;
    bool still_pending = false;
};

}

#endif
