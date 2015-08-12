//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment_descriptor.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#ifndef TCP_SEGMENT_DESCRIPTOR_H
#define TCP_SEGMENT_DESCRIPTOR_H

#include "flow/flow.h"
#include "protocols/packet.h"

class TcpSegmentDescriptor
{
public:
    TcpSegmentDescriptor( Flow*, Packet* );
    virtual ~TcpSegmentDescriptor();

    uint32_t get_ack() const
    {
        return ack;
    }

    uint32_t get_end_seq() const
    {
        return end_seq;
    }

    const Flow* get_flow() const
    {
        return flow;
    }

    const Packet* get_pkt() const
    {
        return pkt;
    }

    uint32_t get_seq() const
    {
        return seq;
    }

    uint32_t get_ts() const
    {
        return ts;
    }

    uint32_t get_win() const
    {
        return win;
    }

private:
    Packet* pkt;
    Flow*   flow;

    uint32_t seq;
    uint32_t ack;
    uint32_t win;
    uint32_t end_seq;
    uint32_t ts;
};

#endif
