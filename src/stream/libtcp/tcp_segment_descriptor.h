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
#include "protocols/tcp.h"
#include "protocols/packet.h"

class TcpSegmentDescriptor
{
public:
    TcpSegmentDescriptor( Flow*, Packet* );
    virtual ~TcpSegmentDescriptor();

    const Flow* get_flow() const
    {
        return flow;
    }

    const Packet* get_pkt() const
    {
        return pkt;
    }
    const tcp::TCPHdr* get_tcph() const
    {
        return tcph;
    }

    uint32_t get_ack() const
    {
        return ack;
    }

    uint32_t get_end_seq() const
    {
        return end_seq;
    }

    uint32_t get_seq() const
    {
    	return seq;
    }

    uint32_t get_ts() const
    {
    	return ts;
    }

    uint16_t get_win() const
    {
    	return win;
    }

    uint16_t get_dst_port() const
    {
        return dst_port;
    }

    uint16_t get_src_port() const
    {
        return src_port;
    }

    uint8_t get_direction() const
    {
        return direction;
    }

    void set_direction(uint8_t direction)
    {
        this->direction = direction;
    }

    uint32_t get_data_len() const
    {
        return data_len;
    }

    void set_data_len(uint32_t data_len)
    {
        this->data_len = data_len;
    }

private:
    Flow*   flow;
    Packet* pkt;

    uint8_t direction;

    const tcp::TCPHdr* tcph;
    uint32_t data_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t win;
    uint32_t end_seq;
    uint32_t ts;
};

#endif
