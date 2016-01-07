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

#include "stream/tcp/tcp_event_logger.h"

class TcpSegmentDescriptor
{
public:
    TcpSegmentDescriptor(Flow*, Packet*, TcpEventLogger*);
    virtual ~TcpSegmentDescriptor();

    uint32_t init_mss(uint16_t* value);
    uint32_t init_wscale(uint16_t* value);
    uint32_t has_wscale(void);

    Flow* get_flow() const
    {
        return flow;
    }

    Packet* get_pkt() const
    {
        return pkt;
    }

    const tcp::TCPHdr* get_tcph() const
    {
        return tcph;
    }

    void set_seq(uint32_t seq)
    {
        this->seq = seq;
    }

    uint32_t get_seq() const
    {
        return seq;
    }

    uint32_t get_ack() const
    {
        return ack;
    }

    void set_end_seq(uint32_t end_seq)
    {
        this->end_seq = end_seq;
    }

    uint32_t get_end_seq() const
    {
        return end_seq;
    }

    void set_ts(uint32_t ts)
    {
        this->ts = ts;
    }

    uint32_t get_ts() const
    {
        return ts;
    }

    void set_win(uint32_t win)
    {
        this->win = win;
    }

    uint32_t get_win() const
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
        return flow->ssn_state.direction;
    }

    uint32_t get_data_len() const
    {
        return pkt->dsize;
    }

    void print_tsd(void);

private:
    Flow* flow;
    Packet* pkt;

    const tcp::TCPHdr* tcph;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint32_t win;
    uint32_t end_seq;
    uint32_t ts;
};

#endif

