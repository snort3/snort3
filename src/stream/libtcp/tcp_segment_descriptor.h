//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "protocols/tcp.h"
#include "stream/tcp/tcp_event_logger.h"

class TcpSegmentDescriptor
{
public:
    TcpSegmentDescriptor(snort::Flow*, snort::Packet*, TcpEventLogger&);
    virtual ~TcpSegmentDescriptor() = default;

    uint32_t init_mss(uint16_t* value);
    uint32_t init_wscale(uint16_t* value);
    bool has_wscale();

    snort::Flow* get_flow() const
    {
        return flow;
    }

    snort::Packet* get_pkt() const
    {
        return pkt;
    }

    const snort::tcp::TCPHdr* get_tcph() const
    {
        return tcph;
    }

    void set_seg_seq(uint32_t seq)
    {
        this->seg_seq = seq;
    }

    void update_seg_seq(int32_t offset)
    {
        seg_seq += offset;
    }

    uint32_t get_seg_seq() const
    {
        return seg_seq;
    }

    uint32_t get_seg_ack() const
    {
        return seg_ack;
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

    void scale_seg_wnd(uint16_t wscale)
    {
        this->seg_wnd <<= wscale;
    }

    uint32_t get_seg_wnd() const
    {
        return seg_wnd;
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

    uint16_t get_seg_len() const
    {
        return pkt->dsize;
    }

    void set_seg_len(uint16_t seg_len)
    {
        pkt->dsize = seg_len;
    }

    void update_seg_len(int32_t offset)
    {
        pkt->dsize += offset;
    }

    bool is_packet_from_server()
    {
        return pkt->is_from_server();
    }

    void slide_segment_in_rcv_window(int32_t offset)
    {
        seg_seq += offset;
        pkt->data += offset;
        pkt->dsize -= offset;
    }

private:
    snort::Flow* flow;
    snort::Packet* pkt;

    const snort::tcp::TCPHdr* tcph;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seg_seq;
    uint32_t seg_ack;
    uint32_t seg_wnd;
    uint32_t end_seq;
    uint32_t ts;
};

#endif

