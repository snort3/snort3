//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment_descriptor.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifndef TCP_SEGMENT_DESCRIPTOR_H
#define TCP_SEGMENT_DESCRIPTOR_H

#include <cassert>

#include <daq_common.h>

#include "flow/flow.h"
#include "detection/ips_context.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "stream/tcp/tcp_event_logger.h"

class TcpStreamTracker;

class TcpSegmentDescriptor
{
public:
    TcpSegmentDescriptor(snort::Flow*, snort::Packet*, TcpEventLogger&);
    TcpSegmentDescriptor(snort::Flow*, snort::Packet*, uint32_t meta_ack, uint16_t window);

    virtual ~TcpSegmentDescriptor() = default;

    static void setup();
    static void clear();

    bool is_ips_policy_inline()
    { return pkt->context->conf->ips_inline_mode(); }

    bool is_nap_policy_inline()
    { return pkt->context->conf->nap_inline_mode(); }

    uint32_t init_mss(uint16_t* value);
    uint32_t init_wscale(uint16_t* value);
    void set_retransmit_flag();

    snort::Flow* get_flow() const
    { return flow; }

    snort::Packet* get_pkt() const
    { return pkt; }

    const snort::tcp::TCPHdr* get_tcph() const
    { return tcph; }

    void set_seq(uint32_t seq_num)
    { seq = seq_num; }

    void update_seq(int32_t offset)
    { seq += offset; }

    uint32_t get_seq() const
    { return seq; }

    uint32_t get_ack() const
    { return ack; }

    void set_ack(uint32_t ack_num)
    { ack = ack_num; }

    void set_end_seq(uint32_t seq)
    { end_seq = seq; }

    uint32_t get_end_seq() const
    { return end_seq; }

    void set_timestamp(uint32_t timestamp)
    { timestamp_option = timestamp; }

    uint32_t get_timestamp() const
    { return timestamp_option; }

    void scale_wnd(uint16_t wscale)
    { wnd <<= wscale; }

    uint32_t get_wnd() const
    { return wnd; }

    uint16_t get_dst_port() const
    { return dst_port; }

    uint16_t get_src_port() const
    { return src_port; }

    uint8_t get_direction() const
    { return flow->ssn_state.direction; }

    uint16_t get_len() const
    { return pkt->dsize; }

    void set_len(uint16_t seg_len)
    { pkt->dsize = seg_len; }

    bool is_data_segment() const
    { return pkt->dsize > 0; }

    bool is_packet_from_client() const
    { return packet_from_client; }

    bool is_packet_from_server() const
    { return !packet_from_client; }

    void slide_segment_in_rcv_window(int32_t offset)
    {
        seq += offset;
        pkt->data += offset;
        pkt->dsize -= offset;
    }

    void set_packet_flags(uint32_t flags) const
    { pkt->packet_flags |= flags; }

    bool are_packet_flags_set(uint32_t flags) const
    { return (pkt->packet_flags & flags) == flags; }

    uint32_t get_packet_timestamp() const
    { return packet_timestamp; }

    void drop_packet() const
    {
        pkt->active->drop_packet(pkt);
        pkt->active->set_drop_reason("stream");
    }

    bool is_meta_ack_packet() const
    { return meta_ack_packet; }

    uint64_t get_packet_number() const
    { return packet_number; }

    void rewrite_payload(uint16_t offset, uint8_t* from, uint16_t length)
    {
        memcpy(const_cast<uint8_t*>(pkt->data + offset), from, length);
        set_packet_flags(PKT_MODIFIED);
    }

    void rewrite_payload(uint16_t offset, uint8_t* from)
    { rewrite_payload(offset, from, pkt->dsize); }

    TcpStreamTracker* get_listener() const
    { return listener; }

    void set_listener(TcpStreamTracker& tracker)
    { listener = &tracker; }

    TcpStreamTracker* get_talker() const
    { return talker; }

    void set_talker(TcpStreamTracker& tracker)
    { talker = &tracker; }

private:
    snort::Flow* const flow;
    snort::Packet* const pkt;
    const snort::tcp::TCPHdr* const tcph;
    TcpStreamTracker* talker = nullptr;
    TcpStreamTracker* listener = nullptr;

    const uint64_t packet_number;
    uint32_t seq;
    uint32_t ack;
    uint32_t wnd;
    uint32_t end_seq;
    uint32_t timestamp_option;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_timestamp;
    bool packet_from_client;
    bool meta_ack_packet = false;
};

#endif

