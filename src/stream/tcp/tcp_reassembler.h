//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembly.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H

#include "stream/stream.h"
#include "stream/tcp/segment_overlap_editor.h"

class TcpSession;
class TcpStreamTracker;

class TcpReassembler : public SegmentOverlapEditor
{
public:
    virtual int queue_packet_for_reassembly(TcpReassemblerState&, TcpSegmentDescriptor&);
    virtual void purge_segment_list(TcpReassemblerState&);
    virtual int purge_flushed_ackd(TcpReassemblerState&);
    virtual int flush_stream(
        TcpReassemblerState&, snort::Packet* p, uint32_t dir, bool final_flush = false);
    virtual void flush_queued_segments(
        TcpReassemblerState&, snort::Flow* flow, bool clear, snort::Packet* p = nullptr);
    virtual bool is_segment_pending_flush(TcpReassemblerState&);
    virtual int flush_on_data_policy(TcpReassemblerState&, snort::Packet*);
    virtual int flush_on_ack_policy(TcpReassemblerState&, snort::Packet*);
    virtual void trace_segments(TcpReassemblerState&);

protected:
    TcpReassembler() = default;

    int add_reassembly_segment(
        TcpReassemblerState&, TcpSegmentDescriptor&, int16_t len, uint32_t slide,
        uint32_t trunc, uint32_t seq, TcpSegmentNode* left) override;

    int dup_reassembly_segment(
        TcpReassemblerState&, TcpSegmentNode* left, TcpSegmentNode** retSeg) override;
    int delete_reassembly_segment(TcpReassemblerState&, TcpSegmentNode*) override;
    virtual void insert_segment_in_empty_seglist(TcpReassemblerState&, TcpSegmentDescriptor&);
    virtual int insert_segment_in_seglist(TcpReassemblerState&, TcpSegmentDescriptor&);
    virtual uint32_t get_pending_segment_count(TcpReassemblerState&, unsigned max);
    bool flush_data_ready(TcpReassemblerState&);
    int trim_delete_reassembly_segment(TcpReassemblerState&, TcpSegmentNode*, uint32_t flush_seq);
    void queue_reassembly_segment(TcpReassemblerState&, TcpSegmentNode* prev, TcpSegmentNode*);
    void init_overlap_editor(TcpReassemblerState&, TcpSegmentDescriptor&);
    bool is_segment_fasttrack(TcpReassemblerState&, TcpSegmentNode* tail, TcpSegmentDescriptor&);
    int purge_alerts(TcpReassemblerState&, snort::Flow*);
    void show_rebuilt_packet(TcpReassemblerState&, snort::Packet*);
    uint32_t get_flush_data_len(
        TcpReassemblerState&, TcpSegmentNode*, uint32_t to_seq, unsigned max);
    int flush_data_segments(
        TcpReassemblerState&, snort::Packet*, uint32_t total, snort::Packet* pdu);
    void prep_pdu(
        TcpReassemblerState&, snort::Flow*, snort::Packet*, uint32_t pkt_flags,
        snort::Packet* pdu);
    snort::Packet* initialize_pdu(
        TcpReassemblerState&, snort::Packet* p, uint32_t pkt_flags, struct timeval tv);
    int _flush_to_seq(TcpReassemblerState&, uint32_t bytes, snort::Packet*, uint32_t pkt_flags);
    int flush_to_seq(TcpReassemblerState&, uint32_t bytes, snort::Packet*, uint32_t pkt_flags);
    int do_zero_byte_flush(TcpReassemblerState&, snort::Packet* p, uint32_t pkt_flags);
    uint32_t get_q_footprint(TcpReassemblerState&);
    uint32_t get_q_sequenced(TcpReassemblerState&);
    void final_flush(TcpReassemblerState&, snort::Packet*, uint32_t dir);
    uint32_t get_reverse_packet_dir(TcpReassemblerState&, const snort::Packet*);
    uint32_t get_forward_packet_dir(TcpReassemblerState&, const snort::Packet*);
    int32_t flush_pdu_ips(TcpReassemblerState&, uint32_t*);
    void fallback(TcpReassemblerState&);
    int32_t flush_pdu_ackd(TcpReassemblerState&, uint32_t* flags);
    int purge_to_seq(TcpReassemblerState&, uint32_t flush_seq);

    bool next_no_gap(TcpSegmentNode&);
    void update_next(TcpReassemblerState&, TcpSegmentNode&);
};

#endif

