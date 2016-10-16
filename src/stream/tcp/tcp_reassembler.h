//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
    virtual ~TcpReassembler() { }

    virtual int queue_packet_for_reassembly(TcpSegmentDescriptor&);
    virtual void purge_segment_list();
    virtual int flush_stream(Packet* p, uint32_t dir);
    virtual int purge_flushed_ackd();
    virtual void flush_queued_segments(Flow* flow, bool clear, Packet* p = nullptr);
    virtual bool is_segment_pending_flush();
    virtual int flush_on_data_policy(Packet*);
    virtual int flush_on_ack_policy(Packet*);
    void set_seglist_base_seq(uint32_t seglist_base_seq)
    {
        this->seglist_base_seq = seglist_base_seq;
        DebugFormat(DEBUG_STREAM_STATE, "seglist_base_seq = %X\n", seglist_base_seq);
    }

    uint32_t get_seglist_base_seq() const
    {
        return seglist_base_seq;
    }

    void set_xtradata_mask(uint32_t xtradata_mask)
    {
        this->xtradata_mask = xtradata_mask;
    }

    uint32_t get_xtradata_mask() const
    {
        return xtradata_mask;
    }

    uint32_t get_seg_count() const
    {
        return seg_count;
    }

    uint32_t get_seg_bytes_total() const
    {
        return seg_bytes_total;
    }

    uint32_t get_overlap_count() const
    {
        return overlap_count;
    }

    void set_overlap_count(uint32_t overlap_count)
    {
        this->overlap_count = overlap_count;
    }

    uint32_t get_flush_count() const
    {
        return flush_count;
    }

    uint32_t get_seg_bytes_logical() const
    {
        return seg_bytes_logical;
    }

    ReassemblyPolicy get_reassembly_policy() const
    {
        return reassembly_policy;
    }

    void trace_segments();

protected:
    TcpReassembler(TcpSession* session, TcpStreamTracker* tracker,
            StreamPolicy os_policy, bool server) : server_side(server), tracker(tracker)
    {
        this->session = session;
        set_tcp_reassembly_policy(os_policy);

        if ( server_side )
        {
            ignore_dir = SSN_DIR_FROM_CLIENT;
            packet_dir = PKT_FROM_CLIENT;
        }
        else
        {
            ignore_dir = SSN_DIR_FROM_SERVER;
            packet_dir = PKT_FROM_SERVER;
        }

        seglist.head = nullptr;
        seglist.tail = nullptr;
        seglist.next = nullptr;
    }

    int add_reassembly_segment(TcpSegmentDescriptor&, int16_t len, uint32_t slide, uint32_t trunc,
        uint32_t seq, TcpSegmentNode* left) override;
    int dup_reassembly_segment(TcpSegmentNode* left, TcpSegmentNode** retSeg) override;
    int delete_reassembly_segment(TcpSegmentNode*) override;

    virtual void insert_segment_in_empty_seglist(TcpSegmentDescriptor&);
    virtual int insert_segment_in_seglist(TcpSegmentDescriptor&);

    void set_tcp_reassembly_policy(StreamPolicy os_policy);
    virtual uint32_t get_pending_segment_count(unsigned max);

    bool flush_data_ready();
    int trim_delete_reassembly_segment(TcpSegmentNode*, uint32_t flush_seq);
    void queue_reassembly_segment(TcpSegmentNode* prev, TcpSegmentNode*);
    void init_overlap_editor(TcpSegmentDescriptor&);
    bool is_segment_fasttrack(TcpSegmentNode* tail, TcpSegmentDescriptor&);
    int purge_alerts(uint32_t /*flush_seq*/,  Flow*);
    void show_rebuilt_packet(Packet*);
    uint32_t get_flush_data_len(TcpSegmentNode*, uint32_t to_seq, unsigned max);
    int flush_data_segments(Packet*, uint32_t total, Packet* pdu);
    void prep_pdu(Flow*, Packet*, uint32_t pkt_flags, Packet* pdu);
    int _flush_to_seq(uint32_t bytes, Packet*, uint32_t pkt_flags);
    int flush_to_seq(uint32_t bytes, Packet*, uint32_t pkt_flags);
    uint32_t get_q_footprint();
    uint32_t get_q_sequenced();
    void final_flush(Packet*, uint32_t dir);
    uint32_t get_reverse_packet_dir(const Packet*);
    uint32_t get_forward_packet_dir(const Packet*);
    int32_t flush_pdu_ips(uint32_t*);
    void fallback();
    int32_t flush_pdu_ackd(uint32_t* flags);
    int purge_to_seq(uint32_t flush_seq);

    bool server_side;
    TcpStreamTracker* tracker;
    uint8_t ignore_dir;
    uint8_t packet_dir;
    uint32_t flush_count = 0; /* number of flushed queued segments */
    uint32_t xtradata_mask = 0; /* extra data available to log */
};

#endif

