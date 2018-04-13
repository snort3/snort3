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

// tcp_reassemblers.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 9, 2015

#ifndef TCP_REASSEMBLERS_H
#define TCP_REASSEMBLERS_H

#include "tcp_reassembler.h"

class TcpReassemblerFactory
{
public:
    static TcpReassembler* create(StreamPolicy);
};

class TcpReassemblerPolicy

{
public:
    TcpReassemblerPolicy() = default;
    ~TcpReassemblerPolicy() = default;

    void init(TcpSession* ssn, TcpStreamTracker* trk, StreamPolicy pol, bool server);
    void reset();

    int queue_packet_for_reassembly(TcpSegmentDescriptor& tsd)
    { return reassembler->queue_packet_for_reassembly(trs, tsd); }

    void purge_segment_list()
    { reassembler->purge_segment_list(trs); }

    int purge_flushed_ackd()
    { return reassembler->purge_flushed_ackd(trs); }

    int flush_stream(snort::Packet* p, uint32_t dir, bool final_flush = false)
    { return reassembler->flush_stream(trs, p, dir, final_flush); }

    void flush_queued_segments(snort::Flow* flow, bool clear, snort::Packet* p = nullptr)
    { reassembler->flush_queued_segments(trs, flow, clear, p); }

    bool is_segment_pending_flush()
    { return reassembler->is_segment_pending_flush(trs); }

    int flush_on_data_policy(snort::Packet* p)
    { return reassembler->flush_on_data_policy(trs, p); }

    int flush_on_ack_policy(snort::Packet* p)
    { return reassembler->flush_on_ack_policy(trs, p); }

    void trace_segments()
    { reassembler->trace_segments(trs); }

    void set_seglist_base_seq(uint32_t seglist_base_seq)
    { trs.sos.seglist_base_seq = seglist_base_seq; }

    uint32_t get_seglist_base_seq() const
    { return trs.sos.seglist_base_seq; }

    void set_xtradata_mask(uint32_t xtradata_mask)
    { trs.xtradata_mask = xtradata_mask; }

    uint32_t get_xtradata_mask() const
    { return trs.xtradata_mask; }

    uint32_t get_seg_count() const
    { return trs.sos.seg_count; }

    uint32_t get_seg_bytes_total() const
    { return trs.sos.seg_bytes_total; }

    uint32_t get_overlap_count() const
    { return trs.sos.overlap_count; }

    void set_overlap_count(uint32_t overlap_count)
    { trs.sos.overlap_count = overlap_count;  }

    uint32_t get_flush_count() const
    { return trs.flush_count; }

    uint32_t get_seg_bytes_logical() const
    { return trs.sos.seg_bytes_logical; }

    ReassemblyPolicy get_reassembly_policy() const
    { return trs.sos.reassembly_policy; }

    void set_norm_mode_test()
    { trs.sos.tcp_ips_data = NORM_MODE_TEST; }

private:
    TcpReassembler* reassembler = nullptr;
    TcpReassemblerState trs;
};
#endif

