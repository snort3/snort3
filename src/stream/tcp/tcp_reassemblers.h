//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassemblers.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 9, 2015

#ifndef TCP_REASSEMBLERS_H
#define TCP_REASSEMBLERS_H

#include "tcp_reassembler.h"

class TcpReassemblerFactory
{
public:
    static void initialize();
    static void term();
    static TcpReassembler* get_instance(StreamPolicy);

private:
    TcpReassemblerFactory() = delete;

    static TcpReassembler* reassemblers[StreamPolicy::OS_END_OF_LIST];
};

class TcpReassemblerPolicy
{
public:
    TcpReassemblerPolicy() = default;
    ~TcpReassemblerPolicy() = default;

    void init(TcpSession* ssn, TcpStreamTracker* trk, StreamPolicy pol, bool server);
    void reset();

    void queue_packet_for_reassembly(TcpSegmentDescriptor& tsd)
    { reassembler->queue_packet_for_reassembly(trs, tsd); }

    bool add_alert(uint32_t gid, uint32_t sid)
    { return reassembler->add_alert(trs, gid, sid); }

    bool check_alerted(uint32_t gid, uint32_t sid)
    { return reassembler->check_alerted(trs, gid, sid); }

    int update_alert(uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second)
    { return reassembler->update_alert(trs, gid, sid, event_id, event_second); }

    void purge_alerts()
    { reassembler->purge_alerts(trs); }

    void purge_segment_list()
    { reassembler->purge_segment_list(trs); }

    void purge_flushed_ackd()
    { return reassembler->purge_flushed_ackd(trs); }

    int flush_stream(snort::Packet* p, uint32_t dir, bool final_flush = false)
    { return reassembler->flush_stream(trs, p, dir, final_flush); }

    void finish_and_final_flush(snort::Flow* flow, bool clear, snort::Packet* p)
    { reassembler->finish_and_final_flush(trs, flow, clear, p); }

    void flush_queued_segments(snort::Flow* flow, bool clear, const snort::Packet* p = nullptr)
    { reassembler->flush_queued_segments(trs, flow, clear, p); }

    bool is_segment_pending_flush()
    { return reassembler->is_segment_pending_flush(trs); }

    int flush_on_data_policy(snort::Packet* p)
    { return reassembler->flush_on_data_policy(trs, p); }

    int flush_on_ack_policy(snort::Packet* p)
    { return reassembler->flush_on_ack_policy(trs, p); }

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

    StreamPolicy get_reassembly_policy() const
    { return trs.sos.reassembly_policy; }

    void set_norm_mode_test()
    { trs.sos.tcp_ips_data = NORM_MODE_TEST; }

    uint32_t perform_partial_flush(snort::Flow* flow, snort::Packet*& p)
    { return reassembler->perform_partial_flush(trs, flow, p); }

    void reset_paf()
    { paf_reset(&trs.paf_state); }

    void clear_paf()
    { paf_clear(&trs.paf_state); }

    void setup_paf()
    {
        paf_setup(&trs.paf_state);
        if ( trs.sos.seglist.cur_rseg )
            trs.sos.seglist.cur_sseg = trs.sos.seglist.cur_rseg;
        else
            trs.sos.seglist.cur_sseg = trs.sos.seglist.head;
    }

private:
    TcpReassembler* reassembler = nullptr;
    TcpReassemblerState trs;
    friend inline void TraceSegments(const TcpReassemblerPolicy&, const snort::Packet* p);
};
#endif

