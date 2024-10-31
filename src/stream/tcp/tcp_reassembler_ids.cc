//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembler_ids.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassembler_ids.h"

#include <cassert>

#include "detection/detection_engine.h"
#include "log/log.h"
#include "main/analyzer.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_segment_node.h"
#include "tcp_session.h"
#include "tcp_stream_tracker.h"

using namespace snort;

bool TcpReassemblerIds::has_seglist_hole(TcpSegmentNode& tsn, uint32_t& total, uint32_t& flags)
{
    if ( !tsn.prev or SEQ_GEQ(tsn.prev->scan_seq() + tsn.prev->unscanned(), tsn.scan_seq())
    	or SEQ_GEQ(tsn.scan_seq(), tracker.r_win_base) )
    {
    	check_first_segment_hole();
    	return false;
    }

    // safety - prevent seq + total < seq
    if ( total > 0x7FFFFFFF )
        total = 0x7FFFFFFF;

    if ( !paf.tot )
        flags |= PKT_PDU_HEAD;

    paf.state = StreamSplitter::SKIP;
    return true;
}

void TcpReassemblerIds::skip_seglist_hole(Packet* p, uint32_t flags, int32_t flush_amt)
{
    if ( is_splitter_paf() )
    {
        if ( flush_amt > 0 )
            update_skipped_bytes(flush_amt);
        tracker.fallback();
    }
    else
    {
        if ( flush_amt > 0 )
            flush_to_seq(flush_amt, p, flags);
        paf.state = StreamSplitter::START;
    }

    if ( seglist.head )
    {
        if ( flush_amt > 0 )
            purge_to_seq(seglist.seglist_base_seq + flush_amt);
        seglist.seglist_base_seq = seglist.head->scan_seq();
    }
    else
        seglist.seglist_base_seq = tracker.r_win_base;  // FIXIT-H - do we need to set rcv_nxt here?

    seglist.cur_rseg = seglist.head;
    tracker.set_order(TcpStreamTracker::OUT_OF_SEQUENCE);
}

// iterate over seglist and scan all new acked bytes
// - new means not yet scanned
// - must use seglist data (not packet) since this packet may plug a
//   hole and enable paf scanning of following segments
// - if we reach a flush point
//   - return bytes to flush if data available (must be acked)
//   - return zero if not yet received or received but not acked
// - if we reach a skip point
//   - jump ahead and resume scanning any available data
// - must stop if we reach a gap
// - one segment may lead to multiple checks since
//   it may contain multiple encapsulated PDUs
// - if we partially scan a segment we must save state so we
//   know where we left off and can resume scanning the remainder
int32_t TcpReassemblerIds::scan_data_post_ack(uint32_t* flags, Packet* p)
{
    assert(seglist.session->flow == p->flow);

    int32_t ret_val = FINAL_FLUSH_HOLD;

    if ( !seglist.cur_sseg || SEQ_GEQ(seglist.seglist_base_seq, tracker.r_win_base) )
        return ret_val ;

    if ( !seglist.cur_rseg )
        seglist.cur_rseg = seglist.cur_sseg;

    uint32_t total = 0;
    TcpSegmentNode* tsn = seglist.cur_sseg;
    if ( paf.paf_initialized() )
    {
        uint32_t end_seq = tsn->scan_seq() + tsn->unscanned();
        if ( SEQ_EQ(end_seq, paf.paf_position()) )
        {
            total = end_seq - seglist.seglist_base_seq;
            tsn = tsn->next;
        }
        else
            total = tsn->scan_seq() - seglist.cur_rseg->scan_seq();
    }

    ret_val = FINAL_FLUSH_OK;
    while (tsn && *flags && SEQ_LT(tsn->scan_seq(), tracker.r_win_base))
    {
        // only flush acked data that fits in pdu reassembly buffer...
        uint32_t end = tsn->scan_seq() + tsn->unscanned();
        uint32_t flush_len;
        int32_t flush_pt;

        if ( SEQ_GT(end, tracker.r_win_base))
            flush_len = tracker.r_win_base - tsn->scan_seq();
        else
            flush_len = tsn->unscanned();

        if ( tsn->next_acked_no_gap(tracker.r_win_base) )
            *flags |= PKT_MORE_TO_FLUSH;
        else
            *flags &= ~PKT_MORE_TO_FLUSH;

        if ( has_seglist_hole(*tsn, total, *flags) )
            flush_pt = total;
        else
        {
            total += flush_len;
            flush_pt = paf.paf_check(p, tsn->paf_data(), flush_len, total, tsn->scan_seq(), flags);
        }

        // Get splitter from tracker as paf check may change it.
        seglist.cur_sseg = tsn;

        if ( flush_pt >= 0 )
        {
            seglist.seglist_base_seq = seglist.cur_rseg->scan_seq();
            return flush_pt;
        }

        if (flush_len < tsn->unscanned() || (splitter->is_paf() and !tsn->next_no_gap()) ||
            (paf.state == StreamSplitter::STOP))
        {
            if ( !(tsn->next_no_gap() || fin_acked_no_gap(*tsn)) )
                ret_val = FINAL_FLUSH_HOLD;
            break;
        }

        tsn = tsn->next;
    }

    return ret_val;
}

int TcpReassemblerIds::eval_flush_policy_on_ack(Packet* p)
{
    last_pdu = nullptr;
    uint32_t flushed = 0;
    int32_t flush_amt;
    uint32_t flags;

    do
    {
        flags = packet_dir;
        flush_amt = scan_data_post_ack(&flags, p);
        if ( flush_amt <= 0 or paf.state == StreamSplitter::SKIP )
            break;

        // for consistency with other cases, should return total
        // but that breaks flushing pipelined pdus
        flushed += flush_to_seq(flush_amt, p, flags);
        assert( flushed );

        // ideally we would purge just once after this loop but that throws off base
        if ( seglist.head )
            purge_to_seq(seglist.seglist_base_seq);
    } while ( seglist.head and !p->flow->is_inspection_disabled() );

    if ( (paf.state == StreamSplitter::ABORT) && is_splitter_paf() )
    {
        tracker.fallback();
        return eval_flush_policy_on_ack(p);
    }
    else if ( paf.state == StreamSplitter::SKIP )
    {
        skip_seglist_hole(p, flags, flush_amt);
        return eval_flush_policy_on_ack(p);
    }
    else if ( final_flush_on_fin(flush_amt, p, FIN_WITH_SEQ_ACKED) )
        finish_and_final_flush(p->flow, true, p);

    return flushed;
}

int TcpReassemblerIds::eval_flush_policy_on_data(Packet* p)
{
    uint32_t flushed = 0;

    if ( !seglist.head )
        return flushed;

    if ( tracker.is_retransmit_of_held_packet(p) )
        flushed += perform_partial_flush(p);

    if ( !p->flow->two_way_traffic() and
        seglist.get_seg_bytes_total() > seglist.session->tcp_config->asymmetric_ids_flush_threshold )
    {
        seglist.skip_hole_at_beginning(seglist.head);
        flushed += eval_asymmetric_flush(p);
    }

    return flushed;
}

int TcpReassemblerIds::eval_asymmetric_flush(snort::Packet* p)
{
    // asymmetric flush in IDS mode.. advance r_win_base to end of in-order data
    tracker.r_win_base = tracker.rcv_nxt;

    uint32_t flushed = eval_flush_policy_on_ack(p);
    if ( flushed )
    {
        if (PacketTracer::is_active())
            PacketTracer::log("stream_tcp: IDS mode - %u bytes flushed on asymmetric flow\n", flushed);
        tcpStats.flush_on_asymmetric_flow++;
    }

    return flushed;
}

int TcpReassemblerIds::flush_stream(Packet* p, uint32_t dir, bool final_flush)
{
    uint32_t bytes = 0;

    if ( seglist.session->flow->two_way_traffic() )
        bytes = get_q_footprint();
    else
        bytes = get_q_sequenced();

    if ( bytes )
        return flush_to_seq(bytes, p, dir);

    if ( final_flush )
        return do_zero_byte_flush(p, dir);

    return 0;
}

