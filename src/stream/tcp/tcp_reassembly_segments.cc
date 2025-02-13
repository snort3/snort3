//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembly_segments.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 9, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassembly_segments.h"

#include "log/messages.h"
#include "packet_io/packet_tracer.h"
#include "protocols/tcp.h"

#include "tcp_module.h"
#include "tcp_overlap_resolver.h"
#include "tcp_segment_descriptor.h"
#include "tcp_segment_node.h"
#include "tcp_session.h"
#include "tcp_stream_tracker.h"
#include "tcp_overlap_resolver.h"

using namespace snort;

TcpReassemblySegments::~TcpReassemblySegments()
{
    delete tos;
}

void TcpReassemblySegments::init(TcpSession* ssn, TcpStreamTracker* trk, StreamPolicy pol)
{
    session = ssn;
    tracker = trk;
    overlap_resolver = TcpOverlapResolverFactory::get_instance(pol);
    if ( tos )
        delete tos;
    tos = new TcpOverlapState(*this);
}

void TcpReassemblySegments::reset()
{
    purge();
    seglist_base_seq = 0;
}

void TcpReassemblySegments::purge_segment_list()
{
    purge();
}

void TcpReassemblySegments::update_next(TcpSegmentNode* tsn)
{
    cur_rseg = tsn->next_no_gap() ?  tsn->next : nullptr;
}

bool TcpReassemblySegments::is_segment_pending_flush() const
{
    return ( get_pending_segment_count(1) > 0 );
}

uint32_t TcpReassemblySegments::get_pending_segment_count(const unsigned max) const
{
    uint32_t n = seg_count - flush_count;

    if ( !n || max == 1 )
        return n;

    n = 0;
    const TcpSegmentNode* tsn = head;
    while ( tsn )
    {
        if ( tsn->unscanned() && SEQ_LT(tsn->scan_seq(), tracker->r_win_base) )
            n++;

        if ( max && n == max )
            return n;

        tsn = tsn->next;
    }

    return n;
}

bool TcpReassemblySegments::segment_within_seglist_window(TcpSegmentDescriptor& tsd)
{
    if ( !head )
        return true;

    // Left side
    uint32_t start;
    if ( SEQ_LT(seglist_base_seq, head->start_seq()) )
        start = seglist_base_seq;
    else
        start = head->seq;

    if ( SEQ_LEQ(tsd.get_end_seq(), start) )
        return false;

    // Right side
    if ( SEQ_GEQ(tsd.get_seq(), tail->next_seq()) )
        return false;

    return true;
}

void TcpReassemblySegments::queue_reassembly_segment(TcpSegmentDescriptor& tsd)
{
    if ( seg_count == 0 )
    {
        insert_segment_in_empty_seglist(tsd);
    }
    else if ( SEQ_GT(tracker->r_win_base, tsd.get_seq() ) )
    {
        const int32_t offset = tracker->r_win_base - tsd.get_seq();

        if ( offset < tsd.get_len() )
        {
            tsd.slide_segment_in_rcv_window(offset);
            insert_segment_in_seglist(tsd);
            tsd.slide_segment_in_rcv_window(-offset);
        }
    }
    else
        insert_segment_in_seglist(tsd);
}

void TcpReassemblySegments::insert_segment_in_empty_seglist(TcpSegmentDescriptor& tsd)
{
    uint32_t overlap = 0;

    if ( SEQ_GT(seglist_base_seq,  tsd.get_seq()) )
    {
        overlap = seglist_base_seq - tsd.get_seq();
        if ( overlap >= tsd.get_len() )
            return;
    }

    add_reassembly_segment(tsd, tsd.get_len(), overlap, 0, tsd.get_seq(), nullptr);
}

bool TcpReassemblySegments::is_segment_fasttrack(TcpSegmentNode* tail, const TcpSegmentDescriptor& tsd)
{
    if ( SEQ_EQ(tsd.get_seq(), tail->next_seq()) )
        return true;

    return false;
}

void TcpReassemblySegments::insert_segment_in_seglist(TcpSegmentDescriptor& tsd)
{
    // NORM fast tracks are in sequence - no norms
    if ( tail && is_segment_fasttrack(tail, tsd) )
    {
        /* segment fit cleanly at the end of the segment list */
        add_reassembly_segment(tsd, tsd.get_len(), 0, 0, tsd.get_seq(), tail);
        return;
    }

    tos->init(tsd);
    overlap_resolver->eval_left(*tos);
    overlap_resolver->eval_right(*tos);

    if ( tos->keep_segment )
    {
        // FIXIT-L - is this skipping the add if the segment is first and already scan
        if ( !tos->left and tos->right and tracker->reassembler->segment_already_scanned(tsd.get_seq()) )
        {
            return;
        }

        add_reassembly_segment(tsd, tos->len, tos->slide, tos->trunc_len, tos->seq, tos->left);
    }
}

void TcpReassemblySegments::insert_segment_data(TcpSegmentNode* prev, TcpSegmentNode* tsn)
{
    insert(prev, tsn);

    if ( !cur_sseg )
        cur_sseg = tsn;
    else if ( SEQ_LT(tsn->scan_seq(), cur_sseg->scan_seq()) )
    {
        cur_sseg = tsn;
        if ( SEQ_LT(tsn->scan_seq(), seglist_base_seq) )
            seglist_base_seq = tsn->scan_seq();

        if ( cur_rseg && SEQ_LT(tsn->scan_seq(), cur_rseg->scan_seq()) )
            cur_rseg = tsn;
    }

    // FIXIT-M - increment seg_count here?
    seg_bytes_total += tsn->size;
    total_segs_queued++;
    tcpStats.segs_queued++;

    if ( seg_count > tcpStats.max_segs )
        tcpStats.max_segs = seg_count;

    if ( seg_bytes_total > tcpStats.max_bytes )
        tcpStats.max_bytes = seg_bytes_total;
}

void TcpReassemblySegments::add_reassembly_segment(TcpSegmentDescriptor& tsd, uint16_t len,
    uint32_t slide, uint32_t trunc_len, uint32_t seq, TcpSegmentNode* left)
{
    const int32_t new_size = len - slide - trunc_len;
    assert(new_size >= 0);

    // if trimming will delete all data, don't insert this segment in the queue
    if ( new_size <= 0 )
    {
        tcpStats.payload_fully_trimmed++;
        tracker->normalizer.trim_win_payload(tsd);
        return;
    }

    // FIXIT-L don't allocate overlapped part
    TcpSegmentNode* tsn = TcpSegmentNode::init(tsd);

    tsn->seq = seq;
    tsn->offset = slide;
    tsn->length = (uint16_t)new_size;
    tsn->cursor = 0;
    tsn->ts = tsd.get_timestamp();

    // FIXIT-M the urgent ptr handling is broken... urg_offset could be set here but currently
    // not actually referenced anywhere else.  In 2.9.7 the FlushStream function did reference
    // this field but that code has been lost... urg ptr handling needs to be reviewed and fixed
    // tsn->urg_offset = tracker->normalizer.set_urg_offset(tsd.get_tcph(), tsd.get_seg_len());

    insert_segment_data(left, tsn);

    seg_bytes_logical += tsn->length;
    total_bytes_queued += tsn->size;
    tsd.set_packet_flags(PKT_STREAM_INSERT);

    if( tsd.is_packet_inorder()
        or (SEQ_LEQ(tsn->start_seq(), tracker->get_rcv_nxt())
            and SEQ_GEQ(tsn->next_seq(), tracker->get_rcv_nxt())) )
        advance_rcv_nxt(tsn);
}

void TcpReassemblySegments::dup_reassembly_segment(TcpSegmentNode* left, TcpSegmentNode** retSeg)
{
    TcpSegmentNode* tsn = TcpSegmentNode::init(*left);
    tcpStats.segs_split++;

    // twiddle the values for overlaps
    tsn->cursor = left->cursor;
    tsn->seq = left->seq;
    insert_segment_data(left, tsn);

    *retSeg = tsn;
}

int TcpReassemblySegments::delete_reassembly_segment(TcpSegmentNode* tsn)
{
    int ret;
    assert(tsn);

    remove(tsn);
    seg_bytes_total -= tsn->size;
    seg_bytes_logical -= tsn->length;
    ret = tsn->length;

    if ( !tsn->unscanned() )
    {
        tcpStats.segs_used++;
        flush_count--;
    }

    if ( cur_sseg == tsn )
        cur_sseg = tsn->next;

    if ( cur_rseg == tsn )
        update_next(tsn);

    tsn->term();

    return ret;
}

void TcpReassemblySegments::purge_flushed_segments(uint32_t flush_seq)
{
    assert( head );
    uint32_t last_ts = 0;

    TcpSegmentNode* tsn = head;
    while ( tsn && SEQ_LT(tsn->start_seq(), flush_seq))
    {
        if ( tsn->unscanned() )
            break;

        TcpSegmentNode* dump_me = tsn;
        tsn = tsn->next;
        if (dump_me->ts > last_ts)
            last_ts = dump_me->ts;

        delete_reassembly_segment(dump_me);
    }

    if ( tsn and SEQ_LT(tracker->rcv_nxt, tsn->next_seq()) )
        advance_rcv_nxt(tsn);

    /* Update the "last" time stamp seen from the other side
     * to be the most recent timestamp (largest) that was removed
     * from the queue.  This will ensure that as we go forward,
     * last timestamp is the highest one that we had stored and
     * purged and handle the case when packets arrive out of order,
     * such as:
     * P1: seq 10, length 10, timestamp 10
     * P3: seq 30, length 10, timestamp 30
     * P2: seq 20, length 10, timestamp 20
     *
     * Without doing it this way, the timestamp would be 20.  With
     * the next packet to arrive (P4, seq 40), the ts_last value
     * wouldn't be updated for the talker in ProcessTcp() since that
     * code specifically looks for the NEXT sequence number.
     */
    if ( last_ts )
    {
        if ( tracker->client_tracker )
        {
            int32_t delta = last_ts - session->server.get_ts_last();
            if ( delta > 0 )
                session->server.set_ts_last(last_ts);
        }
       else
        {
           int32_t delta = last_ts - session->client.get_ts_last();
           if ( delta > 0 )
               session->client.set_ts_last(last_ts);
        }
    }
}

void TcpReassemblySegments::purge_segments_left_of_hole(const TcpSegmentNode* end_tsn)
{
    uint32_t packets_skipped = 0;

    TcpSegmentNode* cur_tsn = head;
    do
    {
        TcpSegmentNode* drop_tsn = cur_tsn;
        cur_tsn = cur_tsn->next;
        delete_reassembly_segment(drop_tsn);
        ++packets_skipped;
    } while( cur_tsn and cur_tsn != end_tsn );

    tracker->set_order(TcpStreamTracker::OUT_OF_SEQUENCE);

    if (PacketTracer::is_active())
        PacketTracer::log("stream_tcp: Skipped %u packets before seglist hole\n", packets_skipped);
}

void TcpReassemblySegments::advance_rcv_nxt(TcpSegmentNode *tsn)
{
    if ( !tsn )
    {
        if ( !head )
            return;
        tsn = head;
    }

    while (tsn->next_no_gap())
        tsn = tsn->next;
    tracker->set_rcv_nxt(tsn->next_seq());
}

bool TcpReassemblySegments::skip_hole_at_beginning(TcpSegmentNode *tsn)
{
    assert( tsn );

    bool hole_skipped = false;

    if (SEQ_GT(tsn->seq, seglist_base_seq))
    {
        hole_skipped = true;
        seglist_base_seq = tsn->seq;
        tracker->set_order(TcpStreamTracker::OUT_OF_SEQUENCE);
        if (PacketTracer::is_active())
            PacketTracer::log("stream_tcp: Skipped hole at beginning of the seglist\n");
    }

    return hole_skipped;
}

void TcpReassemblySegments::skip_holes()
{
    assert( head );

    TcpSegmentNode* tsn = head;
    uint32_t num_segs = 0, total_segs = 0, num_holes = 0;

    // if there is a hole at the beginning, skip it...
    if ( skip_hole_at_beginning(tsn) )
        ++num_holes;

    while ( tsn )
    {
        ++num_segs;

        if ( tsn->next and SEQ_GT(tsn->next->start_seq(), tsn->next_seq()) )
        {
            ++num_holes;
            total_segs += num_segs;
            if (PacketTracer::is_active())
                PacketTracer::log("stream_tcp: Seglist hole(%u): %u-->%u:%u. Segments purged: %u Total purged: %u\n",
                    tsn->seq, tsn->next->seq, tsn->next->seq - tsn->seq, num_holes, num_segs, total_segs);
            tsn = tsn->next;
            purge_segments_left_of_hole(tsn);
            seglist_base_seq = head->start_seq();
            num_segs = 0;
        }
        else
            tsn = tsn->next;
    }

    advance_rcv_nxt();
    tracker->set_order(TcpStreamTracker::OUT_OF_SEQUENCE);
}

void TcpReassemblySegments::skip_midstream_pickup_seglist_hole(TcpSegmentDescriptor& tsd)
{
    uint32_t ack = tsd.get_ack();

    TcpSegmentNode* tsn = head;
    while ( tsn )
    {
        if ( SEQ_GEQ( tsn->next_seq(), ack) )
            break;

        if ( tsn->next and SEQ_GT(tsn->next->start_seq(), tsn->next_seq()) )
        {
            tsn = tsn->next;
            purge_segments_left_of_hole(tsn);
            seglist_base_seq = head->start_seq();
        }
        else if ( !tsn->next and SEQ_LT(tsn->next_seq(), ack) )
        {
            tsn = tsn->next;
            purge_segments_left_of_hole(tsn);
            seglist_base_seq = ack;
        }
        else
            tsn = tsn->next;
    }

    tsn = head;
    if ( tsn )
    {
        tracker->reassembler->initialize_paf();
        advance_rcv_nxt(tsn);
    }
    else
        tracker->set_rcv_nxt(ack);
}
