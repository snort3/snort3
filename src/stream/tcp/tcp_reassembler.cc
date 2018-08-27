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

// tcp_reassembler.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassembler.h"

#include "detection/detection_engine.h"
#include "log/log.h"
#include "main/snort.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

void TcpReassembler::trace_segments(TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn = trs.sos.seglist.head;
    uint32_t sx = trs.tracker->r_win_base;
    unsigned segs = 0, bytes = 0;

    while ( tsn )
    {
        if (SEQ_LT(sx, tsn->c_seq))
            fprintf(stdout, " +%u", tsn->c_seq - sx);
        else if (SEQ_GT(sx, tsn->c_seq))
            fprintf(stdout, " -%u", sx - tsn->c_seq);

        fprintf(stdout, " %hu", tsn->c_len);

        segs++;
        bytes += tsn->i_len;
        sx = tsn->c_seq + tsn->c_len;
        tsn = tsn->next;
    }
    assert(trs.sos.seg_count == segs);
    assert(trs.sos.seg_bytes_logical == bytes);
}

bool TcpReassembler::is_segment_pending_flush(TcpReassemblerState& trs)
{
    return ( get_pending_segment_count(trs, 1) > 0 );
}

uint32_t TcpReassembler::get_pending_segment_count(TcpReassemblerState& trs, unsigned max)
{
    uint32_t n = trs.sos.seg_count - trs.flush_count;
    TcpSegmentNode* tsn;

    if ( !n || max == 1 )
        return n;

    n = 0;
    tsn = trs.sos.seglist.head;
    while ( tsn )
    {
        if ( tsn->c_len && SEQ_LT(tsn->c_seq, trs.tracker->r_win_base) )
            n++;

        if ( max && n == max )
            return n;

        tsn = tsn->next;
    }

    return n;
}

bool TcpReassembler::flush_data_ready(TcpReassemblerState& trs)
{
    // needed by stream_reassemble:action disable; can fire on rebuilt
    // packets, yanking the splitter out from under us :(
    if (!trs.tracker->flush_policy or !trs.tracker->splitter)
        return false;

    if ( (trs.tracker->flush_policy == STREAM_FLPOLICY_ON_DATA) or
        trs.tracker->splitter->is_paf() )
        return ( is_segment_pending_flush(trs) );

    return ( get_pending_segment_count(trs, 2) > 1 );  // FIXIT-L return false?
}

bool TcpReassembler::next_no_gap(TcpSegmentNode& tsn)
{
    return tsn.next and (tsn.next->i_seq == tsn.i_seq + tsn.i_len);
}

void TcpReassembler::update_next(TcpReassemblerState& trs, TcpSegmentNode& tsn)
{
    trs.sos.seglist.cur_rseg = next_no_gap(tsn) ?  tsn.next : nullptr;
    if ( trs.sos.seglist.cur_rseg )
    	trs.sos.seglist.cur_rseg->c_seq = trs.sos.seglist.cur_rseg->i_seq;
}

int TcpReassembler::delete_reassembly_segment(TcpReassemblerState& trs, TcpSegmentNode* tsn)
{
    int ret;
    assert(tsn);

    trs.sos.seglist.remove(tsn);
    trs.sos.seg_bytes_total -= tsn->i_len;
    trs.sos.seg_bytes_logical -= tsn->i_len;
    ret = tsn->i_len;

    if ( !tsn->c_len )
    {
        tcpStats.segs_used++;
        trs.flush_count--;
    }

    if ( trs.sos.seglist.cur_rseg == tsn )
        update_next(trs, *tsn);

    tsn->term();
    trs.sos.seg_count--;

    return ret;
}

void TcpReassembler::queue_reassembly_segment(
    TcpReassemblerState& trs, TcpSegmentNode* prev, TcpSegmentNode* tsn)
{
    trs.sos.seglist.insert(prev, tsn);
    if ( SEQ_EQ(tsn->i_seq, trs.sos.seglist_base_seq) )
    {
    	tsn->c_seq = tsn->i_seq;
        trs.sos.seglist.cur_rseg = tsn;
    }

    trs.sos.seg_count++;
    trs.sos.seg_bytes_total += tsn->i_len;
    trs.sos.total_segs_queued++;
    tcpStats.segs_queued++;
}

bool TcpReassembler::is_segment_fasttrack(
    TcpReassemblerState&, TcpSegmentNode* tail, TcpSegmentDescriptor& tsd)
{
    if ( SEQ_EQ(tsd.get_seg_seq(), tail->i_seq + tail->i_len) )
        return true;

    return false;
}

int TcpReassembler::add_reassembly_segment(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd, int16_t len, uint32_t slide,
    uint32_t trunc_len, uint32_t seq, TcpSegmentNode* left)
{
    TcpSegmentNode* tsn = nullptr;
    int32_t newSize = len - slide - trunc_len;

    if ( newSize <= 0 )
    {
        // FIXIT-L ideally newSize would not go negative
        //assert(newSize == 0);

        // zero size data because of trimming.  Don't insert it

        inc_tcp_discards();
        trs.tracker->normalizer.trim_win_payload(tsd);

        return STREAM_INSERT_OK;
    }

    // FIXIT-L don't allocate overlapped part
    tsn = TcpSegmentNode::init(tsd);
    tsn->offset = slide;
    tsn->c_len = (uint16_t)newSize;
    tsn->i_len = (uint16_t)newSize;
    tsn->i_seq = tsn->c_seq = seq;
    tsn->ts = tsd.get_ts();

    // FIXIT-M the urgent ptr handling is broken... urg_offset is set here but currently
    // not actually referenced anywhere else.  In 2.9.7 the FlushStream function did reference
    // this field but that code has been lost... urg ptr handling needs to be reviewed and fixed
    tsn->urg_offset = trs.tracker->normalizer.set_urg_offset(tsd.get_tcph(), tsd.get_seg_len() );

    queue_reassembly_segment(trs, left, tsn);

    trs.sos.seg_bytes_logical += tsn->c_len;
    trs.sos.total_bytes_queued += tsn->c_len;
    tsd.get_pkt()->packet_flags |= PKT_STREAM_INSERT;

    return STREAM_INSERT_OK;
}

int TcpReassembler::dup_reassembly_segment(
    TcpReassemblerState& trs, TcpSegmentNode* left, TcpSegmentNode** retSeg)
{
    TcpSegmentNode* tsn = TcpSegmentNode::init(*left);
    tcpStats.segs_split++;

    // twiddle the values for overlaps
    tsn->c_len = left->c_len;
    tsn->i_seq = tsn->c_seq = left->i_seq;
    queue_reassembly_segment(trs, left, tsn);

    *retSeg = tsn;
    return STREAM_INSERT_OK;
}

int TcpReassembler::purge_alerts(TcpReassemblerState& trs, Flow* flow)
{
    for (int i = 0; i < trs.tracker->alert_count; i++)
    {
        StreamAlertInfo* ai = trs.tracker->alerts + i;
        Stream::log_extra_data(flow, trs.xtradata_mask, ai->event_id, ai->event_second);
    }
    trs.tracker->alert_count = 0;

    return 0;
}

int TcpReassembler::purge_to_seq(TcpReassemblerState& trs, uint32_t flush_seq)
{
    assert(trs.sos.seglist.head != nullptr);
    int total_purged = 0;
    uint32_t last_ts = 0;

    TcpSegmentNode* tsn = trs.sos.seglist.head;
    while ( tsn && SEQ_LT(tsn->i_seq, flush_seq))
    {
        if ( !tsn->c_len )
    	{
            TcpSegmentNode* dump_me = tsn;
    		tsn = tsn->next;
    		if (dump_me->ts > last_ts)
    			last_ts = dump_me->ts;

    		total_purged += dump_me->last_flush_len;
    		delete_reassembly_segment(trs, dump_me);
    	}
    	else
    	{
    	    total_purged += tsn->last_flush_len;
    		tsn->last_flush_len = 0;
    		break;
    	}
    }

    if ( SEQ_LT(trs.tracker->rcv_nxt, flush_seq) )
        trs.tracker->rcv_nxt = flush_seq;

    purge_alerts(trs, trs.sos.session->flow);

    if ( trs.sos.seglist.head == nullptr )
        trs.sos.seglist.tail = nullptr;

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
        if ( trs.server_side )
        {
            int32_t delta = last_ts - trs.sos.session->client.get_ts_last();
            if ( delta > 0 )
                trs.sos.session->client.set_ts_last(last_ts);
        }
       else
        {
            int32_t delta = last_ts - trs.sos.session->server.get_ts_last();
            if ( delta > 0 )
                trs.sos.session->server.set_ts_last(last_ts);
        }
    }

    return total_purged;
}

// purge_flushed_ackd():
// must only purge flushed and acked bytes we may flush partial segments
// must adjust seq->seq and tsn->size when a flush gets only the  initial
// part of a segment
// * FIXIT-L need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
int TcpReassembler::purge_flushed_ackd(TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn = trs.sos.seglist.head;
    uint32_t seq;

    if (!trs.sos.seglist.head)
        return 0;

    seq = trs.sos.seglist.head->i_seq;

    while ( tsn && !tsn->c_len )
    {
        uint32_t end = tsn->i_seq + tsn->i_len;

        if ( SEQ_GT(end, trs.tracker->r_win_base) )
        {
            seq = trs.tracker->r_win_base;
            break;
        }
        seq = end;
        tsn = tsn->next;
    }

    if ( seq != trs.sos.seglist.head->i_seq )
        return purge_to_seq(trs, seq);

    return 0;
}

void TcpReassembler::show_rebuilt_packet(TcpReassemblerState& trs, Packet* pkt)
{
    if ( trs.sos.session->config->flags & STREAM_CONFIG_SHOW_PACKETS )
    {
        LogFlow(pkt);
        LogNetData(pkt->data, pkt->dsize, pkt);
    }
}

uint32_t TcpReassembler::get_flush_data_len(
    TcpReassemblerState& trs, TcpSegmentNode* tsn, uint32_t to_seq, unsigned max)
{
    unsigned int flush_len = ( tsn->c_len <= max ) ? tsn->c_len : max;

    // copy only to flush point
    if ( paf_active(&trs.tracker->paf_state) && SEQ_GT(tsn->c_seq + flush_len, to_seq) )
        flush_len = to_seq - tsn->c_seq;

    return flush_len;
}

// flush the client trs.sos.seglist up to the most recently acked segment
int TcpReassembler::flush_data_segments(
    TcpReassemblerState& trs, Packet* p, uint32_t total, Packet* pdu)
{
    uint32_t total_flushed = 0;
    uint32_t flags = PKT_PDU_HEAD;

    assert(trs.sos.seglist.cur_rseg);
    DeepProfile profile(s5TcpBuildPacketPerfStats);

    uint32_t to_seq = trs.sos.seglist.cur_rseg->c_seq + total;

    while ( SEQ_LT(trs.sos.seglist.cur_rseg->c_seq, to_seq) )
    {
        TcpSegmentNode* tsn = trs.sos.seglist.cur_rseg;
        unsigned bytes_copied = 0;
        unsigned bytes_to_copy = get_flush_data_len(
            trs, tsn, to_seq, trs.tracker->splitter->max(p->flow));
        assert(bytes_to_copy);

        if ( !tsn->next or (bytes_to_copy < tsn->c_len) or
            SEQ_EQ(tsn->c_seq + bytes_to_copy, to_seq) or
            (total_flushed + tsn->c_len + tsn->next->c_len >
                trs.tracker->splitter->get_max_pdu()) )
        {
            flags |= PKT_PDU_TAIL;
        }
        const StreamBuffer sb = trs.tracker->splitter->reassemble(
            trs.sos.session->flow, total, total_flushed, tsn->payload(),
            bytes_to_copy, flags, bytes_copied);

        if ( sb.data )
        {
            pdu->data = sb.data;
            pdu->dsize = sb.length;
            assert(sb.length <= Packet::max_dsize);
        }

        total_flushed += bytes_copied;
        tsn->c_seq += bytes_copied;
        tsn->c_len -= bytes_copied;
        tsn->offset += bytes_copied;
        tsn->last_flush_len = bytes_copied;
        flags = 0;

        if ( !tsn->c_len )
        {
            trs.flush_count++;
            update_next(trs, *tsn);
            if ( SEQ_EQ(tsn->c_seq, to_seq) )
                break;
        }

        /* Check for a gap/missing packet */
        // FIXIT-L PAF should account for missing data and resume
        // scanning at the start of next PDU instead of aborting.
        // FIXIT-L FIN may be in to_seq causing bogus gap counts.
        if ( tsn->is_packet_missing(to_seq) )
        {
            // FIXIT-L this is suboptimal - better to exclude fin from to_seq
            if ( !trs.tracker->is_fin_seq_set() or
                SEQ_LEQ(to_seq, trs.tracker->get_fin_final_seq()) )
            {
                trs.tracker->set_tf_flags(TF_MISSING_PKT);
            }
            break;
        }

        if ( ( sb.data || !trs.sos.seglist.cur_rseg ) or
             ( ( total_flushed + trs.sos.seglist.cur_rseg->c_len ) >
                 trs.tracker->splitter->get_max_pdu() ) )
            break;
    }

    return total_flushed;
}

// FIXIT-L consolidate encode format, update, and this into new function?
void TcpReassembler::prep_pdu(
    TcpReassemblerState&, Flow* flow, Packet* p, uint32_t pkt_flags, Packet* pdu)
{
    pdu->ptrs.set_pkt_type(PktType::PDU);
    pdu->proto_bits |= PROTO_BIT__TCP;
    pdu->packet_flags |= (pkt_flags & PKT_PDU_FULL);
    pdu->flow = flow;

    if (p == pdu)
    {
        // final
        if (pkt_flags & PKT_FROM_SERVER)
        {
            pdu->packet_flags |= PKT_FROM_SERVER;
            pdu->ptrs.ip_api.set(flow->server_ip, flow->client_ip);
            pdu->ptrs.sp = flow->server_port;
            pdu->ptrs.dp = flow->client_port;
        }
        else
        {
            pdu->packet_flags |= PKT_FROM_CLIENT;
            pdu->ptrs.ip_api.set(flow->client_ip, flow->server_ip);
            pdu->ptrs.sp = flow->client_port;
            pdu->ptrs.dp = flow->server_port;
        }
    }
    else if (!p->packet_flags || (pkt_flags & p->packet_flags))
    {
        // forward
        pdu->packet_flags |= (p->packet_flags
            & (PKT_FROM_CLIENT | PKT_FROM_SERVER));
        pdu->ptrs.ip_api.set(*p->ptrs.ip_api.get_src(),
            *p->ptrs.ip_api.get_dst());
        pdu->ptrs.sp = p->ptrs.sp;
        pdu->ptrs.dp = p->ptrs.dp;
    }
    else
    {
        // reverse
        if (p->is_from_client())
            pdu->packet_flags |= PKT_FROM_SERVER;
        else
            pdu->packet_flags |= PKT_FROM_CLIENT;

        pdu->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(),
            *p->ptrs.ip_api.get_src());
        pdu->ptrs.dp = p->ptrs.sp;
        pdu->ptrs.sp = p->ptrs.dp;
    }
}

Packet* TcpReassembler::initialize_pdu(
    TcpReassemblerState& trs, Packet* p, uint32_t pkt_flags, struct timeval tv)
{
    DetectionEngine::onload(trs.sos.session->flow);
    Packet* pdu = DetectionEngine::set_next_packet(p);

    EncodeFlags enc_flags = 0;
    DAQ_PktHdr_t pkth;
    trs.sos.session->GetPacketHeaderFoo(&pkth, pkt_flags);
    PacketManager::format_tcp(enc_flags, p, pdu, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
    prep_pdu(trs, trs.sos.session->flow, p, pkt_flags, pdu);
    (const_cast<DAQ_PktHdr_t*>(pdu->pkth))->ts = tv;
    pdu->dsize = 0;
    pdu->data = nullptr;
    return pdu;
}

int TcpReassembler::_flush_to_seq(
    TcpReassemblerState& trs, uint32_t bytes, Packet* p, uint32_t pkt_flags)
{
    DeepProfile profile(s5TcpFlushPerfStats);
    DetectionEngine::onload(trs.sos.session->flow);

    if ( !p )
    {
        // FIXIT-H we need to have user_policy_id in this case
        // FIXIT-H this leads to format_tcp() copying from pdu to pdu
        // (neither of these issues is created by passing null through to here)
        p = DetectionEngine::set_next_packet();
    }

    uint32_t bytes_processed = 0;
    uint32_t stop_seq = trs.sos.seglist.cur_rseg->c_seq + bytes;

    while ( trs.sos.seglist.cur_rseg and SEQ_LT(trs.sos.seglist.cur_rseg->c_seq, stop_seq) )
    {
        trs.sos.seglist_base_seq = trs.sos.seglist.cur_rseg->c_seq;
        uint32_t footprint = stop_seq - trs.sos.seglist_base_seq;

        if ( footprint == 0 )
            return bytes_processed;

        if ( footprint > Packet::max_dsize )
            /* this is as much as we can pack into a stream buffer */
            footprint = Packet::max_dsize;

        if ( trs.tracker->splitter->is_paf() and
            ( trs.tracker->get_tf_flags() & TF_MISSING_PREV_PKT ) )
            fallback(trs);

        Packet* pdu = initialize_pdu(trs, p, pkt_flags, trs.sos.seglist.cur_rseg->tv);
        int32_t flushed_bytes = flush_data_segments(trs, p, footprint, pdu);
        if ( flushed_bytes == 0 )
            break; /* No more data... bail */

        bytes_processed += flushed_bytes;
        trs.sos.seglist_base_seq += flushed_bytes;

        if ( pdu->dsize )
        {
            if ( p->packet_flags & PKT_PDU_TAIL )
                pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_TAIL );
            else
                pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST );

            show_rebuilt_packet(trs, pdu);
            tcpStats.rebuilt_packets++;
            tcpStats.rebuilt_bytes += flushed_bytes;

            NoProfile exclude(s5TcpFlushPerfStats);
            Snort::inspect(pdu);
        }
        else
        {
            tcpStats.rebuilt_buffers++; // FIXIT-L this is not accurate
        }

        // FIXIT-L must check because above may clear trs.sos.session
        if ( trs.tracker->splitter )
            trs.tracker->splitter->update();

        // FIXIT-L abort should be by PAF callback only since recovery may be possible
        if ( trs.tracker->get_tf_flags() & TF_MISSING_PKT )
        {
            trs.tracker->set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);
            trs.tracker->clear_tf_flags(TF_MISSING_PKT);
            tcpStats.gaps++;
        }
        else
            trs.tracker->clear_tf_flags(TF_MISSING_PREV_PKT);

        // check here instead of in while to allow single segment flushes
        if ( !flush_data_ready(trs) )
            break;
    }

    return bytes_processed;
}

// flush a seglist up to the given point, generate a pseudopacket, and fire it thru the system.
int TcpReassembler::flush_to_seq(
    TcpReassemblerState& trs, uint32_t bytes, Packet* p, uint32_t pkt_flags)
{
    if ( !bytes || !trs.sos.seglist.cur_rseg )
        return 0;

    if ( !flush_data_ready(trs) and !(trs.tracker->get_tf_flags() & TF_FORCE_FLUSH) and
        !trs.tracker->splitter->is_paf() )
        return 0;

    trs.tracker->clear_tf_flags(TF_MISSING_PKT | TF_MISSING_PREV_PKT);

    /* This will set this flag on the first reassembly
     * if reassembly for this direction was set midstream */
    if ( SEQ_LT(trs.sos.seglist_base_seq, trs.sos.seglist.cur_rseg->c_seq) )
    {
        uint32_t missed = trs.sos.seglist.cur_rseg->c_seq - trs.sos.seglist_base_seq;

        if ( missed <= bytes )
            bytes -= missed;

        trs.tracker->set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);

        tcpStats.gaps++;
        trs.sos.seglist_base_seq = trs.sos.seglist.cur_rseg->c_seq;

        if ( !bytes )
            return 0;
    }

    return _flush_to_seq(trs, bytes, p, pkt_flags);
}

// flush a seglist up to the given point, generate a pseudopacket, and fire it thru the system.
int TcpReassembler::do_zero_byte_flush(TcpReassemblerState& trs, Packet* p, uint32_t pkt_flags)
{
    unsigned bytes_copied = 0;

    const StreamBuffer sb = trs.tracker->splitter->reassemble(
        trs.sos.session->flow, 0, 0, nullptr, 0, (PKT_PDU_HEAD | PKT_PDU_TAIL), bytes_copied);

     if ( sb.data )
     {
        Packet* pdu = initialize_pdu(trs, p, pkt_flags, p->pkth->ts);
        /* setup the pseudopacket payload */
        pdu->data = sb.data;
        pdu->dsize = sb.length;
        pdu->packet_flags |= (PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_HEAD | PKT_PDU_TAIL);
        trs.flush_count++;

        show_rebuilt_packet(trs, pdu);
        NoProfile profile_exclude(s5TcpFlushPerfStats);
        Snort::inspect(pdu);

        if ( trs.tracker->splitter )
            trs.tracker->splitter->update();
     }

     return bytes_copied;
}

// get the footprint for the current trs.sos.seglist, the difference
// between our base sequence and the last ack'd sequence we received

uint32_t TcpReassembler::get_q_footprint(TcpReassemblerState& trs)
{
    int32_t footprint = 0, sequenced = 0;

    if ( !trs.tracker )
        return 0;

    footprint = trs.tracker->r_win_base - trs.sos.seglist_base_seq;

    if ( footprint )
    {
        sequenced = get_q_sequenced(trs);

        if ( trs.tracker->fin_seq_status == TcpStreamTracker::FIN_WITH_SEQ_ACKED )
            --footprint;
    }

    return ( footprint > sequenced ) ? sequenced : footprint;
}

// FIXIT-P get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as trs.sos.seglist is updated
// to avoid the while loop, etc. below.

uint32_t TcpReassembler::get_q_sequenced(TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn;

    if ( trs.sos.seglist.cur_rseg )
        tsn = trs.sos.seglist.cur_rseg;
    else
    {
        trs.sos.seglist.cur_rseg = trs.sos.seglist.head;
        tsn = trs.tracker ? trs.sos.seglist.cur_rseg : nullptr;  // FIXIT-H why check tracker here?

        if ( !tsn or (trs.sos.session->flow->two_way_traffic() and
            SEQ_LT(trs.tracker->r_win_base, tsn->c_seq)) )
        {
            if ( trs.sos.seglist.cur_rseg )
                trs.sos.seglist.cur_rseg = trs.sos.seglist.cur_rseg->prev;

            if ( trs.sos.seglist.cur_rseg )
            	trs.sos.seglist.cur_rseg->c_seq = trs.sos.seglist.cur_rseg->i_seq;
            return 0;
        }
    }

    uint32_t len = 0;
    const uint32_t limit = trs.tracker->splitter->get_max_pdu();

    while ( len < limit and next_no_gap(*tsn) )
    {
        if ( !tsn->c_len )
            trs.sos.seglist.cur_rseg = tsn->next;
        else
            len += tsn->c_len;

        tsn = tsn->next;
    }
    if ( tsn->c_len )
        len += tsn->c_len;

    trs.sos.seglist_base_seq = trs.sos.seglist.cur_rseg->c_seq;

    return len;
}

// FIXIT-L flush_stream() calls should be replaced with calls to
// CheckFlushPolicyOn*() with the exception that for the *OnAck() case,
// any available ackd data must be flushed in both directions.
int TcpReassembler::flush_stream(
    TcpReassemblerState& trs, Packet* p, uint32_t dir, bool final_flush)
{
    // this is not always redundant; stream_reassemble rule option causes trouble
    if ( !trs.tracker->flush_policy or !trs.tracker->splitter )
        return 0;

    uint32_t bytes;

    if ( trs.tracker->normalizer.is_tcp_ips_enabled() )
        bytes = get_q_sequenced(trs);
    else
        bytes = get_q_footprint(trs);

    if ( bytes )
        return flush_to_seq(trs, bytes, p, dir);

    if ( final_flush )
        return do_zero_byte_flush(trs, p, dir);

    return 0;
}

void TcpReassembler::final_flush(TcpReassemblerState& trs, Packet* p, uint32_t dir)
{
    trs.tracker->set_tf_flags(TF_FORCE_FLUSH);

    if ( flush_stream(trs, p, dir, true) )
    {
        if ( trs.server_side )
            tcpStats.server_cleanups++;
        else
            tcpStats.client_cleanups++;

        purge_flushed_ackd(trs);
    }
    trs.tracker->clear_tf_flags(TF_FORCE_FLUSH);
}

static Packet* set_packet(Flow* flow, uint32_t flags, bool c2s)
{
    Packet* p = DetectionEngine::get_current_packet();
    p->reset();

    DAQ_PktHdr_t* ph = const_cast<DAQ_PktHdr_t*>(p->pkth);
    memset(ph, 0, sizeof(*ph));
    packet_gettimeofday(&ph->ts);

    p->ptrs.set_pkt_type(PktType::PDU);
    p->proto_bits |= PROTO_BIT__TCP;
    p->flow = flow;
    p->packet_flags = flags;

    if ( c2s )
    {
        p->ptrs.ip_api.set(flow->client_ip, flow->server_ip);
        p->ptrs.sp = flow->client_port;
        p->ptrs.dp = flow->server_port;
    }
    else
    {
        p->ptrs.ip_api.set(flow->server_ip, flow->client_ip);
        p->ptrs.sp = flow->server_port;
        p->ptrs.dp = flow->client_port;
    }
    return p;
}

void TcpReassembler::flush_queued_segments(
    TcpReassemblerState& trs, Flow* flow, bool clear, Packet* p)
{
    if ( !p )
    {
        // this packet is required if we call finish and/or final_flush
        p = set_packet(flow, trs.packet_dir, trs.server_side);
    }

    bool pending = clear and paf_initialized(&trs.tracker->paf_state)
        and (!trs.tracker->splitter or trs.tracker->splitter->finish(flow) );

    if ( pending and !(flow->ssn_state.ignore_direction & trs.ignore_dir) )
        final_flush(trs, p, trs.packet_dir);
}

// this is for post-ack flushing
uint32_t TcpReassembler::get_reverse_packet_dir(TcpReassemblerState&, const Packet* p)
{
    /* Remember, one side's packets are stored in the
     * other side's queue.  So when talker ACKs data,
     * we need to check if we're ready to flush.
     *
     * If we do decide to flush, the flush IP & port info
     * is the opposite of the packet -- again because this
     * is the ACK from the talker and we're flushing packets
     * that actually came from the listener.
     */
    if ( p->is_from_server() )
        return PKT_FROM_CLIENT;

    if ( p->is_from_client() )
        return PKT_FROM_SERVER;

    return 0;
}

uint32_t TcpReassembler::get_forward_packet_dir(TcpReassemblerState&, const Packet* p)
{
    if ( p->is_from_server() )
        return PKT_FROM_SERVER;

    if ( p->is_from_client() )
        return PKT_FROM_CLIENT;

    return 0;
}

// see flush_pdu_ackd() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
int32_t TcpReassembler::flush_pdu_ips(TcpReassemblerState& trs, uint32_t* flags)
{
    DeepProfile profile(s5TcpPAFPerfStats);
    DetectionEngine::onload(trs.sos.session->flow);

    uint32_t total = 0, avail;
    TcpSegmentNode* tsn;

    avail = get_q_sequenced(trs);
    tsn = trs.sos.seglist.cur_rseg;

    // * must stop if gap (checked in paf_check)
    while ( tsn && *flags && ( total < avail ) )
    {
        int32_t flush_pt;
        uint32_t size = tsn->c_len;
        uint32_t end = tsn->c_seq + tsn->c_len;
        uint32_t pos = paf_position(&trs.tracker->paf_state);

        total += size;

        if ( paf_initialized(&trs.tracker->paf_state) && SEQ_LEQ(end, pos) )
        {
            tsn = tsn->next;
            continue;
        }

        flush_pt = paf_check(
            trs.tracker->splitter, &trs.tracker->paf_state, trs.sos.session->flow,
            tsn->payload(), size, total, tsn->c_seq, flags);

        if (flush_pt >= 0)
        {
            // see flush_pdu_ackd()
            if ( !trs.tracker->splitter->is_paf() && avail > (unsigned)flush_pt )
            {
                paf_jump(&trs.tracker->paf_state, avail - (unsigned)flush_pt);
                return avail;
            }
            return flush_pt;
        }
        tsn = tsn->next;
    }

    return -1;
}

void TcpReassembler::fallback(TcpReassemblerState& trs)
{
    bool c2s = trs.tracker->splitter->to_server();

    delete trs.tracker->splitter;
    trs.tracker->splitter = new AtomSplitter(c2s, trs.sos.session->config->paf_max);
    trs.tracker->paf_state.paf = StreamSplitter::SEARCH;

    trs.sos.session->flow->set_session_flags(
        c2s ? SSNFLAG_ABORT_CLIENT : SSNFLAG_ABORT_SERVER );
}

// iterate over trs.sos.seglist and scan all new acked bytes
// - new means not yet scanned
// - must use trs.sos.seglist data (not packet) since this packet may plug a
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

int32_t TcpReassembler::flush_pdu_ackd(TcpReassemblerState& trs, uint32_t* flags)
{
    DeepProfile profile(s5TcpPAFPerfStats);
    DetectionEngine::onload(trs.sos.session->flow);

    uint32_t total = 0;
    TcpSegmentNode* tsn =
        SEQ_LT(trs.sos.seglist_base_seq, trs.tracker->r_win_base) ? trs.sos.seglist.head : nullptr;

    // must stop if not acked
    // must use adjusted size of tsn if not fully acked
    // must stop if gap (checked in paf_check)
    while (tsn && *flags && SEQ_LT(tsn->c_seq, trs.tracker->r_win_base))
    {
        int32_t flush_pt;
        uint32_t size = tsn->c_len;
        uint32_t end = tsn->c_seq + tsn->c_len;
        uint32_t pos = paf_position(&trs.tracker->paf_state);

        if ( paf_initialized(&trs.tracker->paf_state) && SEQ_LEQ(end, pos) )
        {
            total += size;
            tsn = tsn->next;
            continue;
        }

        if ( SEQ_GT(end, trs.tracker->r_win_base))
            size = trs.tracker->r_win_base - tsn->c_seq;

        total += size;
        flush_pt = paf_check(
            trs.tracker->splitter, &trs.tracker->paf_state, trs.sos.session->flow,
            tsn->payload(), size, total, tsn->c_seq, flags);

        if ( flush_pt >= 0 )
        {
        	trs.sos.seglist.cur_rseg = trs.sos.seglist.head;
        	trs.sos.seglist_base_seq = trs.sos.seglist.head->c_seq;
            // for non-paf splitters, flush_pt > 0 means we reached
            // the minimum required, but we flush what is available
            // instead of creating more, but smaller, packets
            // FIXIT-L just flush to end of segment to avoid splitting
            // instead of all avail?
            if ( !trs.tracker->splitter->is_paf() )
            {
                // get_q_footprint() w/o side effects
                int32_t avail = trs.tracker->r_win_base - trs.sos.seglist_base_seq;

                if ( avail > flush_pt )
                {
                    paf_jump(&trs.tracker->paf_state, avail - flush_pt);
                    return avail;
                }
            }
            return flush_pt;
        }
        tsn = tsn->next;
    }

    return -1;
}

int TcpReassembler::flush_on_data_policy(TcpReassemblerState& trs, Packet* p)
{
    uint32_t flushed = 0;

    switch ( trs.tracker->flush_policy )
    {
    case STREAM_FLPOLICY_IGNORE:
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
        break;

    case STREAM_FLPOLICY_ON_DATA:
    {
        uint32_t flags = get_forward_packet_dir(trs, p);
        int32_t flush_amt = flush_pdu_ips(trs, &flags);

        while ( flush_amt >= 0 )
        {
            if ( !flush_amt )
                flush_amt = trs.sos.seglist.cur_rseg->c_seq - trs.sos.seglist_base_seq;

            uint32_t this_flush = flush_to_seq(trs, flush_amt, p, flags);
            if (!this_flush)
                break;       // bail if nothing flushed

            flushed += this_flush;
            flags = get_forward_packet_dir(trs, p);
            flush_amt = flush_pdu_ips(trs, &flags);
        }

        if ( !flags && trs.tracker->splitter->is_paf() )
        {
            fallback(trs);
            return flush_on_data_policy(trs, p);
        }
    }
    break;
    }

    return flushed;
}

int TcpReassembler::flush_on_ack_policy(TcpReassemblerState& trs, Packet* p)
{
	uint32_t flushed = 0;

    switch (trs.tracker->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
    {
        uint32_t flags = get_reverse_packet_dir(trs, p);
        int32_t flush_amt = flush_pdu_ackd(trs, &flags);

        while (flush_amt >= 0)
        {
            if (!flush_amt)
                flush_amt = trs.sos.seglist.cur_rseg->c_seq - trs.sos.seglist_base_seq;

            // for consistency with other cases, should return total
            // but that breaks flushing pipelined pdus
            flushed = flush_to_seq(trs, flush_amt, p, flags);

            // ideally we would purge just once after this loop but that throws off base
            if ( flushed and trs.sos.seglist.head )
            {
                purge_to_seq(trs, trs.sos.seglist_base_seq);
                flags = get_reverse_packet_dir(trs, p);
                flush_amt = flush_pdu_ackd(trs, &flags);
            }
            else
                break;  // bail if nothing flushed
        }

        if (!flags && trs.tracker->splitter->is_paf())
        {
            fallback(trs);
            return flush_on_ack_policy(trs, p);
        }
    }
    break;

    case STREAM_FLPOLICY_ON_DATA:
        purge_flushed_ackd(trs);
        break;
    }

    return flushed;
}

void TcpReassembler::purge_segment_list(TcpReassemblerState& trs)
{
    trs.sos.seglist.reset();
    trs.sos.seg_count = 0;
    trs.sos.seg_bytes_total = 0;
    trs.sos.seg_bytes_logical = 0;
    trs.flush_count = 0;
}

void TcpReassembler::insert_segment_in_empty_seglist(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    uint32_t overlap = 0;
    uint32_t seq = tsd.get_seg_seq();

    if ( tcph->is_syn() )
        seq++;

    if ( SEQ_GT(trs.tracker->r_win_base, seq) )
    {
        overlap = trs.tracker->r_win_base - tsd.get_seg_seq();

        if ( overlap >= tsd.get_seg_len() )
            return;
    }

    // BLOCK add new block to trs.sos.seglist containing data
    add_reassembly_segment(
        trs, tsd, tsd.get_seg_len(), overlap, 0, seq + overlap, nullptr);

}

void TcpReassembler::init_overlap_editor(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    TcpSegmentNode* left = nullptr, *right = nullptr, *tsn = nullptr;
    int32_t dist_head = 0, dist_tail = 0;

    if ( trs.sos.seglist.head && trs.sos.seglist.tail )
    {
        if ( SEQ_GT(tsd.get_seg_seq(), trs.sos.seglist.head->i_seq) )
            dist_head = tsd.get_seg_seq() - trs.sos.seglist.head->i_seq;
        else
            dist_head = trs.sos.seglist.head->i_seq - tsd.get_seg_seq();

        if ( SEQ_GT(tsd.get_seg_seq(), trs.sos.seglist.tail->i_seq) )
            dist_tail = tsd.get_seg_seq() - trs.sos.seglist.tail->i_seq;
        else
            dist_tail = trs.sos.seglist.tail->i_seq - tsd.get_seg_seq();
    }

    if ( SEQ_LEQ(dist_head, dist_tail) )
    {
        for ( tsn = trs.sos.seglist.head; tsn; tsn = tsn->next )
        {
            right = tsn;

            if ( SEQ_GEQ(right->i_seq, tsd.get_seg_seq() ) )
                break;

            left = right;
        }

        if ( tsn == nullptr )
            right = nullptr;
    }
    else
    {
        for ( tsn = trs.sos.seglist.tail; tsn; tsn = tsn->prev )
        {
            left = tsn;

            if ( SEQ_LT(left->i_seq, tsd.get_seg_seq() ) )
                break;

            right = left;
        }

        if (tsn == nullptr)
            left = nullptr;
    }

    trs.sos.init_soe(tsd, left, right);
}

int TcpReassembler::insert_segment_in_seglist(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    int rc = STREAM_INSERT_OK;

    // NORM fast tracks are in sequence - no norms
    if ( trs.sos.seglist.tail && is_segment_fasttrack(trs, trs.sos.seglist.tail, tsd) )
    {
        /* segment fit cleanly at the end of the segment list */
        rc = add_reassembly_segment(trs, tsd, tsd.get_seg_len(), 0, 0,
        		tsd.get_seg_seq(), trs.sos.seglist.tail);
        return rc;
    }

    init_overlap_editor(trs, tsd);
    rc = eval_left(trs);

    if ( rc != STREAM_INSERT_OK )
        return rc;

    rc = eval_right(trs);

    if ( rc != STREAM_INSERT_OK )
        return rc;

    if ( trs.sos.keep_segment )
    {
        /* Adjust slide so that is correct relative to orig seq */
        trs.sos.slide = trs.sos.seq - tsd.get_seg_seq();
        rc = add_reassembly_segment(
            trs, tsd, trs.sos.len, trs.sos.slide, trs.sos.trunc_len, trs.sos.seq, trs.sos.left);
    }
    else
        rc = STREAM_INSERT_OK;

    return rc;
}

int TcpReassembler::queue_packet_for_reassembly(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    DeepProfile profile(s5TcpInsertPerfStats);

    int rc = STREAM_INSERT_OK;

    if ( trs.sos.seg_count == 0 )
    {
        insert_segment_in_empty_seglist(trs, tsd);
        return STREAM_INSERT_OK;
    }

    if ( SEQ_GT(trs.tracker->r_win_base, tsd.get_seg_seq() ) )
    {
        int32_t offset = trs.tracker->r_win_base - tsd.get_seg_seq();

        if ( offset < tsd.get_seg_len() )
        {
            tsd.slide_segment_in_rcv_window(offset);
            rc = insert_segment_in_seglist(trs, tsd);
            tsd.slide_segment_in_rcv_window(-offset);
        }
    }
    else
        rc = insert_segment_in_seglist(trs, tsd);

    return rc;
}

