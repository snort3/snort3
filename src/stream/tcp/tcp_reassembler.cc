//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
#include "detection/detection_engine.h"
#include "protocols/packet_manager.h"
#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_normalizer.h"

ReassemblyPolicy stream_reassembly_policy_map[] =
{
    ReassemblyPolicy::OS_INVALID,
    ReassemblyPolicy::OS_FIRST,
    ReassemblyPolicy::OS_LAST,
    ReassemblyPolicy::OS_LINUX,
    ReassemblyPolicy::OS_OLD_LINUX,
    ReassemblyPolicy::OS_BSD,
    ReassemblyPolicy::OS_MACOS,
    ReassemblyPolicy::OS_SOLARIS,
    ReassemblyPolicy::OS_IRIX,
    ReassemblyPolicy::OS_HPUX11,
    ReassemblyPolicy::OS_HPUX10,
    ReassemblyPolicy::OS_WINDOWS,
    ReassemblyPolicy::OS_WINDOWS2K3,
    ReassemblyPolicy::OS_VISTA,
    ReassemblyPolicy::OS_PROXY,
    ReassemblyPolicy::OS_DEFAULT
};

void TcpReassembler::set_tcp_reassembly_policy(StreamPolicy os_policy)
{
    reassembly_policy = stream_reassembly_policy_map[ static_cast<int>( os_policy ) ];
}

void TcpReassembler::trace_segments()
{
    TcpSegmentNode* tsn = seglist.head;
    uint32_t sx = tracker->r_win_base;
    unsigned segs = 0, bytes = 0;

    while ( tsn )
    {
        if (SEQ_LT(sx, tsn->seq))
            fprintf(stdout, " +%u", tsn->seq - sx);
        else if (SEQ_GT(sx, tsn->seq))
            fprintf(stdout, " -%u", sx - tsn->seq);

        fprintf(stdout, " %hu", tsn->payload_size);

        segs++;
        bytes += tsn->payload_size;

        sx = tsn->seq + tsn->payload_size;
        tsn = tsn->next;
    }
    assert(seg_count == segs);
    assert(seg_bytes_logical == bytes);
}

bool TcpReassembler::is_segment_pending_flush()
{
    return ( get_pending_segment_count(1) > 0 );
}

uint32_t TcpReassembler::get_pending_segment_count(unsigned max)
{
    uint32_t n = seg_count - flush_count;
    TcpSegmentNode* tsn;

    if ( !n || max == 1 )
        return n;

    n = 0;
    tsn = seglist.head;
    while ( tsn )
    {
        if ( !tsn->buffered && SEQ_LT(tsn->seq, tracker->r_win_base) )
            n++;

        if ( max && n == max )
            return n;

        tsn = tsn->next;
    }

    return n;
}

bool TcpReassembler::flush_data_ready()
{
    // needed by stream_reassemble:action disable; can fire on rebuilt
    // packets, yanking the splitter out from under us :(
    if (!tracker->flush_policy or !tracker->splitter)
        return false;

    if (tracker->flush_policy == STREAM_FLPOLICY_ON_DATA || tracker->splitter->is_paf())
        return ( is_segment_pending_flush( ) );

    return ( get_pending_segment_count(2) > 1 );  // FIXIT-L return false?
}

int TcpReassembler::delete_reassembly_segment(TcpSegmentNode* tsn)
{
    int ret;
    assert(tsn);

    DebugFormat(DEBUG_STREAM_STATE, "Dropping segment at seq %X, len %d\n", tsn->seq,
        tsn->payload_size);

    if (tsn->prev)
        tsn->prev->next = tsn->next;
    else
        seglist.head = tsn->next;

    if (tsn->next)
        tsn->next->prev = tsn->prev;
    else
        seglist.tail = tsn->prev;

    seg_bytes_logical -= tsn->payload_size;
    seg_bytes_total -= tsn->orig_dsize;

    ret = tsn->orig_dsize;

    if (tsn->buffered)
    {
        tcpStats.segs_used++;
        flush_count--;
    }

    if (seglist.next == tsn)
        seglist.next = NULL;

    tsn->term( );
    seg_count--;

    return ret;
}

int TcpReassembler::trim_delete_reassembly_segment(TcpSegmentNode* tsn, uint32_t flush_seq)
{
    if ( paf_active(&tracker->paf_state) && ( ( tsn->seq + tsn->payload_size ) > flush_seq ) )
    {
        uint32_t delta = flush_seq - tsn->seq;

        if (delta < tsn->payload_size)
        {
            DebugFormat(DEBUG_STREAM_STATE, "Left-Trimming segment at seq %X, len %d, delta %u\n",
                tsn->seq, tsn->payload_size, delta);

            tsn->seq = flush_seq;
            tsn->payload_size -= (uint16_t)delta;
            seg_bytes_logical -= delta;
            return 0;
        }
    }

    return delete_reassembly_segment(tsn);
}

void TcpReassembler::queue_reassembly_segment(TcpSegmentNode* prev, TcpSegmentNode* tsn)
{
    seglist.insert(prev, tsn);
    seg_count++;
    seg_bytes_total += tsn->orig_dsize;
    total_segs_queued++;
    tcpStats.segs_queued++;
}

bool TcpReassembler::is_segment_fasttrack(TcpSegmentNode* tail, TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE,  "Checking seq for fast track: %X > %X\n", tsd.get_seg_seq(),
        tail->seq + tail->payload_size);

    if ( SEQ_EQ(tsd.get_seg_seq(), tail->seq + tail->payload_size) )
        return true;

    return false;
}

int TcpReassembler::add_reassembly_segment(TcpSegmentDescriptor& tsd, int16_t len, uint32_t slide,
    uint32_t trunc_len,
    uint32_t seq, TcpSegmentNode* left)
{
    TcpSegmentNode* tsn = nullptr;
    int32_t newSize = len - slide - trunc_len;

    if ( newSize <= 0 )
    {
        // FIXIT-L ideally newSize would not go negative
        //assert(newSize == 0);

        // zero size data because of trimming.  Don't insert it
        DebugFormat(DEBUG_STREAM_STATE, "zero size TCP data after left & right trimming "
            "(len: %hd slide: %u trunc: %u)\n", len, slide, trunc_len);

        inc_tcp_discards();
        tracker->normalizer->trim_win_payload(tsd);

        return STREAM_INSERT_OK;
    }

    // FIXIT-L don't allocate overlapped part
    tsn = TcpSegmentNode::init(tsd);
    tsn->offset = slide;
    tsn->payload_size = (uint16_t)newSize;
    tsn->seq = seq;
    tsn->ts = tsd.get_ts();

    // FIXIT-M the urgent ptr handling is broken... urg_offset is set here but currently
    // not actually referenced anywhere else.  In 2.9.7 the FlushStream function did reference
    // this field but that code has been lost... urg ptr handling needs to be reviewed and fixed
    tsn->urg_offset = tracker->normalizer->set_urg_offset(tsd.get_tcph(), tsd.get_seg_len() );
    queue_reassembly_segment(left, tsn);
    seg_bytes_logical += tsn->payload_size;
    total_bytes_queued += tsn->payload_size;
    tsd.get_pkt()->packet_flags |= PKT_STREAM_INSERT;

    DebugFormat(DEBUG_STREAM_STATE,
        "added %hu bytes on segment list @ seq: 0x%X, total %u, %u segments queued\n",
        tsn->payload_size, tsn->seq, seg_bytes_logical, get_pending_segment_count(0));

#ifdef SEG_TEST
    CheckSegments(tracker);
#endif
    return STREAM_INSERT_OK;
}

int TcpReassembler::dup_reassembly_segment(TcpSegmentNode* left, TcpSegmentNode** retSeg)
{
    TcpSegmentNode* tsn = TcpSegmentNode::init(*left);
    tcpStats.segs_split++;

    // twiddle the values for overlaps
    tsn->payload_size = left->payload_size;
    tsn->seq = left->seq;

    queue_reassembly_segment(left, tsn);

    DebugFormat(DEBUG_STREAM_STATE,
        "added %hu bytes on segment list @ seq: 0x%X, total %u, %u segments queued\n",
        tsn->payload_size, tsn->seq, seg_bytes_logical, get_pending_segment_count(0));

    *retSeg = tsn;
    return STREAM_INSERT_OK;
}

int TcpReassembler::purge_alerts(uint32_t /*flush_seq*/,  Flow* flow)
{
    int i;
    int new_count = 0;

    for (i = 0; i < tracker->alert_count; i++)
    {
        StreamAlertInfo* ai = tracker->alerts + i;

        //if (SEQ_LT(ai->seq, flush_seq) )
        {
            Stream::log_extra_data(flow, xtradata_mask, ai->event_id, ai->event_second);
            memset(ai, 0, sizeof(*ai));
        }
#if 0
        else
        {
            if (new_count != i)
            {
                tracker->alerts[new_count] = tracker->alerts[i];
            }
            new_count++;
        }
#endif
    }
    tracker->alert_count = new_count;

    return new_count;
}

int TcpReassembler::purge_to_seq(uint32_t flush_seq)
{
    TcpSegmentNode* tsn = nullptr;
    TcpSegmentNode* dump_me = nullptr;
    int purged_bytes = 0;
    uint32_t last_ts = 0;

    if ( seglist.head == nullptr )
    {
        if ( SEQ_LT(seglist_base_seq, flush_seq) )
        {
            DebugFormat(DEBUG_STREAM_STATE, "setting seglist_base_seq to 0x%X\n", flush_seq);
            seglist_base_seq = flush_seq;
        }
        return 0;
    }

    tsn = seglist.head;

    DebugFormat(DEBUG_STREAM_STATE, "In purge_to_seq, start seq = 0x%X end seq = 0x%X delta %u\n",
        tsn->seq, flush_seq, flush_seq-tsn->seq);

    while ( tsn )
    {
        DebugFormat(DEBUG_STREAM_STATE, "s: %X  sz: %d\n", tsn->seq, tsn->payload_size);
        dump_me = tsn;

        tsn = tsn->next;
        if ( SEQ_LT(dump_me->seq, flush_seq) )
        {
            if (dump_me->ts > last_ts)
                last_ts = dump_me->ts;

            purged_bytes += trim_delete_reassembly_segment(dump_me, flush_seq);
        }
        else
            break;
    }

    if ( SEQ_LT(seglist_base_seq, flush_seq) )
    {
        DebugFormat(DEBUG_STREAM_STATE, "setting seglist_base_seq to 0x%X\n", flush_seq);
        seglist_base_seq = flush_seq;
    }

    if ( SEQ_LT(tracker->r_nxt_ack, flush_seq) )
        tracker->r_nxt_ack = flush_seq;

    purge_alerts(flush_seq, session->flow);

    if ( seglist.head == nullptr )
        seglist.tail = nullptr;

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
    if ( !last_ts )
        return purged_bytes;

    if ( !server_side )
    {
        int32_t delta = last_ts - session->server->get_ts_last();
        if ( delta > 0 )
            session->server->set_ts_last(last_ts);
    }
    else
    {
        int32_t delta = last_ts - session->client->get_ts_last();
        if ( delta > 0 )
            session->client->set_ts_last(last_ts);
    }

    return purged_bytes;
}

// purge_flushed_ackd():
// must only purge flushed and acked bytes we may flush partial segments
// must adjust seq->seq and tsn->size when a flush gets only the  initial
// part of a segment
// * FIXIT-L need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
int TcpReassembler::purge_flushed_ackd()
{
    TcpSegmentNode* tsn = seglist.head;
    uint32_t seq;

    if (!seglist.head)
        return 0;

    seq = seglist.head->seq;

    while ( tsn && tsn->buffered )
    {
        uint32_t end = tsn->seq + tsn->payload_size;

        if ( SEQ_GT(end, tracker->r_win_base) )
        {
            seq = tracker->r_win_base;
            break;
        }
        seq = end;
        tsn = tsn->next;
    }
    if ( seq != seglist.head->seq )
        return purge_to_seq(seq);

    return 0;
}

void TcpReassembler::show_rebuilt_packet(Packet* pkt)
{
    if ( session->config->flags & STREAM_CONFIG_SHOW_PACKETS )
    {
        LogFlow(pkt);
        LogNetData(pkt->data, pkt->dsize, pkt);
    }
}

uint32_t TcpReassembler::get_flush_data_len(TcpSegmentNode* tsn, uint32_t to_seq, unsigned max)
{
    unsigned int flushSize = tsn->payload_size;

    if ( flushSize > max )
        flushSize = max;

    // copy only to flush point
    if ( paf_active(&tracker->paf_state) && SEQ_GT(tsn->seq + flushSize, to_seq) )
        flushSize = to_seq - tsn->seq;

    return flushSize;
}

// flush the client seglist up to the most recently acked segment
int TcpReassembler::flush_data_segments(Packet* p, uint32_t total, Packet* pdu)
{
    uint32_t bytes_flushed = 0;
    uint32_t segs = 0;
    uint32_t flags = PKT_PDU_HEAD;
    DEBUG_WRAP(uint32_t bytes_queued = seg_bytes_logical; );

    assert(seglist.next);
    Profile profile(s5TcpBuildPacketPerfStats);

    uint32_t to_seq = seglist.next->seq + total;

    while ( SEQ_LT(seglist.next->seq, to_seq) )
    {
        TcpSegmentNode* tsn = seglist.next, * sr = nullptr;
        unsigned bytes_to_copy = get_flush_data_len(tsn, to_seq, tracker->splitter->max(p->flow));
        unsigned bytes_copied = 0;
        assert(bytes_to_copy);

        DebugFormat(DEBUG_STREAM_STATE, "Flushing %u bytes from %X\n", bytes_to_copy, tsn->seq);

        if ( !tsn->next || ( bytes_to_copy < tsn->payload_size )
            || SEQ_EQ(tsn->seq +  bytes_to_copy, to_seq) )
            flags |= PKT_PDU_TAIL;

        const StreamBuffer sb = tracker->splitter->reassemble(
            session->flow, total, bytes_flushed, tsn->payload(),
            bytes_to_copy, flags, bytes_copied);

        flags = 0;

        if ( sb.data )
        {
            pdu->data = sb.data;
            pdu->dsize = sb.length;
            assert(sb.length <= pdu->max_dsize);

            bytes_to_copy = bytes_copied;
        }
        assert(bytes_to_copy == bytes_copied);
        bytes_flushed += bytes_to_copy;

        if ( bytes_to_copy < tsn->payload_size
            && dup_reassembly_segment(tsn, &sr) == STREAM_INSERT_OK )
        {
            tsn->payload_size = bytes_to_copy;
            sr->seq += bytes_to_copy;
            sr->payload_size -= bytes_to_copy;
            sr->offset += bytes_to_copy;
        }
        tsn->buffered = true;
        flush_count++;
        segs++;

        seglist.next = tsn->next;

        if ( SEQ_EQ(tsn->seq + bytes_to_copy, to_seq) )
            break;

        /* Check for a gap/missing packet */
        // FIXIT-L PAF should account for missing data and resume
        // scanning at the start of next PDU instead of aborting.
        // FIXIT-L FIN may be in to_seq causing bogus gap counts.
        if (((tsn->next && (tsn->seq + tsn->payload_size != tsn->next->seq))
            || (!tsn->next && (tsn->seq + tsn->payload_size < to_seq))))
        {
            // FIXIT-L this is suboptimal - better to exclude fin from to_seq
            if ( !tracker->is_fin_seq_set() or SEQ_LEQ(to_seq, tracker->get_fin_final_seq()) )
                tracker->set_tf_flags(TF_MISSING_PKT);

            break;
        }

        if ( sb.data || !seglist.next )
            break;

        if ( bytes_flushed + seglist.next->payload_size >= tracker->splitter->get_max_pdu() )
            break;
    }

    DEBUG_WRAP(bytes_queued -= bytes_flushed; );
    DebugFormat(DEBUG_STREAM_STATE,
        "flushed %u bytes / %u segs on stream, %u bytes still queued\n",
        bytes_flushed, segs, bytes_queued);

    return bytes_flushed;
}

// FIXIT-L consolidate encode format, update, and this into new function?
void TcpReassembler::prep_pdu(Flow* flow, Packet* p, uint32_t pkt_flags, Packet* pdu)
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

int TcpReassembler::_flush_to_seq(uint32_t bytes, Packet* p, uint32_t pkt_flags)
{
    Profile profile(s5TcpFlushPerfStats);

    DetectionEngine::onload(session->flow);
    Packet* pdu = DetectionEngine::set_next_packet();

    if ( !p )
    {
        // FIXIT-H we need to have user_policy_id in this case
        // FIXIT-H this leads to format_tcp() copying from pdu to pdu
        // (neither of these issues is created by passing null through to here)
        p = pdu;
    }

    DebugFormat(DEBUG_STREAM_STATE, "Attempting to flush %u bytes\n", bytes);

    uint32_t bytes_processed = 0;
    uint32_t stop_seq = seglist.next->seq + bytes;

    while ( seglist.next and SEQ_LT(seglist.next->seq, stop_seq) )
    {
        seglist_base_seq = seglist.next->seq;
        uint32_t footprint = stop_seq - seglist_base_seq;

        if ( footprint == 0 )
            return bytes_processed;

        if ( footprint > pdu->max_dsize )
            /* this is as much as we can pack into a stream buffer */
            footprint = pdu->max_dsize;

        DetectionEngine::onload(session->flow);
        pdu = DetectionEngine::set_next_packet();

        DAQ_PktHdr_t pkth;
        session->GetPacketHeaderFoo(&pkth, pkt_flags);

        EncodeFlags enc_flags = 0;
        PacketManager::format_tcp(enc_flags, p, pdu, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
        prep_pdu(session->flow, p, pkt_flags, pdu);

        ((DAQ_PktHdr_t*)pdu->pkth)->ts = seglist.next->tv;

        /* setup the pseudopacket payload */
        pdu->dsize = 0;
        pdu->data = nullptr;

        if ( tracker->splitter->is_paf() and ( tracker->get_tf_flags() & TF_MISSING_PREV_PKT ) )
            fallback();

        int32_t flushed_bytes = flush_data_segments(p, footprint, pdu);

        if ( flushed_bytes == 0 )
            break; /* No more data... bail */

        bytes_processed += flushed_bytes;
        seglist_base_seq += flushed_bytes;

        if ( pdu->dsize )
        {
            if ( p->packet_flags & PKT_PDU_TAIL )
                pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_TAIL );
            else
                pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST );

            // FIXIT-H this came with merge should it be here? YES
            //pdu->application_protocol_ordinal = p->application_protocol_ordinal;
            show_rebuilt_packet(pdu);
            tcpStats.rebuilt_packets++;
            tcpStats.rebuilt_bytes += flushed_bytes;

            ProfileExclude profile_exclude(s5TcpFlushPerfStats);
            Snort::inspect(pdu);
        }
        else
        {
            tcpStats.rebuilt_buffers++; // FIXIT-L this is not accurate
        }

        DebugFormat(DEBUG_STREAM_STATE, "setting seglist_base_seq to 0x%X\n", seglist_base_seq);

        // FIXIT-L must check because above may clear session
        if ( tracker->splitter )
            tracker->splitter->update();

        // FIXIT-L abort should be by PAF callback only since recovery may be possible
        if ( tracker->get_tf_flags() & TF_MISSING_PKT )
        {
            tracker->set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);
            tracker->clear_tf_flags(TF_MISSING_PKT);
            tcpStats.gaps++;
        }
        else
            tracker->clear_tf_flags(TF_MISSING_PREV_PKT);

        // check here instead of in while to allow single segment flushes
        if ( !flush_data_ready() )
            break;
    }

    return bytes_processed;
}

// flush a seglist up to the given point, generate a pseudopacket, and fire it thru the system.
int TcpReassembler::flush_to_seq(uint32_t bytes, Packet* p, uint32_t pkt_flags)
{
    if ( !bytes || !seglist.next )
    {
        DebugFormat(DEBUG_STREAM_STATE, "bailing: no bytes: %u or empty seglist: %p\n",
            bytes, (void*)seglist.next);
        return 0;
    }

    if ( !flush_data_ready() and !(tracker->get_tf_flags() & TF_FORCE_FLUSH) and
        !tracker->splitter->is_paf() )
    {
        DebugMessage(DEBUG_STREAM_STATE, "only 1 packet in seglist no need to flush\n");
        return 0;
    }

    tracker->clear_tf_flags(TF_MISSING_PKT | TF_MISSING_PREV_PKT);

    /* This will set this flag on the first reassembly
     * if reassembly for this direction was set midstream */
    if ( SEQ_LT(seglist_base_seq, seglist.next->seq) )
    {
        uint32_t missed = seglist.next->seq - seglist_base_seq;

        if ( missed <= bytes )
            bytes -= missed;

        tracker->set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);

        tcpStats.gaps++;
        seglist_base_seq = seglist.next->seq;

        if ( !bytes )
            return 0;
    }

    return _flush_to_seq(bytes, p, pkt_flags);
}

// get the footprint for the current seglist, the difference
// between our base sequence and the last ack'd sequence we received

uint32_t TcpReassembler::get_q_footprint()
{
    int32_t footprint = 0, sequenced = 0;

    if ( !tracker )
        return 0;

    seglist.next = seglist.head;
    footprint = tracker->r_win_base - seglist_base_seq;
    if( footprint )
    {
        sequenced = get_q_sequenced();
        if( tracker->fin_seq_status == TcpStreamTracker::FIN_WITH_SEQ_ACKED )
            --footprint;
    }

    return ( footprint > sequenced ) ? sequenced : footprint;
}

// FIXIT-P get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as seglist is updated
// to avoid the while loop, etc. below.

uint32_t TcpReassembler::get_q_sequenced()
{
    TcpSegmentNode* tsn = tracker ? seglist.head : nullptr;
    TcpSegmentNode* base = nullptr;

    if ( !tsn || ( session->flow->two_way_traffic() && SEQ_LT(tracker->r_win_base, tsn->seq) ) )
        return 0;

    while ( tsn->next && ( tsn->next->seq == tsn->seq + tsn->payload_size ) )
    {
        if ( !tsn->buffered && !base )
            base = tsn;
        tsn = tsn->next;
    }

    if ( !tsn->buffered && !base )
        base = tsn;

    int32_t len = 0;
    if ( base )
    {
        seglist.next = base;
        seglist_base_seq = base->seq;
        len = tsn->seq + tsn->payload_size - base->seq;
    }

    return ( len > 0 ) ? len : 0;
}

// FIXIT-L flush_stream() calls should be replaced with calls to
// CheckFlushPolicyOn*() with the exception that for the *OnAck() case,
// any available ackd data must be flushed in both directions.
int TcpReassembler::flush_stream(Packet* p, uint32_t dir)
{
    // this is not always redundant; stream_reassemble rule option causes trouble
    if ( !tracker->flush_policy or !tracker->splitter )
        return 0;

    uint32_t bytes;

    if ( tracker->normalizer->is_tcp_ips_enabled() )
        bytes = get_q_sequenced( );
    else
        bytes = get_q_footprint( );

    return flush_to_seq(bytes, p, dir);
}

void TcpReassembler::final_flush(Packet* p, uint32_t dir)
{
    tracker->set_tf_flags(TF_FORCE_FLUSH);

    if ( flush_stream(p, dir) )
        purge_flushed_ackd( );

    tracker->clear_tf_flags(TF_FORCE_FLUSH);
}

static Packet* set_packet(Flow* flow, uint32_t flags, bool c2s)
{
    Packet* p = DetectionEngine::get_current_packet();
    p->reset();

    DAQ_PktHdr_t* ph = (DAQ_PktHdr_t*)p->pkth;
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

void TcpReassembler::flush_queued_segments(Flow* flow, bool clear, Packet* p)
{
    bool data = p or seglist.head;

    if ( !p )
    {
        // this packet is required if we call finish and/or final_flush
        p = set_packet(flow, packet_dir, server_side);

        if ( server_side )
            tcpStats.s5tcp2++;
        else
            tcpStats.s5tcp1++;
    }

    bool pending = clear and paf_initialized(&tracker->paf_state)
        and (!tracker->splitter or tracker->splitter->finish(flow) );

    if ( pending and data and !(flow->ssn_state.ignore_direction & ignore_dir) )
    {
        final_flush(p, packet_dir);
    }
}

// this is for post-ack flushing
uint32_t TcpReassembler::get_reverse_packet_dir(const Packet* p)
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
    else if ( p->is_from_client() )
        return PKT_FROM_SERVER;

    return 0;
}

uint32_t TcpReassembler::get_forward_packet_dir(const Packet* p)
{
    if ( p->is_from_server() )
        return PKT_FROM_SERVER;
    else if ( p->is_from_client() )
        return PKT_FROM_CLIENT;

    return 0;
}

// see flush_pdu_ackd() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
int32_t TcpReassembler::flush_pdu_ips(uint32_t* flags)
{
    Profile profile(s5TcpPAFPerfStats);
    DetectionEngine::onload(session->flow);

    uint32_t total = 0, avail;
    TcpSegmentNode* tsn;

    avail = get_q_sequenced( );
    tsn = seglist.next;

    // * must stop if gap (checked in paf_check)
    while ( tsn && *flags && ( total < avail ) )
    {
        int32_t flush_pt;
        uint32_t size = tsn->payload_size;
        uint32_t end = tsn->seq + tsn->payload_size;
        uint32_t pos = paf_position(&tracker->paf_state);

        total += size;

        if ( paf_initialized(&tracker->paf_state) && SEQ_LEQ(end, pos) )
        {
            tsn = tsn->next;
            continue;
        }

        flush_pt = paf_check(tracker->splitter, &tracker->paf_state, session->flow,
            tsn->payload(), size, total, tsn->seq, flags);

        if (flush_pt >= 0)
        {
            // see flush_pdu_ackd()
            if ( !tracker->splitter->is_paf() && avail > (unsigned)flush_pt )
            {
                paf_jump(&tracker->paf_state, avail - (unsigned)flush_pt);
                return avail;
            }
            return flush_pt;
        }
        tsn = tsn->next;
    }

    return -1;
}

void TcpReassembler::fallback()
{
    bool c2s = tracker->splitter->to_server();

    delete tracker->splitter;
    tracker->splitter = new AtomSplitter(c2s, session->config->paf_max);
    tracker->paf_state.paf = StreamSplitter::SEARCH;

    session->flow->set_session_flags( c2s ? SSNFLAG_ABORT_CLIENT : SSNFLAG_ABORT_SERVER );
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

int32_t TcpReassembler::flush_pdu_ackd(uint32_t* flags)
{
    Profile profile(s5TcpPAFPerfStats);
    DetectionEngine::onload(session->flow);

    uint32_t total = 0;
    TcpSegmentNode* tsn = SEQ_LT(seglist_base_seq, tracker->r_win_base) ? seglist.head : nullptr;

    // must stop if not acked
    // must use adjusted size of tsn if not fully acked
    // must stop if gap (checked in paf_check)
    while (tsn && *flags && SEQ_LT(tsn->seq, tracker->r_win_base))
    {
        int32_t flush_pt;
        uint32_t size = tsn->payload_size;
        uint32_t end = tsn->seq + tsn->payload_size;
        uint32_t pos = paf_position(&tracker->paf_state);

        if ( paf_initialized(&tracker->paf_state) && SEQ_LEQ(end, pos) )
        {
            total += size;
            tsn = tsn->next;
            continue;
        }
        if ( SEQ_GT(end, tracker->r_win_base))
            size = tracker->r_win_base - tsn->seq;

        total += size;

        flush_pt = paf_check(tracker->splitter, &tracker->paf_state, session->flow,
            tsn->payload(), size, total, tsn->seq, flags);

        if ( flush_pt >= 0 )
        {
            // for non-paf splitters, flush_pt > 0 means we reached
            // the minimum required, but we flush what is available
            // instead of creating more, but smaller, packets
            // FIXIT-L just flush to end of segment to avoid splitting
            // instead of all avail?
            if ( !tracker->splitter->is_paf() )
            {
                // get_q_footprint() w/o side effects
                int32_t avail = tracker->r_win_base - seglist_base_seq;
                if ( avail > flush_pt )
                {
                    paf_jump(&tracker->paf_state, avail - flush_pt);
                    return avail;
                }
            }
            return flush_pt;
        }
        tsn = tsn->next;
    }

    return -1;
}

int TcpReassembler::flush_on_data_policy(Packet* p)
{
    uint32_t flushed = 0;

    DebugMessage(DEBUG_STREAM_STATE, "In CheckFlushPolicyOnData\n");
    DebugFormat(DEBUG_STREAM_STATE, "Listener flush policy: %s\n",
        flush_policy_names[ tracker->flush_policy ]);

    switch ( tracker->flush_policy )
    {
    case STREAM_FLPOLICY_IGNORE:
        DebugMessage(DEBUG_STREAM_STATE, "STREAM_FLPOLICY_IGNORE\n");
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
        break;

    case STREAM_FLPOLICY_ON_DATA:
    {
        uint32_t flags = get_forward_packet_dir(p);
        int32_t flush_amt = flush_pdu_ips(&flags);
        uint32_t this_flush;

        while ( flush_amt >= 0 )
        {
            if ( !flush_amt )
                flush_amt = seglist.next->seq - seglist_base_seq;
#if 0
// FIXIT-P can't do this with new HI - copy is inevitable
            // if this payload is exactly one pdu, don't
            // actually flush, just use the raw packet
            if ( listener->seglist.next &&
                ( tsd.seq == listener->seglist.next->seq ) &&
                ( flush_amt == listener->seglist.next->payload_size ) &&
                ( flush_amt == p->dsize ) )
            {
                this_flush = flush_amt;
                listener->seglist.next->buffered = true;
                listener->flush_count++;
                p->packet_flags |= PKT_PDU_FULL;
                ShowRebuiltPacket(p);
            }
            else
#endif
            {
                this_flush = flush_to_seq(flush_amt, p, flags);
            }
            // if we didn't flush as expected, bail
            // (we can flush less than max dsize)
            if (!this_flush)
                break;

            flushed += this_flush;
            flags = get_forward_packet_dir(p);
            flush_amt = flush_pdu_ips(&flags);
        }

        if ( !flags && tracker->splitter->is_paf() )
        {
            fallback( );
            return flush_on_data_policy(p);
        }
    }
    break;
    }
    return flushed;
}

int TcpReassembler::flush_on_ack_policy(Packet* p)
{
    uint32_t flushed = 0;

    DebugMessage(DEBUG_STREAM_STATE, "In CheckFlushPolicyOnAck\n");
    DebugFormat(DEBUG_STREAM_STATE, "Talker flush policy: %s\n",
        flush_policy_names[ tracker->flush_policy ]);

    switch (tracker->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        DebugMessage(DEBUG_STREAM_STATE, "STREAM_FLPOLICY_IGNORE\n");
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
    {
        uint32_t flags = get_reverse_packet_dir(p);
        int32_t flush_amt = flush_pdu_ackd(&flags);

        while (flush_amt >= 0)
        {
            if (!flush_amt)
                flush_amt = seglist.next->seq - seglist_base_seq;

            seglist.next = seglist.head;
            seglist_base_seq = seglist.head->seq;

            // for consistency with other cases, should return total
            // but that breaks flushing pipelined pdus
            flushed = flush_to_seq(flush_amt, p, flags);

            // ideally we would purge just once after this loop
            // but that throws off base
            if ( flushed and seglist.head )
                purge_to_seq(seglist.head->seq + flushed);

            // if we didn't flush as expected, bail
            // (we can flush less than max dsize)
            if (!flushed)
                break;

            flags = get_reverse_packet_dir(p);
            flush_amt = flush_pdu_ackd(&flags);
        }

        if (!flags && tracker->splitter->is_paf())
        {
            fallback( );
            return flush_on_ack_policy(p);
        }
    }
    break;

    case STREAM_FLPOLICY_ON_DATA:
        purge_flushed_ackd( );
        break;
    }

    return flushed;
}

void TcpReassembler::purge_segment_list()
{
    seglist.clear( );
    seg_count = 0;
    flush_count = 0;
    seg_bytes_total = 0;
    seg_bytes_logical = 0;
}

void TcpReassembler::insert_segment_in_empty_seglist(TcpSegmentDescriptor& tsd)
{
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    uint32_t overlap = 0;
    uint32_t seq = tsd.get_seg_seq();

    if ( tcph->is_syn() )
        seq++;

    if ( SEQ_GT(tracker->r_win_base, seq) )
    {
        DebugMessage(DEBUG_STREAM_STATE, "segment overlaps ack'd data...\n");
        overlap = tracker->r_win_base - tsd.get_seg_seq();
        if ( overlap >= tsd.get_seg_len() )
        {
            DebugMessage(DEBUG_STREAM_STATE, "full overlap on ack'd data, dropping segment\n");
            return;
        }
    }

    // BLOCK add new block to seglist containing data
    add_reassembly_segment(tsd, tsd.get_seg_len(), overlap, 0, tsd.get_seg_seq() + overlap, NULL);

    DebugFormat(DEBUG_STREAM_STATE,
        "Attached new queue to seglist, %u bytes queued, base_seq 0x%X\n",
        tsd.get_seg_len() - overlap, seglist_base_seq);
}

void TcpReassembler::init_overlap_editor(TcpSegmentDescriptor& tsd)
{
    TcpSegmentNode* left = nullptr;
    TcpSegmentNode* right = nullptr;
    TcpSegmentNode* tsn = nullptr;
    int32_t dist_head;
    int32_t dist_tail;
    DEBUG_WRAP(
        TcpSegmentNode *lastptr = NULL;
        uint32_t base_seq = seglist_base_seq;
        int last = 0;
        );

    if ( seglist.head && seglist.tail )
    {
        if ( SEQ_GT(tsd.get_seg_seq(), seglist.head->seq) )
            dist_head = tsd.get_seg_seq() - seglist.head->seq;
        else
            dist_head = seglist.head->seq - tsd.get_seg_seq();

        if ( SEQ_GT(tsd.get_seg_seq(), seglist.tail->seq) )
            dist_tail = tsd.get_seg_seq() - seglist.tail->seq;
        else
            dist_tail = seglist.tail->seq - tsd.get_seg_seq();
    }
    else
        dist_head = dist_tail = 0;

    if ( SEQ_LEQ(dist_head, dist_tail) )
    {
        for ( tsn = seglist.head; tsn; tsn = tsn->next )
        {
            DEBUG_WRAP(
                DebugFormat(DEBUG_STREAM_STATE, "tsn: %p  seq: 0x%X  size: %hu delta: %u\n",
                (void*) tsn, tsn->seq, tsn->payload_size, ( tsn->seq - base_seq ) - last);
                last = tsn->seq - base_seq;
                lastptr = tsn;

                DebugFormat(DEBUG_STREAM_STATE, "   lastptr: %p tsn->next: %p tsn->prev: %p\n",
                (void*) lastptr, (void*) tsn->next, (void*) tsn->prev);
                );

            right = tsn;
            if ( SEQ_GEQ(right->seq, tsd.get_seg_seq() ) )
                break;
            left = right;
        }

        if ( tsn == nullptr )
            right = nullptr;
    }
    else
    {
        for ( tsn = seglist.tail; tsn; tsn = tsn->prev )
        {
            DEBUG_WRAP(
                DebugFormat(DEBUG_STREAM_STATE, "tsn: %p  seq: 0x%X  size: %hu delta: %u\n",
                (void*) tsn, tsn->seq, tsn->payload_size, ( tsn->seq - base_seq ) - last);
                last = tsn->seq - base_seq;
                lastptr = tsn;

                DebugFormat(DEBUG_STREAM_STATE, "   lastptr: %p tsn->next: %p tsn->prev: %p\n",
                (void*) lastptr, (void*) tsn->next, (void*) tsn->prev);
                );

            left = tsn;
            if ( SEQ_LT(left->seq, tsd.get_seg_seq() ) )
                break;
            right = left;
        }

        if (tsn == nullptr)
            left = nullptr;
    }

    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");
    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");
    DebugFormat(DEBUG_STREAM_STATE, "left: %p:0x%X  right: %p:0x%X\n",
        (void*) left, left ? left->seq : 0, (void*) right, right ? right->seq : 0);

    init_soe(tsd, left, right);
}

int TcpReassembler::insert_segment_in_seglist(TcpSegmentDescriptor& tsd)
{
    int rc = STREAM_INSERT_OK;

    DebugFormat(DEBUG_STREAM_STATE,
        "Queuing %u bytes on stream!\nbase_seq: %X seq: %X  seq_end: %X\n",
        tsd.get_end_seq() - tsd.get_seg_seq(), seglist_base_seq, tsd.get_seg_seq(),
        tsd.get_end_seq());

    DebugFormat(DEBUG_STREAM_STATE, "%u segments on seglist\n", get_pending_segment_count(0));
    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");
    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");

    // NORM fast tracks are in sequence - no norms
    if ( seglist.tail && is_segment_fasttrack(seglist.tail, tsd) )
    {
        /* segment fit cleanly at the end of the segment list */
        TcpSegmentNode* left = seglist.tail;

        DebugFormat(DEBUG_STREAM_STATE, "Fast tracking segment! (tail_seq %X size %d)\n",
            seglist.tail->seq, seglist.tail->payload_size);

        // BLOCK add to existing block and/or allocate new block
        rc = add_reassembly_segment(tsd, tsd.get_seg_len(), 0, 0, tsd.get_seg_seq(), left);
        return rc;
    }

    init_overlap_editor(tsd);
    rc = eval_left();
    if ( rc != STREAM_INSERT_OK )
        return rc;

    rc = eval_right( );
    if ( rc != STREAM_INSERT_OK )
        return rc;

    if ( keep_segment )
    {
        /* Adjust slide so that is correct relative to orig seq */
        slide = seq - tsd.get_seg_seq();
        rc = add_reassembly_segment(tsd, len, slide, trunc_len, seq, left);
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "Fully truncated right overlap\n");
        rc = STREAM_INSERT_OK;
    }

    return rc;
}

int TcpReassembler::queue_packet_for_reassembly(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpInsertPerfStats);

    int rc = STREAM_INSERT_OK;

    if ( seg_count == 0 )
    {
        insert_segment_in_empty_seglist(tsd);
        return STREAM_INSERT_OK;
    }

    if ( SEQ_GT(tracker->r_win_base, tsd.get_seg_seq() ) )
    {
        int32_t offset = tracker->r_win_base - tsd.get_seg_seq();

        if ( offset < tsd.get_seg_len() )
        {
            tsd.slide_segment_in_rcv_window(offset);
            rc = insert_segment_in_seglist(tsd);
            tsd.slide_segment_in_rcv_window(-offset);
        }
    }
    else
        rc = insert_segment_in_seglist(tsd);

    return rc;
}

#ifdef SEG_TEST
static void CheckSegments(const TcpStreamTracker* a)
{
    TcpSegmentNode* tsn = a->seglist.head;
    uint32_t sx = tsn ? tsn->seq : 0;

    while ( tsn )
    {
        if ( SEQ_GT(sx, tsn->seq) )
        {
            const int SEGBORK = 0;
            assert(SEGBORK);
        }
        sx = tsn->seq + tsn->payload_size;
        tsn = tsn->next;
    }
}

#endif

