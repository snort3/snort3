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

// tcp_reassembler.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassembler.h"

#include <cassert>

#include "detection/detection_engine.h"
#include "log/log.h"
#include "main/analyzer.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

static THREAD_LOCAL Packet* last_pdu = nullptr;

static void purge_alerts_callback_ackd(IpsContext* c)
{
    TcpSession* session = (TcpSession*)c->packet->flow->session;

    if ( c->packet->is_from_server() )
        session->client.reassembler.purge_alerts();
    else
        session->server.reassembler.purge_alerts();
}

static void purge_alerts_callback_ips(IpsContext* c)
{
    TcpSession* session = (TcpSession*)c->packet->flow->session;

    if ( c->packet->is_from_server() )
        session->server.reassembler.purge_alerts();
    else
        session->client.reassembler.purge_alerts();
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

bool TcpReassembler::next_no_gap(const TcpSegmentNode& tsn)
{
    return tsn.next and (tsn.next->i_seq == tsn.i_seq + tsn.i_len);
}

bool TcpReassembler::next_no_gap_c(const TcpSegmentNode& tsn)
{
    return tsn.next and (tsn.next->c_seq == tsn.c_seq + tsn.c_len);
}

bool TcpReassembler::next_acked_no_gap_c(const TcpSegmentNode& tsn, const TcpReassemblerState& trs)
{
    return tsn.next and (tsn.next->c_seq == tsn.c_seq + tsn.c_len)
        and SEQ_LT(tsn.next->c_seq, trs.tracker->r_win_base);
}

bool TcpReassembler::fin_no_gap(const TcpSegmentNode& tsn, const TcpReassemblerState& trs)
{
    return trs.tracker->fin_seq_status >= TcpStreamTracker::FIN_WITH_SEQ_SEEN
        and SEQ_GEQ(tsn.i_seq + tsn.i_len, trs.tracker->get_fin_i_seq());
}

bool TcpReassembler::fin_acked_no_gap(const TcpSegmentNode& tsn, const TcpReassemblerState& trs)
{
    return trs.tracker->fin_seq_status >= TcpStreamTracker::FIN_WITH_SEQ_ACKED
        and SEQ_GEQ(tsn.i_seq + tsn.i_len, trs.tracker->get_fin_i_seq());
}

void TcpReassembler::update_next(TcpReassemblerState& trs, const TcpSegmentNode& tsn)
{
    trs.sos.seglist.cur_rseg = next_no_gap(tsn) ?  tsn.next : nullptr;
    if ( trs.sos.seglist.cur_rseg )
        trs.sos.seglist.cur_rseg->c_seq = trs.sos.seglist.cur_rseg->i_seq;
}

// If we are skipping seglist hole, update tsn so that we can purge
void TcpReassembler::update_skipped_bytes(uint32_t remaining_bytes, TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn;

    while ( remaining_bytes and (tsn = trs.sos.seglist.cur_rseg) )
    {
        auto bytes_skipped = ( tsn->c_len <= remaining_bytes ) ? tsn->c_len : remaining_bytes;

        remaining_bytes -= bytes_skipped;
        tsn->update_ressembly_lengths(bytes_skipped);

        if ( !tsn->c_len )
        {
            trs.flush_count++;
            update_next(trs, *tsn);
        }
    }
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

    if ( trs.sos.seglist.cur_sseg == tsn )
        trs.sos.seglist.cur_sseg = tsn->next;

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

    if ( !trs.sos.seglist.cur_sseg )
        trs.sos.seglist.cur_sseg = tsn;
    else if ( SEQ_LT(tsn->c_seq, trs.sos.seglist.cur_sseg->c_seq) )
    {
        trs.sos.seglist.cur_sseg = tsn;
        if ( SEQ_LT(tsn->c_seq, trs.sos.seglist_base_seq) )
            trs.sos.seglist_base_seq = tsn->c_seq;

        if ( trs.sos.seglist.cur_rseg && SEQ_LT(tsn->c_seq, trs.sos.seglist.cur_rseg->c_seq) )
            trs.sos.seglist.cur_rseg = tsn;
    }

    trs.sos.seg_count++;
    trs.sos.seg_bytes_total += tsn->i_len;
    trs.sos.total_segs_queued++;
    tcpStats.segs_queued++;

    if ( trs.sos.seg_count > tcpStats.max_segs )
        tcpStats.max_segs = trs.sos.seg_count;

    if ( trs.sos.seg_bytes_total > tcpStats.max_bytes )
        tcpStats.max_bytes = trs.sos.seg_bytes_total;
}

bool TcpReassembler::is_segment_fasttrack(
    TcpReassemblerState&, TcpSegmentNode* tail, const TcpSegmentDescriptor& tsd)
{
    if ( SEQ_EQ(tsd.get_seq(), tail->i_seq + tail->i_len) )
        return true;

    return false;
}

void TcpReassembler::add_reassembly_segment(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd, uint16_t len, uint32_t slide,
    uint32_t trunc_len, uint32_t seq, TcpSegmentNode* left)
{
    const int32_t new_size = len - slide - trunc_len;
    assert(new_size >= 0);

    // if trimming will delete all data, don't insert this segment in the queue
    if ( new_size <= 0 )
    {
        tcpStats.payload_fully_trimmed++;
        trs.tracker->normalizer.trim_win_payload(tsd);
        return;
    }

    // FIXIT-L don't allocate overlapped part
    TcpSegmentNode* const tsn = TcpSegmentNode::init(tsd);

    tsn->offset = slide;
    tsn->c_len = (uint16_t)new_size;
    tsn->i_len = (uint16_t)new_size;
    tsn->i_seq = tsn->c_seq = seq;
    tsn->ts = tsd.get_timestamp();

    // FIXIT-M the urgent ptr handling is broken... urg_offset could be set here but currently
    // not actually referenced anywhere else.  In 2.9.7 the FlushStream function did reference
    // this field but that code has been lost... urg ptr handling needs to be reviewed and fixed
    // tsn->urg_offset = trs.tracker->normalizer.set_urg_offset(tsd.get_tcph(), tsd.get_seg_len());

    queue_reassembly_segment(trs, left, tsn);

    trs.sos.seg_bytes_logical += tsn->c_len;
    trs.sos.total_bytes_queued += tsn->c_len;
    tsd.set_packet_flags(PKT_STREAM_INSERT);
}

void TcpReassembler::dup_reassembly_segment(
    TcpReassemblerState& trs, TcpSegmentNode* left, TcpSegmentNode** retSeg)
{
    TcpSegmentNode* tsn = TcpSegmentNode::init(*left);
    tcpStats.segs_split++;

    // twiddle the values for overlaps
    tsn->c_len = left->c_len;
    tsn->i_seq = tsn->c_seq = left->i_seq;
    queue_reassembly_segment(trs, left, tsn);

    *retSeg = tsn;
}

bool TcpReassembler::add_alert(TcpReassemblerState& trs, uint32_t gid, uint32_t sid)
{
    trs.alerts.emplace_back(gid, sid);
    return true;
}

bool TcpReassembler::check_alerted(TcpReassemblerState& trs, uint32_t gid, uint32_t sid)
{
    for ( auto& alert : trs.alerts )
       if (alert.gid == gid && alert.sid == sid)
            return true;

    return false;
}

int TcpReassembler::update_alert(TcpReassemblerState& trs, uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    // FIXIT-M comparison of seq_num is wrong, compare value is always 0, should be seq_num of wire packet
    uint32_t seq_num = 0;

    for ( auto& alert : trs.alerts )
       if (alert.gid == gid && alert.sid == sid && SEQ_EQ(alert.seq, seq_num))
       {
           alert.event_id = event_id;
           alert.event_second = event_second;
           return 0;
       }

    return -1;
}

void TcpReassembler::purge_alerts(TcpReassemblerState& trs)
{
    Flow* flow = trs.sos.session->flow;

    for ( auto& alert : trs.alerts )
        Stream::log_extra_data(flow, trs.xtradata_mask, alert);

    if ( !flow->is_suspended() )
        trs.alerts.clear();
}

void TcpReassembler::purge_to_seq(TcpReassemblerState& trs, uint32_t flush_seq)
{
    assert( trs.sos.seglist.head );
    uint32_t last_ts = 0;

    TcpSegmentNode* tsn = trs.sos.seglist.head;
    while ( tsn && SEQ_LT(tsn->i_seq, flush_seq))
    {
        if ( tsn->c_len )
            break;

        TcpSegmentNode* dump_me = tsn;
        tsn = tsn->next;
        if (dump_me->ts > last_ts)
            last_ts = dump_me->ts;

        delete_reassembly_segment(trs, dump_me);
    }

    if ( SEQ_LT(trs.tracker->rcv_nxt, flush_seq) )
        trs.tracker->rcv_nxt = flush_seq;

    if ( last_pdu )
    {
        if ( trs.tracker->normalizer.is_tcp_ips_enabled() )
            last_pdu->context->register_post_callback(purge_alerts_callback_ips);
        else
            last_pdu->context->register_post_callback(purge_alerts_callback_ackd);

        last_pdu = nullptr;
    }
    else
        purge_alerts(trs);

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
}

// must only purge flushed and acked bytes we may flush partial segments
// must adjust seq->seq and tsn->size when a flush gets only the initial
// part of a segment
// * FIXIT-L need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
void TcpReassembler::purge_flushed_ackd(TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn = trs.sos.seglist.head;
    uint32_t seq;

    if (!trs.sos.seglist.head)
        return;

    seq = trs.sos.seglist.head->i_seq;

    while ( tsn && !tsn->c_len )
    {
        uint32_t end = tsn->i_seq + tsn->i_len;

        if ( SEQ_GT(end, trs.tracker->r_win_base) )
            break;

        seq = end;
        tsn = tsn->next;
    }

    if ( seq != trs.sos.seglist.head->i_seq )
        purge_to_seq(trs, seq);
}

void TcpReassembler::show_rebuilt_packet(const TcpReassemblerState& trs, Packet* pkt)
{
    if ( trs.sos.session->tcp_config->flags & STREAM_CONFIG_SHOW_PACKETS )
    {
        // FIXIT-L setting conf here is required because this is called before context start
        pkt->context->conf = SnortConfig::get_conf();
        LogFlow(pkt);
        LogNetData(pkt->data, pkt->dsize, pkt);
    }
}

int TcpReassembler::flush_data_segments(TcpReassemblerState& trs, uint32_t flush_len, Packet* pdu)
{
    uint32_t flags = PKT_PDU_HEAD;
    uint32_t to_seq = trs.sos.seglist.cur_rseg->c_seq + flush_len;
    uint32_t remaining_bytes = flush_len;
    uint32_t total_flushed = 0;

    while ( remaining_bytes )
    {
        TcpSegmentNode* tsn = trs.sos.seglist.cur_rseg;
        unsigned bytes_to_copy = ( tsn->c_len <= remaining_bytes ) ? tsn->c_len : remaining_bytes;

        remaining_bytes -= bytes_to_copy;
        if ( !remaining_bytes )
            flags |= PKT_PDU_TAIL;
        else
            assert( bytes_to_copy >= tsn->c_len );

        unsigned bytes_copied = 0;
        const StreamBuffer sb = trs.tracker->get_splitter()->reassemble(
            trs.sos.session->flow, flush_len, total_flushed, tsn->payload(),
            bytes_to_copy, flags, bytes_copied);

        if ( sb.data )
        {
            pdu->data = sb.data;
            pdu->dsize = sb.length;
        }

        total_flushed += bytes_copied;
        tsn->update_ressembly_lengths(bytes_copied);
        flags = 0;

        if ( !tsn->c_len )
        {
            trs.flush_count++;
            update_next(trs, *tsn);
        }

        /* Check for a gap/missing packet */
        // FIXIT-L FIN may be in to_seq causing bogus gap counts.
        if ( tsn->is_packet_missing(to_seq) or trs.paf_state.paf == StreamSplitter::SKIP )
        {
            // FIXIT-H // assert(false); find when this scenario happens
            // FIXIT-L this is suboptimal - better to exclude fin from to_seq
            if ( !trs.tracker->is_fin_seq_set() or
                SEQ_LEQ(to_seq, trs.tracker->get_fin_final_seq()) )
            {
                trs.tracker->set_tf_flags(TF_MISSING_PKT);
            }
            break;
        }

        if ( sb.data || !trs.sos.seglist.cur_rseg )
            break;
    }

    if ( trs.paf_state.paf == StreamSplitter::SKIP )
        update_skipped_bytes(remaining_bytes, trs);

    return total_flushed;
}

static inline bool both_splitters_aborted(Flow* flow)
{
    uint32_t both_splitters_yoinked = (SSNFLAG_ABORT_CLIENT | SSNFLAG_ABORT_SERVER);
    return (flow->get_session_flags() & both_splitters_yoinked) == both_splitters_yoinked;
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
        pdu->packet_flags |= (p->packet_flags & (PKT_FROM_CLIENT | PKT_FROM_SERVER));
        pdu->ptrs.ip_api.set(*p->ptrs.ip_api.get_src(), *p->ptrs.ip_api.get_dst());
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

        pdu->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(), *p->ptrs.ip_api.get_src());
        pdu->ptrs.dp = p->ptrs.sp;
        pdu->ptrs.sp = p->ptrs.dp;
    }
}

Packet* TcpReassembler::initialize_pdu(
    TcpReassemblerState& trs, Packet* p, uint32_t pkt_flags, struct timeval tv)
{
    // partial flushes already set the pdu for http_inspect splitter processing
    Packet* pdu = p->was_set() ? p : DetectionEngine::set_next_packet(p);

    EncodeFlags enc_flags = 0;
    DAQ_PktHdr_t pkth;
    trs.sos.session->get_packet_header_foo(&pkth, p->pkth, pkt_flags);
    PacketManager::format_tcp(enc_flags, p, pdu, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
    prep_pdu(trs, trs.sos.session->flow, p, pkt_flags, pdu);
    assert(pdu->pkth == pdu->context->pkth);
    pdu->context->pkth->ts = tv;
    pdu->dsize = 0;
    pdu->data = nullptr;
    pdu->ip_proto_next = (IpProtocol)p->flow->ip_proto;


    if ( p->proto_bits & PROTO_BIT__VLAN )
    {
        memcpy( pdu->layers, p->layers, p->num_layers * sizeof(Layer));
        pdu->num_layers = p->num_layers;
        pdu->proto_bits |= PROTO_BIT__VLAN;
        pdu->vlan_idx = p->vlan_idx;
    }

    return pdu;
}

// flush a seglist up to the given point, generate a pseudopacket, and fire it thru the system.
int TcpReassembler::flush_to_seq(
    TcpReassemblerState& trs, uint32_t bytes, Packet* p, uint32_t pkt_flags)
{
    assert( p && trs.sos.seglist.cur_rseg);

    trs.tracker->clear_tf_flags(TF_MISSING_PKT | TF_MISSING_PREV_PKT);

    TcpSegmentNode* tsn = trs.sos.seglist.cur_rseg;
    assert( trs.sos.seglist_base_seq == tsn->c_seq);

    Packet* pdu = initialize_pdu(trs, p, pkt_flags, tsn->tv);
    int32_t flushed_bytes = flush_data_segments(trs, bytes, pdu);
    assert( flushed_bytes );

    trs.sos.seglist_base_seq += flushed_bytes;

    if ( pdu->data )
    {
        if ( p->packet_flags & PKT_PDU_TAIL )
            pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_TAIL );
        else
            pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST );

        show_rebuilt_packet(trs, pdu);
        tcpStats.rebuilt_packets++;
        tcpStats.rebuilt_bytes += flushed_bytes;

        if ( !Analyzer::get_local_analyzer()->inspect_rebuilt(pdu) )
            last_pdu = pdu;
        else
            last_pdu = nullptr;

        trs.tracker->finalize_held_packet(p);
    }
    else
    {
        tcpStats.rebuilt_buffers++; // FIXIT-L this is not accurate
        last_pdu = nullptr;
    }

    // FIXIT-L abort should be by PAF callback only since recovery may be possible
    if ( trs.tracker->get_tf_flags() & TF_MISSING_PKT )
    {
        trs.tracker->set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);
        trs.tracker->clear_tf_flags(TF_MISSING_PKT);
        tcpStats.gaps++;
    }
    else
        trs.tracker->clear_tf_flags(TF_MISSING_PREV_PKT);

    return flushed_bytes;
}

// flush a seglist up to the given point, generate a pseudopacket, and fire it thru the system.
int TcpReassembler::do_zero_byte_flush(TcpReassemblerState& trs, Packet* p, uint32_t pkt_flags)
{
    unsigned bytes_copied = 0;

    const StreamBuffer sb = trs.tracker->get_splitter()->reassemble(
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
        Analyzer::get_local_analyzer()->inspect_rebuilt(pdu);
     }

     return bytes_copied;
}

// get the footprint for the current trs.sos.seglist, the difference
// between our base sequence and the last ack'd sequence we received

uint32_t TcpReassembler::get_q_footprint(TcpReassemblerState& trs)
{
    int32_t footprint = 0;
    int32_t sequenced = 0;

    if ( SEQ_GT(trs.tracker->r_win_base, trs.sos.seglist_base_seq) )
        footprint = trs.tracker->r_win_base - trs.sos.seglist_base_seq;

    if ( footprint )
        sequenced = get_q_sequenced(trs);

    return ( footprint > sequenced ) ? sequenced : footprint;
}

// FIXIT-P get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as trs.sos.seglist is updated
// to avoid the while loop, etc. below.

uint32_t TcpReassembler::get_q_sequenced(TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn = trs.sos.seglist.cur_rseg;

    if ( !tsn )
    {
        tsn = trs.sos.seglist.head;

        if ( !tsn || SEQ_LT(trs.tracker->r_win_base, tsn->c_seq) )
            return 0;

        trs.sos.seglist.cur_rseg = tsn;
    }

    uint32_t len = 0;
    const uint32_t limit = trs.tracker->get_splitter()->max();
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

bool TcpReassembler::is_q_sequenced(TcpReassemblerState& trs)
{
    TcpSegmentNode* tsn = trs.sos.seglist.cur_rseg;

    if ( !tsn )
    {
        tsn = trs.sos.seglist.head;

        if ( !tsn || SEQ_LT(trs.tracker->r_win_base, tsn->c_seq) )
            return false;

        trs.sos.seglist.cur_rseg = tsn;
    }

    while ( next_no_gap(*tsn) )
    {
        if ( tsn->c_len )
            break;

        tsn = trs.sos.seglist.cur_rseg = tsn->next;
    }

    trs.sos.seglist_base_seq = tsn->c_seq;

    return (tsn->c_len != 0);
}

int TcpReassembler::flush_stream(
    TcpReassemblerState& trs, Packet* p, uint32_t dir, bool final_flush)
{
    // this is not always redundant; stream_reassemble rule option causes trouble
    if ( !trs.tracker->is_reassembly_enabled() )
        return 0;

    if ( trs.sos.session->flow->two_way_traffic() )
    {
        uint32_t bytes = 0;

        if ( trs.tracker->normalizer.is_tcp_ips_enabled() )
            bytes = get_q_sequenced(trs);  // num bytes in pre-ack mode
        else
            bytes = get_q_footprint(trs);  // num bytes in post-ack mode

        if ( bytes )
            return flush_to_seq(trs, bytes, p, dir);
    }

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

static Packet* get_packet(Flow* flow, uint32_t flags, bool c2s)
{
    Packet* p = DetectionEngine::set_next_packet(nullptr, flow);

    DAQ_PktHdr_t* ph = p->context->pkth;
    memset(ph, 0, sizeof(*ph));
    packet_gettimeofday(&ph->ts);

    p->pktlen = 0;
    p->data = nullptr;
    p->dsize = 0;

    p->ptrs.set_pkt_type(PktType::PDU);
    p->proto_bits |= PROTO_BIT__TCP;
    p->flow = flow;
    p->packet_flags |= flags;

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

    p->ip_proto_next = (IpProtocol)flow->ip_proto;

    set_inspection_policy(flow->inspection_policy_id);
    const SnortConfig* sc = SnortConfig::get_conf();
    set_ips_policy(sc, flow->ips_policy_id);

    return p;
}

void TcpReassembler::finish_and_final_flush(
    TcpReassemblerState& trs, Flow* flow, bool clear, Packet* p)
{
    bool pending = clear and paf_initialized(&trs.paf_state)
        and trs.tracker->splitter_finish(flow);

    if ( pending and !(flow->ssn_state.ignore_direction & trs.ignore_dir) )
        final_flush(trs, p, trs.packet_dir);
}

// Call this only from outside reassembly.
void TcpReassembler::flush_queued_segments(
    TcpReassemblerState& trs, Flow* flow, bool clear, const Packet* p)
{
    if ( p )
    {
        finish_and_final_flush(trs, flow, clear, const_cast<Packet*>(p));
    }
    else
    {
        Packet* pdu = get_packet(flow, trs.packet_dir, trs.server_side);

        bool pending = clear and paf_initialized(&trs.paf_state);

        if ( pending )
        {
            DetectionEngine de;
            pending = trs.tracker->splitter_finish(flow);
        }

        if ( pending and !(flow->ssn_state.ignore_direction & trs.ignore_dir) )
            final_flush(trs, pdu, trs.packet_dir);
    }
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

// see scan_data_post_ack() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
int32_t TcpReassembler::scan_data_pre_ack(TcpReassemblerState& trs, uint32_t* flags, Packet* p)
{
    assert(trs.sos.session->flow == p->flow);

    int32_t ret_val = FINAL_FLUSH_HOLD;

    if ( SEQ_GT(trs.sos.seglist.head->c_seq, trs.sos.seglist_base_seq) )
        return ret_val;

    if ( !trs.sos.seglist.cur_rseg )
        trs.sos.seglist.cur_rseg = trs.sos.seglist.cur_sseg;

    if ( !is_q_sequenced(trs) )
        return ret_val;

    TcpSegmentNode* tsn = trs.sos.seglist.cur_sseg;
    uint32_t total = tsn->c_seq - trs.sos.seglist_base_seq;

    ret_val = FINAL_FLUSH_OK;
    while ( tsn && *flags )
    {
        total += tsn->c_len;

        uint32_t end = tsn->c_seq + tsn->c_len;
        uint32_t pos = paf_position(&trs.paf_state);

        if ( paf_initialized(&trs.paf_state) && SEQ_LEQ(end, pos) )
        {
            if ( !next_no_gap(*tsn) )
            {
                ret_val = FINAL_FLUSH_HOLD;
                break;
            }

            tsn = tsn->next;
            continue;
        }

        if ( next_no_gap_c(*tsn) )
            *flags |= PKT_MORE_TO_FLUSH;
        else
            *flags &= ~PKT_MORE_TO_FLUSH;
        int32_t flush_pt = paf_check(
            trs.tracker->get_splitter(), &trs.paf_state, p, tsn->payload(),
            tsn->c_len, total, tsn->c_seq, flags);

        if (flush_pt >= 0)
        {
            trs.sos.seglist.cur_sseg = tsn;
            return flush_pt;
        }

        if (!next_no_gap(*tsn) || (trs.paf_state.paf == StreamSplitter::STOP))
        {
            if ( !(next_no_gap(*tsn) || fin_no_gap(*tsn, trs)) )
                ret_val = FINAL_FLUSH_HOLD;
            break;
        }

        tsn = tsn->next;
    }

    trs.sos.seglist.cur_sseg = tsn;
    return ret_val;
}

static inline void fallback(TcpStreamTracker& trk, bool server_side, uint16_t max)
{
#ifndef NDEBUG
    StreamSplitter* splitter = trk.get_splitter();
    assert(splitter);

    // FIXIT-L: consolidate these 3
    bool to_server = splitter->to_server();
    assert(splitter && server_side == to_server && server_side == !trk.client_tracker);
#endif

    trk.set_splitter(new AtomSplitter(server_side, max));
    tcpStats.partial_fallbacks++;
}

void TcpReassembler::fallback(TcpStreamTracker& tracker, bool server_side)
{
    uint16_t max = tracker.session->tcp_config->paf_max;
    ::fallback(tracker, server_side, max);

    Flow* flow = tracker.session->flow;
    if ( server_side )
        flow->set_session_flags(SSNFLAG_ABORT_SERVER);
    else
        flow->set_session_flags(SSNFLAG_ABORT_CLIENT);

    if ( flow->gadget and both_splitters_aborted(flow) )
    {
        flow->clear_gadget();
        tcpStats.inspector_fallbacks++;
    }
}

bool TcpReassembler::segment_within_seglist_window(TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    uint32_t start, end = (trs.sos.seglist.tail->i_seq + trs.sos.seglist.tail->i_len);

    if ( SEQ_LT(trs.sos.seglist_base_seq, trs.sos.seglist.head->i_seq) )
        start = trs.sos.seglist_base_seq;
    else
        start = trs.sos.seglist.head->i_seq;

    // Left side
    if ( SEQ_LEQ(tsd.get_end_seq(), start) )
        return false;

    // Right side
    if ( SEQ_GEQ(tsd.get_seq(), end) )
        return false;

    return true;
}

void TcpReassembler::check_first_segment_hole(TcpReassemblerState& trs)
{
    if ( SEQ_LT(trs.sos.seglist_base_seq, trs.sos.seglist.head->c_seq)
        and SEQ_EQ(trs.sos.seglist_base_seq, trs.tracker->rcv_nxt) )
        {
            trs.sos.seglist_base_seq = trs.sos.seglist.head->c_seq;
            trs.tracker->rcv_nxt = trs.tracker->r_win_base;
            trs.paf_state.paf = StreamSplitter::START;
        }
}

bool TcpReassembler::has_seglist_hole(TcpReassemblerState& trs, TcpSegmentNode& tsn, PAF_State& ps,
    uint32_t& total, uint32_t& flags)
{
    if ( !tsn.prev or SEQ_GEQ(tsn.prev->c_seq + tsn.prev->c_len, tsn.c_seq) or
        SEQ_GEQ(tsn.c_seq, trs.tracker->r_win_base) )
        {
            check_first_segment_hole(trs);
            return false;
        }

    // safety - prevent seq + total < seq
    if ( total > 0x7FFFFFFF )
        total = 0x7FFFFFFF;

    if ( !ps.tot )
        flags |= PKT_PDU_HEAD;

    ps.paf = StreamSplitter::SKIP;
    return true;
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
int32_t TcpReassembler::scan_data_post_ack(TcpReassemblerState& trs, uint32_t* flags, Packet* p)
{
    assert(trs.sos.session->flow == p->flow);

    int32_t ret_val = FINAL_FLUSH_HOLD;

    if ( !trs.sos.seglist.cur_sseg || SEQ_GEQ(trs.sos.seglist_base_seq, trs.tracker->r_win_base) )
        return ret_val ;

    if ( !trs.sos.seglist.cur_rseg )
        trs.sos.seglist.cur_rseg = trs.sos.seglist.cur_sseg;

    StreamSplitter* splitter = trs.tracker->get_splitter();

    uint32_t total = 0;
    TcpSegmentNode* tsn = trs.sos.seglist.cur_sseg;
    if ( paf_initialized(&trs.paf_state) )
    {
        uint32_t end_seq = tsn->c_seq + tsn->c_len;
        if ( SEQ_EQ(end_seq, paf_position(&trs.paf_state)) )
        {
            total = end_seq - trs.sos.seglist_base_seq;
            tsn = tsn->next;
        }
        else
            total = tsn->c_seq - trs.sos.seglist.cur_rseg->c_seq;
    }

    ret_val = FINAL_FLUSH_OK;
    while (tsn && *flags && SEQ_LT(tsn->c_seq, trs.tracker->r_win_base))
    {
        // only flush acked data that fits in pdu reassembly buffer...
        uint32_t end = tsn->c_seq + tsn->c_len;
        uint32_t flush_len;
        int32_t flush_pt;

        if ( SEQ_GT(end, trs.tracker->r_win_base))
            flush_len = trs.tracker->r_win_base - tsn->c_seq;
        else
            flush_len = tsn->c_len;

        if ( next_acked_no_gap_c(*tsn, trs) )
            *flags |= PKT_MORE_TO_FLUSH;
        else
            *flags &= ~PKT_MORE_TO_FLUSH;

        if ( has_seglist_hole(trs, *tsn, trs.paf_state, total, *flags) )
            flush_pt = total;
        else
        {
            total += flush_len;
            flush_pt = paf_check(splitter, &trs.paf_state, p, tsn->payload(),
                flush_len, total, tsn->c_seq, flags);
        }

        // Get splitter from tracker as paf check may change it.
        splitter = trs.tracker->get_splitter();
        trs.sos.seglist.cur_sseg = tsn;

        if ( flush_pt >= 0 )
        {
            trs.sos.seglist_base_seq = trs.sos.seglist.cur_rseg->c_seq;
            return flush_pt;
        }

        if (flush_len < tsn->c_len || (splitter->is_paf() and !next_no_gap(*tsn)) ||
            (trs.paf_state.paf == StreamSplitter::STOP))
        {
            if ( !(next_no_gap(*tsn) || fin_acked_no_gap(*tsn, trs)) )
                ret_val = FINAL_FLUSH_HOLD;
            break;
        }

        tsn = tsn->next;
    }

    return ret_val;
}

int TcpReassembler::flush_on_data_policy(TcpReassemblerState& trs, Packet* p)
{
    uint32_t flushed = 0;
    last_pdu = nullptr;

    switch ( trs.tracker->get_flush_policy() )
    {
    case STREAM_FLPOLICY_IGNORE:
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
        break;

    case STREAM_FLPOLICY_ON_DATA:
        if ( trs.sos.seglist.head )
        {
            uint32_t flags;
            int32_t flush_amt;
            do
            {
                flags = get_forward_packet_dir(trs, p);
                flush_amt = scan_data_pre_ack(trs, &flags, p);
                if ( flush_amt <= 0 )
                    break;

                flushed += flush_to_seq(trs, flush_amt, p, flags);
            }
            while ( trs.sos.seglist.head and !p->flow->is_inspection_disabled() );

            if ( (trs.paf_state.paf == StreamSplitter::ABORT) && trs.tracker->is_splitter_paf() )
            {
                fallback(*trs.tracker, trs.server_side);
                return flush_on_data_policy(trs, p);
            }
            else if ( trs.tracker->fin_seq_status >= TcpStreamTracker::FIN_WITH_SEQ_SEEN and
                -1 <= flush_amt and flush_amt <= 0 and
                trs.paf_state.paf == StreamSplitter::SEARCH and
                !p->flow->searching_for_service() )
            {
                // we are on a FIN, the data has been scanned, it has no gaps,
                // but somehow we are waiting for more data - do final flush here
                finish_and_final_flush(trs, p->flow, true, p);
            }
        }
        break;
    }

    if ( !trs.sos.seglist.head )
        return flushed;

    if ( trs.tracker->is_retransmit_of_held_packet(p) )
        flushed = perform_partial_flush(trs, p, flushed);

    // FIXIT-M a drop rule will yoink the seglist out from under us
    // because apply_delayed_action is only deferred to end of context
    // this is causing stability issues
    if ( flushed and trs.sos.seg_count and
        !trs.sos.session->flow->two_way_traffic() and !p->ptrs.tcph->is_syn() )
    {
        TcpStreamTracker::TcpState peer = trs.tracker->session->get_peer_state(trs.tracker);

        if ( peer == TcpStreamTracker::TCP_SYN_SENT || peer == TcpStreamTracker::TCP_SYN_RECV )
        {
            purge_to_seq(trs, trs.sos.seglist.head->i_seq + flushed);
            trs.tracker->r_win_base = trs.sos.seglist_base_seq;
        }
    }
    return flushed;
}

void TcpReassembler::skip_seglist_hole(TcpReassemblerState& trs, Packet* p, uint32_t flags,
    int32_t flush_amt)
{
    if ( trs.tracker->is_splitter_paf() )
    {
        if ( flush_amt > 0 )
            update_skipped_bytes(flush_amt, trs);
        fallback(*trs.tracker, trs.server_side);
    }
    else
    {
        if ( flush_amt > 0 )
            flush_to_seq(trs, flush_amt, p, flags);
        trs.paf_state.paf = StreamSplitter::START;
    }

    if ( trs.sos.seglist.head )
    {
        if ( flush_amt > 0 )
            purge_to_seq(trs, trs.sos.seglist_base_seq + flush_amt);
        trs.sos.seglist_base_seq = trs.sos.seglist.head->c_seq;
    }
    else
        trs.sos.seglist_base_seq = trs.tracker->r_win_base;

    trs.tracker->rcv_nxt = trs.tracker->r_win_base;
    trs.sos.seglist.cur_rseg = trs.sos.seglist.head;
}

int TcpReassembler::flush_on_ack_policy(TcpReassemblerState& trs, Packet* p)
{
    uint32_t flushed = 0;
    last_pdu = nullptr;

    switch ( trs.tracker->get_flush_policy() )
    {
    case STREAM_FLPOLICY_IGNORE:
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
    {
        int32_t flush_amt;
        uint32_t flags;

        do
        {
            flags = get_reverse_packet_dir(trs, p);
            flush_amt = scan_data_post_ack(trs, &flags, p);
            if ( flush_amt <= 0 or trs.paf_state.paf == StreamSplitter::SKIP )
                break;

            // for consistency with other cases, should return total
            // but that breaks flushing pipelined pdus
            flushed += flush_to_seq(trs, flush_amt, p, flags);
            assert( flushed );

            // ideally we would purge just once after this loop but that throws off base
            if ( trs.sos.seglist.head )
                purge_to_seq(trs, trs.sos.seglist_base_seq);
        }
        while ( trs.sos.seglist.head and !p->flow->is_inspection_disabled() );

        if ( (trs.paf_state.paf == StreamSplitter::ABORT) && trs.tracker->is_splitter_paf() )
        {
            fallback(*trs.tracker, trs.server_side);
            return flush_on_ack_policy(trs, p);
        }
        else if ( trs.paf_state.paf == StreamSplitter::SKIP )
        {
            skip_seglist_hole(trs, p, flags, flush_amt);
            return flush_on_ack_policy(trs, p);
        }
        else if ( -1 <= flush_amt and flush_amt <= 0 and
            trs.paf_state.paf == StreamSplitter::SEARCH and
            trs.tracker->fin_seq_status == TcpStreamTracker::FIN_WITH_SEQ_ACKED and
            !p->flow->searching_for_service() )
        {
            // we are acknowledging a FIN, the data has been scanned, it has no gaps,
            // but somehow we are waiting for more data - do final flush here
            finish_and_final_flush(trs, p->flow, true, p);
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
    uint32_t seq = tsd.get_seq();

    if ( tcph->is_syn() )
        seq++;

    if ( SEQ_GT(trs.sos.seglist_base_seq, seq) )
    {
        overlap = trs.sos.seglist_base_seq - tsd.get_seq();
        if ( overlap >= tsd.get_len() )
            return;
    }

    add_reassembly_segment(
        trs, tsd, tsd.get_len(), overlap, 0, seq + overlap, nullptr);
}

void TcpReassembler::init_overlap_editor(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    TcpSegmentNode* left = nullptr, *right = nullptr, *tsn = nullptr;
    int32_t dist_head = 0, dist_tail = 0;

    if ( trs.sos.seglist.head && trs.sos.seglist.tail )
    {
        if ( SEQ_GT(tsd.get_seq(), trs.sos.seglist.head->i_seq) )
            dist_head = tsd.get_seq() - trs.sos.seglist.head->i_seq;
        else
            dist_head = trs.sos.seglist.head->i_seq - tsd.get_seq();

        if ( SEQ_GT(tsd.get_seq(), trs.sos.seglist.tail->i_seq) )
            dist_tail = tsd.get_seq() - trs.sos.seglist.tail->i_seq;
        else
            dist_tail = trs.sos.seglist.tail->i_seq - tsd.get_seq();
    }

    if ( SEQ_LEQ(dist_head, dist_tail) )
    {
        for ( tsn = trs.sos.seglist.head; tsn; tsn = tsn->next )
        {
            right = tsn;

            if ( SEQ_GEQ(right->i_seq, tsd.get_seq() ) )
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

            if ( SEQ_LT(left->i_seq, tsd.get_seq() ) )
                break;

            right = left;
        }

        if (tsn == nullptr)
            left = nullptr;
    }

    trs.sos.init_soe(tsd, left, right);
}

void TcpReassembler::insert_segment_in_seglist(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    // NORM fast tracks are in sequence - no norms
    if ( trs.sos.seglist.tail && is_segment_fasttrack(trs, trs.sos.seglist.tail, tsd) )
    {
        /* segment fit cleanly at the end of the segment list */
        add_reassembly_segment(
            trs, tsd, tsd.get_len(), 0, 0, tsd.get_seq(), trs.sos.seglist.tail);
        return;
    }

    init_overlap_editor(trs, tsd);
    eval_left(trs);
    eval_right(trs);

    if ( trs.sos.keep_segment )
    {
        if ( !trs.sos.left and trs.sos.right and
            paf_initialized(&trs.paf_state) and trs.paf_state.pos > tsd.get_seq() )
        {
            return;
        }

        /* Adjust slide so that is correct relative to orig seq */
        trs.sos.slide = trs.sos.seq - tsd.get_seq();
        // FIXIT-L for some reason length - slide - trunc_len is sometimes negative
        if (trs.sos.len - trs.sos.slide - trs.sos.trunc_len < 0)
            return;

        add_reassembly_segment(
            trs, tsd, trs.sos.len, trs.sos.slide, trs.sos.trunc_len, trs.sos.seq, trs.sos.left);
    }
}

void TcpReassembler::queue_packet_for_reassembly(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd)
{
    if ( trs.sos.seg_count == 0 )
    {
        insert_segment_in_empty_seglist(trs, tsd);
        return;
    }

    if ( SEQ_GT(trs.tracker->r_win_base, tsd.get_seq() ) )
    {
        const int32_t offset = trs.tracker->r_win_base - tsd.get_seq();

        if ( offset < tsd.get_len() )
        {
            tsd.slide_segment_in_rcv_window(offset);
            insert_segment_in_seglist(trs, tsd);
            tsd.slide_segment_in_rcv_window(-offset);
        }
    }
    else
        insert_segment_in_seglist(trs, tsd);
}

uint32_t TcpReassembler::perform_partial_flush(TcpReassemblerState& trs, Flow* flow, Packet*& p)
{
    p = get_packet(flow, trs.packet_dir, trs.server_side);
    return perform_partial_flush(trs, p);
}

// No error checking here, so the caller must ensure that p, p->flow and context
// are not null.
uint32_t TcpReassembler::perform_partial_flush(TcpReassemblerState& trs, Packet* p, uint32_t flushed)
{
    if ( trs.tracker->get_splitter()->init_partial_flush(p->flow) )
    {
        flushed += flush_stream(trs, p, trs.packet_dir, false);
        paf_jump(&trs.paf_state, flushed);
        tcpStats.partial_flushes++;
        tcpStats.partial_flush_bytes += flushed;
        if ( trs.sos.seg_count )
        {
            purge_to_seq(trs, trs.sos.seglist.head->i_seq + flushed);
            trs.tracker->r_win_base = trs.sos.seglist_base_seq;
        }
    }
    return flushed;
}
