//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembly.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015


#include <errno.h>
#include <assert.h>

#include "protocols/packet.h"
#include "stream/stream.h"
#include "time/profiler.h"
#include "flow/flow_control.h"

#include "tcp_module.h"
#include "tcp_session.h"
#include "tcp_events.h"
#include "tcp_normalization.h"
#include "tcp_reassembly.h"
#include "tcp_defs.h"

#define SL_BUF_FLUSHED 1

THREAD_LOCAL Packet* s5_pkt = nullptr;
THREAD_LOCAL Memcap* tcp_memcap = nullptr;  // FIXIT - should be part of reassembly/flush class

//-------------------------------------------------------------------------
// TcpSegment stuff
//-------------------------------------------------------------------------

TcpSegment* TcpSegment::init(Packet* p, const struct timeval& tv, const uint8_t* data, unsigned dsize)
{
    TcpSegment* ss;
    unsigned size = sizeof(*ss);

    if (dsize > 0)
        size += dsize - 1;  // ss contains 1st byte

    tcp_memcap->alloc(size);

    if (tcp_memcap->at_max())
    {
        sfBase.iStreamFaults++;

        // FIXIT eliminate the packet dependency?
        if (p)
            flow_con->prune_flows(PktType::TCP, p);
    }

    ss = (TcpSegment*) malloc(size);

    if (!ss)
        return nullptr;

    ss->tv = tv;
    memcpy(ss->data, data, dsize);
    ss->orig_dsize = dsize;

    ss->payload = ss->data;
    ss->prev = ss->next = nullptr;
    ss->ts = ss->seq = 0;
    ss->size = ss->orig_dsize;
    ss->urg_offset = 0;
    ss->buffered = 0;

    return ss;
}

void TcpSegment::term(TcpSegment* seg)
{
    unsigned dropped = sizeof(TcpSegment);

    if (seg->size > 0)
        dropped += seg->size - 1;  // seg contains 1st byte

    tcp_memcap->dealloc(dropped);
    free(seg);
    tcpStats.segs_released++;
}

bool TcpSegment::is_retransmit(const uint8_t* rdata, uint16_t rsize,
        uint32_t rseq)
{
    // retransmit must have same payload at same place
    if (!SEQ_EQ(seq, rseq))
        return false;

    if (((size <= rsize) and !memcmp(data, rdata, size))
            or ((size > rsize) and !memcmp(data, rdata, rsize)))
        return true;

    return false;
}

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
void SetPacketHeaderFoo(TcpSession* tcpssn, const Packet* p)
{
    if ( tcpssn->daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING )
    {
        tcpssn->ingress_index = p->pkth->ingress_index;
        tcpssn->ingress_group = p->pkth->ingress_group;
        // ssn egress may be unknown, but will be correct
        tcpssn->egress_index = p->pkth->egress_index;
        tcpssn->egress_group = p->pkth->egress_group;
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        tcpssn->ingress_index = p->pkth->ingress_index;
        tcpssn->ingress_group = p->pkth->ingress_group;
        // ssn egress not always correct here
    }
    else
    {
        // ssn ingress not always correct here
        tcpssn->egress_index = p->pkth->ingress_index;
        tcpssn->egress_group = p->pkth->ingress_group;
    }
    tcpssn->daq_flags = p->pkth->flags;
    tcpssn->address_space_id = p->pkth->address_space_id;
}

void GetPacketHeaderFoo(
        const TcpSession* tcpssn, DAQ_PktHdr_t* pkth, uint32_t dir)
{
    if ( (dir & PKT_FROM_CLIENT) || (tcpssn->daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING) )
    {
        pkth->ingress_index = tcpssn->ingress_index;
        pkth->ingress_group = tcpssn->ingress_group;
        pkth->egress_index = tcpssn->egress_index;
        pkth->egress_group = tcpssn->egress_group;
    }
    else
    {
        pkth->ingress_index = tcpssn->egress_index;
        pkth->ingress_group = tcpssn->egress_group;
        pkth->egress_index = tcpssn->ingress_index;
        pkth->egress_group = tcpssn->ingress_group;
    }
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    pkth->opaque = 0;
#endif
    pkth->flags = tcpssn->daq_flags;
    pkth->address_space_id = tcpssn->address_space_id;
}

void SwapPacketHeaderFoo(TcpSession* tcpssn)
{
    if ( tcpssn->egress_index != DAQ_PKTHDR_UNKNOWN )
    {
        int32_t ingress_index;
        int32_t ingress_group;

        ingress_index = tcpssn->ingress_index;
        ingress_group = tcpssn->ingress_group;
        tcpssn->ingress_index = tcpssn->egress_index;
        tcpssn->ingress_group = tcpssn->egress_group;
        tcpssn->egress_index = ingress_index;
        tcpssn->egress_group = ingress_group;
    }
}

#endif

#ifdef SEG_TEST
static void CheckSegments (const TcpTracker* a)
{
    TcpSegment* ss = a->seglist;
    uint32_t sx = ss ? ss->seq : 0;

    while ( ss )
    {
        if ( SEQ_GT(sx, ss->seq) )
        {
            const int SEGBORK = 0;
            assert(SEGBORK);
        }
        sx = ss->seq + ss->size;
        ss = ss->next;
    }
}

#endif

void RetransmitProcess(Packet* p, TcpSession*)
{
    // Data has already been analyzed so don't bother looking at it again.
    DisableDetect(p);
}

void RetransmitHandle(Packet* p, TcpSession* tcpssn)
{
    tcpssn->flow->call_handlers(p, false);
}
static inline NormMode get_norm_ips(TcpTracker* st)
{
    if (st->config->policy == STREAM_POLICY_PROXY)
        return NORM_MODE_OFF;

    return Normalize_GetMode(NORM_TCP_IPS);
}

uint32_t SegsToFlush(const TcpTracker* st, unsigned max)
{
    uint32_t n = st->seg_count - st->flush_count;
    TcpSegment* s;

    if (!n || max == 1)
        return n;

    n = 0;
    s = st->seglist;

    while (s)
    {
        if (!s->buffered && SEQ_LT(s->seq, st->r_win_base))
            n++;

        if (max && n == max)
            return n;

        s = s->next;
    }
    return n;
}

static inline bool DataToFlush(const TcpTracker* st)
{
    // needed by stream_reassemble:action disable; can fire on rebuilt
    // packets, yanking the splitter out from under us :(
    if (!st->flush_policy or !st->splitter)
        return false;

    if (st->flush_policy == STREAM_FLPOLICY_ON_DATA || st->splitter->is_paf())
        return (SegsToFlush(st, 1) > 0);

    return (SegsToFlush(st, 2) > 1);  // FIXIT-L return false?
}

static int StreamSeglistDeleteNode(TcpTracker* st, TcpSegment* seg)
{
    int ret;
    assert(st && seg);

    DebugFormat(DEBUG_STREAM_STATE, "Dropping segment at seq %X, len %d\n", seg->seq, seg->size);

    if (seg->prev)
        seg->prev->next = seg->next;
    else
        st->seglist = seg->next;

    if (seg->next)
        seg->next->prev = seg->prev;
    else
        st->seglist_tail = seg->prev;

    st->seg_bytes_logical -= seg->size;
    st->seg_bytes_total -= seg->orig_dsize;

    ret = seg->orig_dsize;

    if (seg->buffered)
    {
        tcpStats.segs_used++;
        st->flush_count--;
    }

    if (st->seglist_next == seg)
        st->seglist_next = NULL;

    TcpSegment::term(seg);
    st->seg_count--;

    return ret;
}

static int StreamSeglistDeleteNodeTrim(TcpTracker* st, TcpSegment* seg, uint32_t flush_seq)
{
    assert(st && seg);

    if (paf_active(&st->paf_state) && ((seg->seq + seg->size) > flush_seq))
    {
        uint32_t delta = flush_seq - seg->seq;

        if (delta < seg->size)
        {
            DebugFormat(DEBUG_STREAM_STATE, "Left-Trimming segment at seq %X, len %d, delta %u\n", seg->seq, seg->size, delta);

            seg->seq = flush_seq;
            seg->size -= (uint16_t) delta;

            st->seg_bytes_logical -= delta;
            return 0;
        }
    }
    return StreamSeglistDeleteNode(st, seg);
}

static void DeleteSeglist(TcpSegment *listhead)
{
    TcpSegment *idx = listhead;
    TcpSegment *dump_me;
    int i = 0;

    DebugMessage(DEBUG_STREAM_STATE, "In DeleteSeglist\n");
    while (idx)
    {
        i++;
        dump_me = idx;
        idx = idx->next;
        TcpSegment::term(dump_me);
    }

    DebugFormat(DEBUG_STREAM_STATE, "Dropped %d segments\n", i);
}

static void StreamSeglistAddNode(TcpTracker *st, TcpSegment *prev, TcpSegment *ss)
{
    if (prev)
    {
        ss->next = prev->next;
        ss->prev = prev;
        prev->next = ss;
        if (ss->next)
            ss->next->prev = ss;
        else
            st->seglist_tail = ss;
    } else
    {
        ss->next = st->seglist;
        if (ss->next)
            ss->next->prev = ss;
        else
            st->seglist_tail = ss;
        st->seglist = ss;
    }
    st->seg_count++;
    st->seg_bytes_total += ss->orig_dsize;
    st->total_segs_queued++;
    tcpStats.segs_queued++;
}

static inline int SegmentFastTrack(TcpSegment *tail, TcpDataBlock *tdb)
{
    DebugFormat(DEBUG_STREAM_STATE,  "Checking seq for fast track: %X > %X\n", tdb->seq, tail->seq + tail->size);

    if ( SEQ_EQ( tdb->seq, tail->seq + tail->size ) )
        return 1;

    return 0;
}

int AddStreamNode(TcpTracker *st, Packet *p, TcpDataBlock* tdb, int16_t len, uint32_t slide,
        uint32_t trunc, uint32_t seq, TcpSegment *left)
{
    TcpSegment *ss = NULL;
    int32_t newSize = len - slide - trunc;

    if ( newSize <= 0 )
    {
        /*
         * zero size data because of trimming.  Don't
         * insert it
         */
        DebugFormat(DEBUG_STREAM_STATE, "zero size TCP data after left & right trimming " "(len: %d slide: %d trunc: %d)\n", len, slide, trunc);
        inc_tcp_discards();
        NormalTrimPayloadIfWin(p, 0, tdb);

#ifdef DEBUG_STREAM_EX
        {
            TcpSegment *idx = st->seglist;
            unsigned long i = 0;
            DebugFormat(DEBUG_STREAM_STATE, "Dumping seglist, %d segments\n", st->seg_count);
            while (idx)
            {
                i++;
                DebugFormat(DEBUG_STREAM_STATE, "%d  ptr: %p  seq: 0x%X  size: %d nxt: %p prv: %p\n",
                        i, idx, idx->seq, idx->size, idx->next, idx->prev);

                if (st->seg_count < i)
                    FatalError("Circular list\n");

                idx = idx->next;
            }
        }
#endif
        return STREAM_INSERT_ANOMALY;
    }

    // FIXIT-L don't allocate overlapped part
    ss = TcpSegment::init(p, p->pkth->ts, p->data, p->dsize);

    if (!ss)
        return STREAM_INSERT_FAILED;

    ss->payload = ss->data + slide;
    ss->size = (uint16_t) newSize;
    ss->seq = seq;
    ss->ts = tdb->ts;

    /* handle the urg ptr */
    if (p->ptrs.tcph->th_flags & TH_URG)
    {
        if (p->ptrs.tcph->urp() < p->dsize)
        {
            switch (st->os_policy)
            {
                case STREAM_POLICY_LINUX:
                case STREAM_POLICY_OLD_LINUX:
                    /* Linux, Old linux discard data from urgent pointer
                       If urg pointer is 0, it's treated as a 1 */
                    ss->urg_offset = p->ptrs.tcph->urp();
                    if (ss->urg_offset == 0)
                    {
                        ss->urg_offset = 1;
                    }
                    break;

                case STREAM_POLICY_FIRST:
                case STREAM_POLICY_LAST:
                case STREAM_POLICY_BSD:
                case STREAM_POLICY_MACOS:
                case STREAM_POLICY_SOLARIS:
                case STREAM_POLICY_WINDOWS:
                case STREAM_POLICY_WINDOWS2K3:
                case STREAM_POLICY_VISTA:
                case STREAM_POLICY_HPUX11:
                case STREAM_POLICY_HPUX10:
                case STREAM_POLICY_IRIX:
                    /* Others discard data from urgent pointer
                       If urg pointer is beyond this packet, it's treated as a 0 */
                    ss->urg_offset = p->ptrs.tcph->urp();
                    if (ss->urg_offset > p->dsize)
                    {
                        ss->urg_offset = 0;
                    }
                    break;
            }
        }
    }

    StreamSeglistAddNode(st, left, ss);
    st->seg_bytes_logical += ss->size;
    st->total_bytes_queued += ss->size;

    p->packet_flags |= PKT_STREAM_INSERT;

    DebugFormat(DEBUG_STREAM_STATE, "added %d bytes on segment list @ seq: 0x%X, total %lu, %d segments queued\n",
            ss->size, ss->seq, st->seg_bytes_logical, SegsToFlush(st, 0));

#ifdef SEG_TEST
    CheckSegments(st);
#endif
    return STREAM_INSERT_OK;
}

static int DupStreamNode(Packet *p, TcpTracker *st, TcpSegment *left, TcpSegment **retSeg)
{
    TcpSegment* ss = TcpSegment::init(p, left->tv, left->payload, left->size);

    if (!ss)
        return STREAM_INSERT_FAILED;

    tcpStats.segs_split++;

    /* twiddle the values for overlaps */
    ss->payload = ss->data;
    ss->size = left->size;
    ss->seq = left->seq;

    StreamSeglistAddNode(st, left, ss);
    //st->total_bytes_queued += ss->size;

    DebugFormat(DEBUG_STREAM_STATE, "added %d bytes on segment list @ seq: 0x%X, total %lu, %d segments queued\n",
            ss->size, ss->seq, st->seg_bytes_logical, SegsToFlush(st, 0));

    *retSeg = ss;
    return STREAM_INSERT_OK;
}

static inline int purge_alerts(TcpTracker *st, uint32_t /*flush_seq*/,  Flow* flow)
{
    int i;
    int new_count = 0;

    for (i = 0; i < st->alert_count; i++)
    {
        StreamAlertInfo* ai = st->alerts + i;

        //if (SEQ_LT(ai->seq, flush_seq) )
        {
            stream.log_extra_data(flow, st->xtradata_mask, ai->event_id,
                    ai->event_second);

            memset(ai, 0, sizeof(*ai));
        }
#if 0
        else
        {
            if (new_count != i)
            {
                st->alerts[new_count] = st->alerts[i];
            }
            new_count++;
        }
#endif
    }
    st->alert_count = new_count;

    return new_count;
}

static inline int purge_to_seq(TcpSession *tcpssn, TcpTracker *st, uint32_t flush_seq)
{
    TcpSegment *ss = nullptr;
    TcpSegment *dump_me = nullptr;
    int purged_bytes = 0;
    uint32_t last_ts = 0;

    if (st->seglist == nullptr)
    {
        if (SEQ_LT(st->seglist_base_seq, flush_seq))
        {
            DebugFormat(DEBUG_STREAM_STATE, "setting st->seglist_base_seq to 0x%X\n", flush_seq);
            st->seglist_base_seq = flush_seq;
        }
        return 0;
    }

    ss = st->seglist;

    DebugFormat(DEBUG_STREAM_STATE, "In purge_to_seq, start seq = 0x%X end seq = 0x%X delta %d\n",
            ss->seq, flush_seq, flush_seq-ss->seq);
    while (ss)
    {
        DebugFormat(DEBUG_STREAM_STATE, "s: %X  sz: %d\n", ss->seq, ss->size);
        dump_me = ss;

        ss = ss->next;
        if (SEQ_LT(dump_me->seq, flush_seq))
        {
            if (dump_me->ts > last_ts)
            {
                last_ts = dump_me->ts;
            }
            purged_bytes += StreamSeglistDeleteNodeTrim(st, dump_me, flush_seq);
        } else
            break;
    }

    if (SEQ_LT(st->seglist_base_seq, flush_seq))
    {
        DebugFormat(DEBUG_STREAM_STATE, "setting st->seglist_base_seq to 0x%X\n", flush_seq);
        st->seglist_base_seq = flush_seq;
    }
    if (SEQ_LT(st->r_nxt_ack, flush_seq))
        st->r_nxt_ack = flush_seq;

    purge_alerts(st, flush_seq, tcpssn->flow);

    if (st->seglist == nullptr)
    {
        st->seglist_tail = nullptr;
    }

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
     * code specificially looks for the NEXT sequence number.
     */
    if (!last_ts)
        return purged_bytes;

    if (st == &tcpssn->client)
    {
        int32_t delta = last_ts - tcpssn->server.ts_last;
        if (delta > 0)
            tcpssn->server.ts_last = last_ts;
    } else if (st == &tcpssn->server)
    {
        int32_t delta = last_ts - tcpssn->client.ts_last;
        if (delta > 0)
            tcpssn->client.ts_last = last_ts;
    }

    return purged_bytes;
}

// purge_flushed_ackd():
// * must only purge flushed and acked bytes
// * we may flush partial segments
// * must adjust seq->seq and seg->size when a flush gets only the
//   initial part of a segment
// * FIXIT-L need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
int purge_flushed_ackd(TcpSession *tcpssn, TcpTracker *st)
{
    TcpSegment* seg = st->seglist;
    uint32_t seq;

    if (!st->seglist)
        return 0;

    seq = st->seglist->seq;

    while (seg && seg->buffered)
    {
        uint32_t end = seg->seq + seg->size;

        if (SEQ_GT(end, st->r_win_base))
        {
            seq = st->r_win_base;
            break;
        }
        seq = end;
        seg = seg->next;
    }
    if (seq != st->seglist->seq)
        return purge_to_seq(tcpssn, st, seq);

    return 0;
}

#define SEPARATOR \
    "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

static void ShowRebuiltPacket(TcpSession* ssn, Packet* pkt)
{
    if ((ssn->client.config->flags & STREAM_CONFIG_SHOW_PACKETS)
            || (ssn->server.config->flags & STREAM_CONFIG_SHOW_PACKETS))
    {
        LogFlow(pkt);
        LogNetData(pkt->data, pkt->dsize, pkt);
    }
}

static inline unsigned int getSegmentFlushSize(TcpTracker* st, TcpSegment *ss,
        uint32_t to_seq, unsigned int flushBufSize)
{
    unsigned int flushSize = ss->size;

    // copy only till flush buffer gets full
    if (flushSize > flushBufSize)
        flushSize = flushBufSize;

    // copy only to flush point
    if (paf_active(&st->paf_state) && SEQ_GT(ss->seq + flushSize, to_seq))
        flushSize = to_seq - ss->seq;

    return flushSize;
}

/*
 * flush the client seglist up to the most recently acked segment
 */
static int FlushStream(Packet* p, TcpTracker *st, uint32_t toSeq,
        uint8_t *flushbuf, const uint8_t *flushbuf_end)
{
    uint16_t bytes_flushed = 0;
    DEBUG_WRAP(uint32_t bytes_queued = st->seg_bytes_logical; );
    uint32_t segs = 0;
    uint32_t flags = PKT_PDU_HEAD;
    PROFILE_VARS;

    assert(st->seglist_next); MODULE_PROFILE_START(s5TcpBuildPacketPerfStats);

    uint32_t total = toSeq - st->seglist_next->seq;

    while (SEQ_LT(st->seglist_next->seq, toSeq))
    {
        TcpSegment* ss = st->seglist_next, *sr;
        unsigned flushbuf_size = flushbuf_end - flushbuf;
        unsigned bytes_to_copy = getSegmentFlushSize(st, ss, toSeq,
                flushbuf_size);
        unsigned bytes_copied = 0;
        assert(bytes_to_copy);

        DebugFormat(DEBUG_STREAM_STATE, "Flushing %u bytes from %X\n", bytes_to_copy, ss->seq);

        if (!ss->next || (bytes_to_copy < ss->size)
                || SEQ_EQ(ss->seq + bytes_to_copy, toSeq))
            flags |= PKT_PDU_TAIL;

        const StreamBuffer* sb = st->splitter->reassemble(p->flow, total,
                bytes_flushed, ss->payload, bytes_to_copy, flags, bytes_copied);

        flags = 0;

        if (sb)
        {
            s5_pkt->data = sb->data;
            s5_pkt->dsize = sb->length;
            assert(sb->length <= s5_pkt->max_dsize);

            // FIXIT-M flushbuf should be eliminated from this function
            // since we are actually using the stream splitter buffer
            flushbuf = (uint8_t*) s5_pkt->data;

            // ensure we stop here
            bytes_to_copy = bytes_copied;
        }
        assert(bytes_to_copy == bytes_copied);

        flushbuf += bytes_to_copy;
        bytes_flushed += bytes_to_copy;

        if (bytes_to_copy < ss->size&&
                DupStreamNode(nullptr, st, ss, &sr) == STREAM_INSERT_OK)
        {
            ss->size = bytes_to_copy;
            sr->seq += bytes_to_copy;
            sr->size -= bytes_to_copy;
            sr->payload += bytes_to_copy;
        }
        ss->buffered = SL_BUF_FLUSHED;
        st->flush_count++;
        segs++;

        if (flushbuf >= flushbuf_end)
            break;

        if (SEQ_EQ(ss->seq + bytes_to_copy, toSeq))
            break;

        /* Check for a gap/missing packet */
        // FIXIT-L PAF should account for missing data and resume
        // scanning at the start of next PDU instead of aborting.
        // FIXIT-L FIN may be in toSeq causing bogus gap counts.
        if (((ss->next && (ss->seq + ss->size != ss->next->seq))
                    || (!ss->next && (ss->seq + ss->size < toSeq)))
                && !(st->flags & TF_FIRST_PKT_MISSING))
        {
            if (ss->next)
                st->seglist_next = ss->next;

            st->flags |= TF_MISSING_PKT;
            break;
        }
        st->seglist_next = ss->next;

        if (sb || !st->seglist_next)
            break;
    }

    DEBUG_WRAP( bytes_queued -= bytes_flushed; );
    DebugFormat(DEBUG_STREAM_STATE, "flushed %d bytes / %d segs on stream, %d still queued\n",
            bytes_flushed, segs, bytes_queued);

    MODULE_PROFILE_END(s5TcpBuildPacketPerfStats);
    return bytes_flushed;
}

// FIXIT-L consolidate encode format, update, and this into new function?
static void prep_s5_pkt(Flow* flow, Packet* p, uint32_t pkt_flags)
{
    s5_pkt->ptrs.set_pkt_type(PktType::PDU);
    s5_pkt->proto_bits |= PROTO_BIT__TCP;
    s5_pkt->packet_flags |= (pkt_flags & PKT_PDU_FULL);
    s5_pkt->flow = flow;

    if (p == s5_pkt)
    {
        // final
        if (pkt_flags & PKT_FROM_SERVER)
        {
            s5_pkt->packet_flags |= PKT_FROM_SERVER;
            s5_pkt->ptrs.ip_api.set(flow->server_ip, flow->client_ip);
            s5_pkt->ptrs.sp = flow->server_port;
            s5_pkt->ptrs.dp = flow->client_port;
        } else
        {
            s5_pkt->packet_flags |= PKT_FROM_CLIENT;
            s5_pkt->ptrs.ip_api.set(flow->client_ip, flow->server_ip);
            s5_pkt->ptrs.sp = flow->client_port;
            s5_pkt->ptrs.dp = flow->server_port;
        }
    } else if (!p->packet_flags || (pkt_flags & p->packet_flags))
    {
        // forward
        s5_pkt->packet_flags |= (p->packet_flags
                & (PKT_FROM_CLIENT | PKT_FROM_SERVER));
        s5_pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_src(),
                *p->ptrs.ip_api.get_dst());
        s5_pkt->ptrs.sp = p->ptrs.sp;
        s5_pkt->ptrs.dp = p->ptrs.dp;
    } else
    {
        // reverse
        if (p->packet_flags & PKT_FROM_CLIENT)
            s5_pkt->packet_flags |= PKT_FROM_SERVER;
        else
            s5_pkt->packet_flags |= PKT_FROM_CLIENT;

        s5_pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(),
                *p->ptrs.ip_api.get_src());
        s5_pkt->ptrs.dp = p->ptrs.sp;
        s5_pkt->ptrs.sp = p->ptrs.dp;
    }
}

static inline int _flush_to_seq(TcpSession *tcpssn, TcpTracker *st,
        uint32_t bytes, Packet *p, uint32_t pkt_flags)
{
    uint32_t stop_seq;
    uint32_t footprint;
    uint32_t bytes_processed = 0;
    int32_t flushed_bytes;
    EncodeFlags enc_flags = 0;
    PROFILE_VARS;

    MODULE_PROFILE_START(s5TcpFlushPerfStats);

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    DAQ_PktHdr_t pkth;
    GetPacketHeaderFoo(tcpssn, &pkth, pkt_flags);
    PacketManager::format_tcp(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
#else
    PacketManager::format_tcp(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP);
#endif

    prep_s5_pkt(tcpssn->flow, p, pkt_flags);

    // if not specified, set bytes to flush to what was acked
    if (!bytes && SEQ_GT(st->r_win_base, st->seglist_base_seq))
        bytes = st->r_win_base - st->seglist_base_seq;

    // FIXIT-L this should not be necessary here
    st->seglist_base_seq = st->seglist_next->seq;
    stop_seq = st->seglist_base_seq + bytes;

    do
    {
        footprint = stop_seq - st->seglist_base_seq;

        if (footprint == 0)
        {
            DebugFormat(DEBUG_STREAM_STATE, "Negative footprint, bailing %d (0x%X - 0x%X)\n",
                    footprint, stop_seq, st->seglist_base_seq);
            MODULE_PROFILE_END(s5TcpFlushPerfStats);

            return bytes_processed;
        }

#ifdef DEBUG_STREAM_EX
        if (footprint < st->seg_bytes_logical)
        {
            DebugFormat(DEBUG_STREAM_STATE, "Footprint less than queued bytes, win_base: 0x%X base_seq: 0x%X\n",
                    stop_seq, st->seglist_base_seq);
        }
#endif

        if (footprint > s5_pkt->max_dsize)
        {
            /* this is as much as we can pack into a stream buffer */
            footprint = s5_pkt->max_dsize;
            stop_seq = st->seglist_base_seq + footprint;
        }

        DebugFormat(DEBUG_STREAM_STATE, "Attempting to flush %lu bytes\n", footprint);

        ((DAQ_PktHdr_t*) s5_pkt->pkth)->ts.tv_sec = st->seglist_next->tv.tv_sec;
        ((DAQ_PktHdr_t*) s5_pkt->pkth)->ts.tv_usec =
            st->seglist_next->tv.tv_usec;

        /* setup the pseudopacket payload */
        s5_pkt->dsize = 0;
        const uint8_t* s5_pkt_end = s5_pkt->data + s5_pkt->max_dsize;
        flushed_bytes = FlushStream(p, st, stop_seq, (uint8_t*) s5_pkt->data,
                s5_pkt_end);

        if (!flushed_bytes)
            break; /* No more data... bail */

        else if (!s5_pkt->dsize)
        {
            tcpStats.rebuilt_buffers++;
            bytes_processed += flushed_bytes;
        } else
        {
            s5_pkt->packet_flags |= (PKT_REBUILT_STREAM | PKT_STREAM_EST);

            if ((p->packet_flags & PKT_PDU_TAIL))
                s5_pkt->packet_flags |= PKT_PDU_TAIL;

            sfBase.iStreamFlushes++;
            bytes_processed += flushed_bytes;

            ShowRebuiltPacket(tcpssn, s5_pkt);
            tcpStats.rebuilt_packets++;
            UpdateStreamReassStats(&sfBase, flushed_bytes);

            MODULE_PROFILE_TMPEND(s5TcpFlushPerfStats);
            {
                PROFILE_VARS; MODULE_PROFILE_START(s5TcpProcessRebuiltPerfStats);

                Snort::detect_rebuilt_packet(s5_pkt);

                MODULE_PROFILE_END(s5TcpProcessRebuiltPerfStats);
            } MODULE_PROFILE_TMPSTART(s5TcpFlushPerfStats);
        }

        st->seglist_base_seq += flushed_bytes;

        DebugFormat(DEBUG_STREAM_STATE, "setting st->seglist_base_seq to 0x%X\n", st->seglist_base_seq);

        if (st->splitter)
            st->splitter->update();

        // TBD abort should be by PAF callback only since
        // recovery may be possible in some cases
        if (st->flags & TF_MISSING_PKT)
        {
            st->flags |= TF_MISSING_PREV_PKT;
            st->flags |= TF_PKT_MISSED;
            st->flags &= ~TF_MISSING_PKT;
            tcpStats.gaps++;
        } else
        {
            st->flags &= ~TF_MISSING_PREV_PKT;
        }
    } while (st->seglist_next and DataToFlush(st));

    /* tell them how many bytes we processed */
    MODULE_PROFILE_END(s5TcpFlushPerfStats);
    return bytes_processed;
}

/*
 * flush a seglist up to the given point, generate a pseudopacket,
 * and fire it thru the system.
 */
static inline int flush_to_seq(TcpSession *tcpssn, TcpTracker *st,
        uint32_t bytes, Packet *p, uint32_t pkt_flags)
{
    DebugMessage(DEBUG_STREAM_STATE, "In flush_to_seq()\n");

    if (!bytes)
    {
        DebugMessage(DEBUG_STREAM_STATE, "bailing, no data\n");
        return 0;
    }

    if (!st->seglist_next)
    {
        DebugMessage(DEBUG_STREAM_STATE, "bailing, bad seglist ptr\n");
        return 0;
    }

    if (!DataToFlush(st) && !(st->flags & TF_FORCE_FLUSH))
    {
        DebugMessage(DEBUG_STREAM_STATE, "only 1 packet in seglist no need to flush\n");
        return 0;
    }

    st->flags &= ~TF_MISSING_PKT;
    st->flags &= ~TF_MISSING_PREV_PKT;

    /* This will set this flag on the first reassembly
     * if reassembly for this direction was set midstream */
    if ( SEQ_LT(st->seglist_base_seq, st->seglist_next->seq)
            && !(st->flags & TF_FIRST_PKT_MISSING))
    {
        uint32_t missed = st->seglist_next->seq - st->seglist_base_seq;

        if (missed <= bytes)
            bytes -= missed;

        st->flags |= TF_MISSING_PREV_PKT;
        st->flags |= TF_PKT_MISSED;

        tcpStats.gaps++;
        st->seglist_base_seq = st->seglist_next->seq;

        if (!bytes)
            return 0;
    }
    st->flags &= ~TF_FIRST_PKT_MISSING;

    return _flush_to_seq(tcpssn, st, bytes, p, pkt_flags);
}

/*
 * get the footprint for the current seglist, the difference
 * between our base sequence and the last ack'd sequence we
 * received
 */
static inline uint32_t get_q_footprint(TcpTracker *st)
{
    uint32_t fp;

    if (st == nullptr)
    {
        return 0;
    }

    fp = st->r_win_base - st->seglist_base_seq;

    if (fp <= 0)
        return 0;

    st->seglist_next = st->seglist;
    return fp;
}

// FIXIT-L get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as seglist is updated
// to avoid the while loop, etc. below.
static inline uint32_t get_q_sequenced(TcpTracker *st)
{
    uint32_t len;
    TcpSegment* seg = st ? st->seglist : nullptr;
    TcpSegment* base = nullptr;

    if (!seg)
        return 0;

    if (SEQ_LT(st->r_win_base, seg->seq))
        return 0;

    while (seg->next && (seg->next->seq == seg->seq + seg->size))
    {
        if (!seg->buffered && !base)
            base = seg;
        seg = seg->next;
    }
    if (!seg->buffered && !base)
        base = seg;

    if (!base)
        return 0;

    st->seglist_next = base;
    st->seglist_base_seq = base->seq;
    len = seg->seq + seg->size - base->seq;

    return (len > 0) ? len : 0;
}

// FIXIT-L flush_stream() calls should be replaced with calls to
// CheckFlushPolicyOn*() with the exception that for the *OnAck() case,
// any available ackd data must be flushed in both directions.
int flush_stream(TcpSession *tcpssn, TcpTracker *st, Packet *p, uint32_t dir)
{
    // this is not always redundant; stream_reassemble rule option causes trouble
    if (!st->flush_policy)
        return 0;

    uint32_t bytes;

    if (Normalize_IsEnabled(NORM_TCP_IPS))
        bytes = get_q_sequenced(st);
    else
        bytes = get_q_footprint(st);

    return flush_to_seq(tcpssn, st, bytes, p, dir);
}

static void final_flush(TcpSession* tcpssn, TcpTracker& trk, Packet* p, PegCount& peg, uint32_t dir)
{
    if (!p)
    {
        p = s5_pkt;

        DAQ_PktHdr_t* const tmp_pcap_hdr = const_cast<DAQ_PktHdr_t*>(p->pkth);
        peg++;

        /* Do each field individually because of size differences on 64bit OS */
        tmp_pcap_hdr->ts.tv_sec = trk.seglist->tv.tv_sec;
        tmp_pcap_hdr->ts.tv_usec = trk.seglist->tv.tv_usec;
    }

    trk.flags |= TF_FORCE_FLUSH;

    if (flush_stream(tcpssn, &trk, p, dir))
        purge_flushed_ackd(tcpssn, &trk);

    trk.flags &= ~TF_FORCE_FLUSH;
}

// flush data on both sides as necessary
void FlushQueuedSegs(Flow* flow, TcpSession* tcpssn, bool clear, Packet* p)
{
    TcpTracker* trk = &tcpssn->client;

    // flush the client (data from server)
    bool pending = clear and paf_initialized(&trk->paf_state)
        and (!trk->splitter or trk->splitter->finish(flow));

    if ((pending and (p or trk->seglist)
                and !(flow->ssn_state.ignore_direction & SSN_DIR_FROM_SERVER)))
    {
        final_flush(tcpssn, *trk, p, tcpStats.s5tcp1, PKT_FROM_SERVER);
    }

    trk = &tcpssn->server;

    // flush the server (data from client)
    pending = clear and paf_initialized(&trk->paf_state)
        and (!trk->splitter or trk->splitter->finish(flow));

    if ((pending and (p or trk->seglist)
                and !(flow->ssn_state.ignore_direction & SSN_DIR_FROM_CLIENT)))
    {
        final_flush(tcpssn, *trk, p, tcpStats.s5tcp2, PKT_FROM_CLIENT);
    }
}

// this is for post-ack flushing
static inline uint32_t GetReverseDir(const Packet* p)
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
    if (p->packet_flags & PKT_FROM_SERVER)
        return PKT_FROM_CLIENT;

    else if (p->packet_flags & PKT_FROM_CLIENT)
        return PKT_FROM_SERVER;

    return 0;
}

static inline uint32_t GetForwardDir(const Packet* p)
{
    if (p->packet_flags & PKT_FROM_SERVER)
        return PKT_FROM_SERVER;

    else if (p->packet_flags & PKT_FROM_CLIENT)
        return PKT_FROM_CLIENT;

    return 0;
}

// see flush_pdu_ackd() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
static inline uint32_t flush_pdu_ips(TcpSession* ssn, TcpTracker* trk, uint32_t* flags)
{
    uint32_t total = 0, avail;
    TcpSegment* seg;
    PROFILE_VARS;

    MODULE_PROFILE_START(s5TcpPAFPerfStats);
    avail = get_q_sequenced(trk);
    seg = trk->seglist_next;

    // * must stop if gap (checked in paf_check)
    while (seg && *flags && (total < avail))
    {
        int32_t flush_pt;
        uint32_t size = seg->size;
        uint32_t end = seg->seq + seg->size;
        uint32_t pos = paf_position(&trk->paf_state);

        total += size;

        if (paf_initialized(&trk->paf_state) && SEQ_LEQ(end, pos))
        {
            seg = seg->next;
            continue;
        }

        flush_pt = paf_check(trk->splitter, &trk->paf_state, ssn->flow,
                seg->payload, size, total, seg->seq, flags);

        if (flush_pt >= 0)
        {
            MODULE_PROFILE_END(s5TcpPAFPerfStats);

            // see flush_pdu_ackd()
            if (!trk->splitter->is_paf() && avail > (unsigned) flush_pt)
            {
                paf_jump(&trk->paf_state, avail - (unsigned) flush_pt);
                return avail;
            }
            return flush_pt;
        }
        seg = seg->next;
    }

    MODULE_PROFILE_END(s5TcpPAFPerfStats);
    return -1;
}

static inline void fallback(TcpTracker* a)
{
    bool c2s = a->splitter->to_server();

    delete a->splitter;
    a->splitter = new AtomSplitter(c2s, a->config->paf_max);
    a->paf_state.paf = StreamSplitter::SEARCH;
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

static inline uint32_t flush_pdu_ackd(TcpSession* ssn, TcpTracker* trk,
        uint32_t* flags)
{
    uint32_t total = 0;
    TcpSegment* seg;
    PROFILE_VARS;

    MODULE_PROFILE_START(s5TcpPAFPerfStats);
    seg = SEQ_LT(trk->seglist_base_seq, trk->r_win_base) ? trk->seglist : NULL;

    // * must stop if not acked
    // * must use adjusted size of seg if not fully acked
    // * must stop if gap (checked in paf_check)
    while (seg && *flags && SEQ_LT(seg->seq, trk->r_win_base))
    {
        int32_t flush_pt;
        uint32_t size = seg->size;
        uint32_t end = seg->seq + seg->size;
        uint32_t pos = paf_position(&trk->paf_state);

        if (paf_initialized(&trk->paf_state) && SEQ_LEQ(end, pos))
        {
            total += size;
            seg = seg->next;
            continue;
        }
        if (SEQ_GT(end, trk->r_win_base))
            size = trk->r_win_base - seg->seq;

        total += size;

        flush_pt = paf_check(trk->splitter, &trk->paf_state, ssn->flow,
                seg->payload, size, total, seg->seq, flags);

        if (flush_pt >= 0)
        {
            MODULE_PROFILE_END(s5TcpPAFPerfStats);

            // for non-paf splitters, flush_pt > 0 means we reached
            // the minimum required, but we flush what is available
            // instead of creating more, but smaller, packets
            // FIXIT-L just flush to end of segment to avoid splitting
            // instead of all avail?
            if (!trk->splitter->is_paf())
            {
                // get_q_footprint() w/o side effects
                int32_t avail = (trk->r_win_base - trk->seglist_base_seq);
                if (avail > flush_pt)
                {
                    paf_jump(&trk->paf_state, avail - flush_pt);
                    return avail;
                }
            }
            return flush_pt;
        }
        seg = seg->next;
    }

    MODULE_PROFILE_END(s5TcpPAFPerfStats);
    return -1;
}
int CheckFlushPolicyOnData(TcpSession *tcpssn, TcpTracker *talker, TcpTracker *listener, Packet *p)
{
    uint32_t flushed = 0;

    DebugMessage(DEBUG_STREAM_STATE, "In CheckFlushPolicyOnData\n");
    DebugFormat(DEBUG_STREAM_STATE, "Talker flush policy: %s\n", flush_policy_names[talker->flush_policy]);
    DebugFormat(DEBUG_STREAM_STATE, "Listener flush policy: %s\n", flush_policy_names[listener->flush_policy]);

    switch (listener->flush_policy) {
        case STREAM_FLPOLICY_IGNORE:
            DebugMessage(DEBUG_STREAM_STATE, "STREAM_FLPOLICY_IGNORE\n");
            return 0;

        case STREAM_FLPOLICY_ON_ACK:
            break;

        case STREAM_FLPOLICY_ON_DATA:
            {
                uint32_t flags = GetForwardDir(p);
                int32_t flush_amt = flush_pdu_ips(tcpssn, listener, &flags);
                uint32_t this_flush;

                while (flush_amt >= 0)
                {
                    if (!flush_amt)
                        flush_amt = listener->seglist_next->seq
                            - listener->seglist_base_seq;
#if 0
                    // FIXIT-P can't do this with new HI - copy is inevitable
                    // if this payload is exactly one pdu, don't
                    // actually flush, just use the raw packet
                    if ( listener->seglist_next &&
                            (tdb->seq == listener->seglist_next->seq) &&
                            (flush_amt == listener->seglist_next->size) &&
                            (flush_amt == p->dsize) )
                    {
                        this_flush = flush_amt;
                        listener->seglist_next->buffered = SL_BUF_FLUSHED;
                        listener->flush_count++;
                        p->packet_flags |= PKT_PDU_FULL;
                        ShowRebuiltPacket(tcpssn, p);
                    }
                    else
#endif
                    {
                        this_flush = flush_to_seq(tcpssn, listener, flush_amt, p,
                                flags);
                    }
                    // if we didn't flush as expected, bail
                    // (we can flush less than max dsize)
                    if (!this_flush)
                        break;

                    flushed += this_flush;
                    flags = GetForwardDir(p);
                    flush_amt = flush_pdu_ips(tcpssn, listener, &flags);
                }
                if (!flags && listener->splitter->is_paf())
                {
                    fallback(listener);
                    return CheckFlushPolicyOnData(tcpssn, talker, listener, p);
                }
            }
            break;
    }
    return flushed;
}

int CheckFlushPolicyOnAck(TcpSession *tcpssn, TcpTracker *talker,
        TcpTracker *listener, Packet *p)
{
    uint32_t flushed = 0;

    DebugMessage(DEBUG_STREAM_STATE, "In CheckFlushPolicyOnAck\n");
    DebugFormat(DEBUG_STREAM_STATE, "Talker flush policy: %s\n", flush_policy_names[talker->flush_policy]);
    DebugFormat(DEBUG_STREAM_STATE, "Listener flush policy: %s\n", flush_policy_names[listener->flush_policy]);

    switch (talker->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        DebugMessage(DEBUG_STREAM_STATE, "STREAM_FLPOLICY_IGNORE\n");
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
        {
            uint32_t flags = GetReverseDir(p);
            int32_t flush_amt = flush_pdu_ackd(tcpssn, talker, &flags);

            while (flush_amt >= 0)
            {
                if (!flush_amt)
                    flush_amt = talker->seglist_next->seq
                        - talker->seglist_base_seq;

                talker->seglist_next = talker->seglist;
                talker->seglist_base_seq = talker->seglist->seq;

                // for consistency with other cases, should return total
                // but that breaks flushing pipelined pdus
                flushed = flush_to_seq(tcpssn, talker, flush_amt, p, flags);

                // ideally we would purge just once after this loop
                // but that throws off base
                if ( flushed and talker->seglist )
                    purge_to_seq(tcpssn, talker, talker->seglist->seq + flushed);

                // if we didn't flush as expected, bail
                // (we can flush less than max dsize)
                if (!flushed)
                    break;

                flags = GetReverseDir(p);
                flush_amt = flush_pdu_ackd(tcpssn, talker, &flags);
            }
            if (!flags && talker->splitter->is_paf())
            {
                fallback(talker);
                return CheckFlushPolicyOnAck(tcpssn, talker, listener, p);
            }
        }
        break;

    case STREAM_FLPOLICY_ON_DATA:
        purge_flushed_ackd(tcpssn, talker);
        break;
    }

    return flushed;
}


bool StreamGetReassemblyFlushPolicyTcp(Flow *flow, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!flow)
        return false;

    tcpssn = (TcpSession*) flow->session;

    if (dir & FROM_CLIENT)
    {
        return (char) tcpssn->client.flush_policy != STREAM_FLPOLICY_IGNORE;
    }

    if (dir & FROM_SERVER)
    {
        return (char) tcpssn->server.flush_policy != STREAM_FLPOLICY_IGNORE;
    }

    return false;
}

void purge_all(TcpTracker *st)
{
    DeleteSeglist(st->seglist);
    st->seglist = st->seglist_tail = st->seglist_next = nullptr;
    st->seg_count = st->flush_count = 0;
    st->seg_bytes_total = st->seg_bytes_logical = 0;
}

int StreamQueue(TcpTracker *st, Packet *p, TcpDataBlock *tdb, TcpSession *tcpssn)
{
    TcpSegment *left = NULL;
    TcpSegment *right = NULL;
    TcpSegment *dump_me = NULL;
    uint32_t seq = tdb->seq;
    uint32_t seq_end = tdb->end_seq;
    uint16_t len = p->dsize;
    int trunc = 0;
    int overlap = 0;
    int slide = 0;
    int ret = STREAM_INSERT_OK;
    char done = 0;
    char addthis = 1;
    int32_t dist_head;
    int32_t dist_tail;
    uint16_t reassembly_policy;
    // To check for retransmitted data
    const uint8_t* rdata = p->data;
    uint16_t rsize = p->dsize;
    uint32_t rseq = tdb->seq;
    PROFILE_VARS;
    DEBUG_WRAP(
            TcpSegment *lastptr = NULL;
            uint32_t base_seq = st->seglist_base_seq;
            int last = 0;
            );


    const NormMode ips_data = get_norm_ips(st);

    if (ips_data == NORM_MODE_ON)
        reassembly_policy = REASSEMBLY_POLICY_FIRST;
    else
        reassembly_policy = st->reassembly_policy;

    DebugFormat(DEBUG_STREAM_STATE, "Queuing %d bytes on stream!\nbase_seq: %X seq: %X  seq_end: %X\n",
            seq_end - seq, base_seq, seq, seq_end);

    DebugFormat(DEBUG_STREAM_STATE, "%d segments on seglist\n", SegsToFlush(st, 0));
    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");
    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");

    MODULE_PROFILE_START(s5TcpInsertPerfStats);

    // NORM fast tracks are in sequence - no norms
    if (st->seglist_tail && SegmentFastTrack(st->seglist_tail, tdb))
    {
        /* segment fit cleanly at the end of the segment list */
        left = st->seglist_tail;
        right = NULL;

        DebugFormat(DEBUG_STREAM_STATE, "Fast tracking segment! (tail_seq %X size %d)\n",
                st->seglist_tail->seq, st->seglist_tail->size);

        // BLOCK add to existing block and/or allocate new block
        ret = AddStreamNode(st, p, tdb, len, slide /* 0 */, trunc /* 0 */, seq,
                left /* tail */);

        MODULE_PROFILE_END(s5TcpInsertPerfStats);
        return ret;
    }

    if (st->seglist && st->seglist_tail)
    {
        if (SEQ_GT(tdb->seq, st->seglist->seq))
        {
            dist_head = tdb->seq - st->seglist->seq;
        } else
        {
            dist_head = st->seglist->seq - tdb->seq;
        }

        if (SEQ_GT(tdb->seq, st->seglist_tail->seq))
        {
            dist_tail = tdb->seq - st->seglist_tail->seq;
        } else
        {
            dist_tail = st->seglist_tail->seq - tdb->seq;
        }
    }
    else
    {
        dist_head = dist_tail = 0;
    }

    if (SEQ_LEQ(dist_head, dist_tail))
    {
        TcpSegment* ss;

        /* Start iterating at the head (left) */
        for (ss = st->seglist; ss; ss = ss->next)
        {
            DEBUG_WRAP(
                    DebugFormat(DEBUG_STREAM_STATE, "ss: %p  seq: 0x%X  size: %lu delta: %d\n",
                        ss, ss->seq, ss->size, (ss->seq-base_seq) - last);
                    last = ss->seq-base_seq;
                    lastptr = ss;

                    DebugFormat(DEBUG_STREAM_STATE, "   lastptr: %p ss->next: %p ss->prev: %p\n",
                        lastptr, ss->next, ss->prev);
                    );

            right = ss;

            if (SEQ_GEQ(right->seq, seq))
                break;

            left = right;
        }

        if (ss == NULL)
            right = NULL;
    }
    else
    {
        TcpSegment* ss;

        /* Start iterating at the tail (right) */
        for (ss = st->seglist_tail; ss; ss = ss->prev)
        {
            DEBUG_WRAP(
                    DebugFormat(DEBUG_STREAM_STATE, "ss: %p  seq: 0x%X  size: %lu delta: %d\n",
                        ss, ss->seq, ss->size, (ss->seq-base_seq) - last);
                    last = ss->seq-base_seq;
                    lastptr = ss;

                    DebugFormat(DEBUG_STREAM_STATE, "   lastptr: %p ss->next: %p ss->prev: %p\n",
                        lastptr, ss->next, ss->prev);
                    );

            left = ss;

            if (SEQ_LT(left->seq, seq))
                break;

            right = left;
        }

        if (ss == NULL)
            left = NULL;
    }

    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");
    DebugMessage(DEBUG_STREAM_STATE, "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n");

    DebugFormat(DEBUG_STREAM_STATE, "left: %p:0x%X  right: %p:0x%X\n", left,
            left ? left->seq : 0, right, right ? right->seq : 0);
    /*
     * handle left overlaps
     */
    if (left)
    {
        // NOTE that left->seq is always less than seq, otherwise it would
        // be a right based on the above determination of left and right

        /* check if the new segment overlaps on the left side */
        overlap = left->seq + left->size - seq;

        DebugFormat(DEBUG_STREAM_STATE, "left overlap %d\n", overlap);

        if (overlap > 0)
        {
            // NOTE that overlap will always be less than left->size since
            // seq is always greater than left->seq
            tcpStats.overlaps++;
            st->overlap_count++;

            switch (reassembly_policy)
            {
                case REASSEMBLY_POLICY_FIRST:
                case REASSEMBLY_POLICY_LINUX:
                case REASSEMBLY_POLICY_BSD:
                case REASSEMBLY_POLICY_WINDOWS:
                case REASSEMBLY_POLICY_WINDOWS2K3:
                case REASSEMBLY_POLICY_VISTA:
                case REASSEMBLY_POLICY_HPUX10:
                case REASSEMBLY_POLICY_IRIX:
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_MACOS:
                    DebugMessage(DEBUG_STREAM_STATE, "left overlap, honoring old data\n");
                    if (SEQ_LT(left->seq, tdb->seq) && SEQ_GT(left->seq + left->size, tdb->seq + p->dsize))
                    {
                        if (ips_data == NORM_MODE_ON)
                        {
                            unsigned offset = tdb->seq - left->seq;
                            memcpy((uint8_t*) p->data, left->payload + offset, p->dsize);
                            p->packet_flags |= PKT_MODIFIED;
                        }
                        normStats[PC_TCP_IPS_DATA][ips_data]++;
                        sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;
                    }
                    else if (SEQ_LT(left->seq, tdb->seq))
                    {
                        if (ips_data == NORM_MODE_ON)
                        {
                            unsigned offset = tdb->seq - left->seq;
                            unsigned length = left->seq + left->size - tdb->seq;
                            memcpy((uint8_t*) p->data, left->payload + offset, length);
                            p->packet_flags |= PKT_MODIFIED;
                        }
                        normStats[PC_TCP_IPS_DATA][ips_data]++;
                        sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;
                    }
                    seq += overlap;
                    //slide = overlap;
                    if (SEQ_LEQ(seq_end, seq))
                    {
                        /*
                         * houston, we have a problem
                         */
                        /* flag an anomaly */
                        EventBadSegment();
                        inc_tcp_discards();
                        MODULE_PROFILE_END(s5TcpInsertPerfStats);
                        return STREAM_INSERT_ANOMALY;
                    }
                    break;

                case REASSEMBLY_POLICY_SOLARIS:
                case REASSEMBLY_POLICY_HPUX11:
                    if (SEQ_LT(left->seq,
                                seq) && SEQ_GEQ(left->seq + left->size, seq + len))
                    {
                        /* New packet is entirely overlapped by an
                         * existing packet on both sides.  Drop the
                         * new data. */
                        DebugMessage(DEBUG_STREAM_STATE, "left overlap, honoring old data\n");
                        seq += overlap;
                        //slide = overlap;
                        if (SEQ_LEQ(seq_end, seq))
                        {
                            /*
                             * houston, we have a problem
                             */
                            /* flag an anomaly */
                            EventBadSegment();
                            inc_tcp_discards();
                            MODULE_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }
                    }

                    /* Otherwise, trim the old data accordingly */
                    left->size -= (int16_t) overlap;
                    st->seg_bytes_logical -= overlap;
                    DebugMessage(DEBUG_STREAM_STATE, "left overlap, honoring new data\n");
                    break;

                case REASSEMBLY_POLICY_LAST:
                    /* True "Last" policy" */
                    if (SEQ_LT(left->seq, seq) && SEQ_GT(left->seq + left->size, seq + len))
                    {
                        /* New data is overlapped on both sides by
                         * existing data.  Existing data needs to be
                         * split and the new data inserted in the
                         * middle.
                         *
                         * Need to duplicate left.  Adjust that
                         * seq by + (seq + len) and
                         * size by - (seq + len - left->seq).
                         */
                        ret = DupStreamNode(p, st, left, &right);
                        if (ret != STREAM_INSERT_OK)
                        {
                            /* No warning, its done in StreamSeglistAddNode */
                            MODULE_PROFILE_END(s5TcpInsertPerfStats);
                            return ret;
                        }
                        left->size -= (int16_t) overlap;
                        st->seg_bytes_logical -= overlap;

                        right->seq = seq + len;
                        uint16_t delta = (int16_t) (right->seq - left->seq);
                        right->size -= delta;
                        right->payload += delta;
                        st->seg_bytes_logical -= delta;
                    }
                    else
                    {
                        left->size -= (int16_t) overlap;
                        st->seg_bytes_logical -= overlap;
                    }

                    DebugMessage(DEBUG_STREAM_STATE,  "left overlap, honoring new data\n");
                    break;
            }

            if (SEQ_LEQ(seq_end, seq))
            {
                DebugMessage(DEBUG_STREAM_STATE, "seq_end < seq");
                /*
                 * houston, we have a problem
                 */
                /* flag an anomaly */
                EventBadSegment();
                inc_tcp_discards();
                MODULE_PROFILE_END(s5TcpInsertPerfStats);
                return STREAM_INSERT_ANOMALY;
            }
        }
        else
        {
            DebugMessage(DEBUG_STREAM_STATE, "No left overlap\n");
        }
    }

    //(seq_end > right->seq) && (seq_end <= (right->seq+right->size))))
    while (right && !done && SEQ_LT(right->seq, seq_end))
    {
        trunc = 0;
        overlap = (int) (seq_end - right->seq);
        //overlap = right->size - (right->seq - seq);
        //right->seq + right->size - seq_end;

        DebugFormat(DEBUG_STREAM_STATE, "right overlap(%d): len: %d right->seq: 0x%X seq: 0x%X\n",
                overlap, len, right->seq, seq);

        /* Treat sequence number overlap as a retransmission
         * Only check right side since left side happens rarely
         */
        RetransmitHandle(p, tcpssn);

        if (overlap < right->size)
        {
            if (right->is_retransmit(rdata, rsize, rseq))
            {
                // All data was retransmitted
                RetransmitProcess(p, tcpssn);
                addthis = 0;
                break;
            }

            tcpStats.overlaps++;
            st->overlap_count++;

            DebugMessage(DEBUG_STREAM_STATE, "Got partial right overlap\n");

            switch (reassembly_policy)
            {
                /* truncate existing data */
                case REASSEMBLY_POLICY_LAST:
                case REASSEMBLY_POLICY_LINUX:
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_BSD:
                case REASSEMBLY_POLICY_WINDOWS:
                case REASSEMBLY_POLICY_WINDOWS2K3:
                case REASSEMBLY_POLICY_IRIX:
                case REASSEMBLY_POLICY_HPUX10:
                case REASSEMBLY_POLICY_MACOS:
                    if (SEQ_EQ(right->seq, seq) && (reassembly_policy != REASSEMBLY_POLICY_LAST))
                    {
                        slide = (right->seq + right->size - seq);
                        seq += slide;
                    }
                    else
                    {
                        /* partial overlap */
                        right->seq += overlap;
                        right->payload += overlap;
                        right->size -= (int16_t) overlap;
                        st->seg_bytes_logical -= overlap;
                        st->total_bytes_queued -= overlap;
                    }

                    // right->size always > 0 since overlap < right->size

                    break;

                case REASSEMBLY_POLICY_FIRST:
                case REASSEMBLY_POLICY_VISTA:
                case REASSEMBLY_POLICY_SOLARIS:
                case REASSEMBLY_POLICY_HPUX11:
                    if (ips_data == NORM_MODE_ON)
                    {
                        unsigned offset = right->seq - tdb->seq;
                        unsigned length = tdb->seq + p->dsize - right->seq;
                        memcpy((uint8_t*) p->data + offset, right->payload, length);
                        p->packet_flags |= PKT_MODIFIED;
                    }
                    normStats[PC_TCP_IPS_DATA][ips_data]++;
                    sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;
                    trunc = overlap;
                    break;
            }

            /* all done, keep me out of the loop */
            done = 1;
        }
        else  // Full overlap
        {
            // Don't want to count retransmits as overlaps or do anything
            // else with them.  Account for retransmits of multiple PDUs
            // in one segment.
            if (right->is_retransmit(rdata, rsize, rseq))
            {
                rdata += right->size;
                rsize -= right->size;
                rseq += right->size;

                seq += right->size;
                left = right;
                right = right->next;

                if (rsize == 0)
                {
                    // All data was retransmitted
                    RetransmitProcess(p, tcpssn);
                    addthis = 0;
                }
                continue;
            }

            DebugMessage(DEBUG_STREAM_STATE, "Got full right overlap\n");

            tcpStats.overlaps++;
            st->overlap_count++;

            switch (reassembly_policy)
            {
                case REASSEMBLY_POLICY_BSD:
                case REASSEMBLY_POLICY_LINUX:
                case REASSEMBLY_POLICY_WINDOWS:
                case REASSEMBLY_POLICY_WINDOWS2K3:
                case REASSEMBLY_POLICY_HPUX10:
                case REASSEMBLY_POLICY_IRIX:
                case REASSEMBLY_POLICY_MACOS:
                    if (SEQ_GEQ(seq_end, right->seq + right->size) && SEQ_LT(seq, right->seq))
                    {
                        dump_me = right;

                        DebugFormat(DEBUG_STREAM_STATE, "retrans, dropping old data at seq %d, size %d\n", right->seq, right->size);
                        right = right->next;
                        StreamSeglistDeleteNode(st, dump_me);
                        break;
                    }
                    else
                    {
                        switch (reassembly_policy)
                        {
                            case REASSEMBLY_POLICY_WINDOWS:
                            case REASSEMBLY_POLICY_WINDOWS2K3:
                            case REASSEMBLY_POLICY_BSD:
                            case REASSEMBLY_POLICY_MACOS:
                                /* BSD/MacOS & Windows follow a FIRST policy in the
                                 * case below... */
                                break;
                            default:
                                /* All others follow a LAST policy */
                                if (SEQ_GT(seq_end, right->seq + right->size) && SEQ_EQ(seq, right->seq))
                                {
                                    /* When existing data is fully overlapped by new
                                     * and sequence numbers are the same, most OSs
                                     * follow a LAST policy.
                                     */
                                    goto right_overlap_last;
                                }
                                break;
                        }
                    }
                    /* Fall through */
                case REASSEMBLY_POLICY_FIRST:
                case REASSEMBLY_POLICY_VISTA:
                    DebugMessage(DEBUG_STREAM_STATE, "Got full right overlap, truncating new\n");
                    if (ips_data == NORM_MODE_ON)
                    {
                        unsigned offset = right->seq - tdb->seq;
                        memcpy((uint8_t*) p->data + offset, right->payload, right->size);
                        p->packet_flags |= PKT_MODIFIED;
                    }
                    normStats[PC_TCP_IPS_DATA][ips_data]++;
                    sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;

                    if (SEQ_EQ(right->seq, seq))
                    {
                        /* Overlap is greater than or equal to right->size
                         * slide gets set before insertion */
                        seq += right->size;
                        left = right;
                        right = right->next;

                        /* Adjusted seq is fully overlapped */
                        if (SEQ_EQ(seq, seq_end))
                        {
                            DebugFormat(DEBUG_STREAM_STATE, "StreamQueue got full right overlap with resulting seq too high, bad segment "
                                    "(seq: %X  seq_end: %X overlap: %lu\n", seq, seq_end, overlap);
                            EventBadSegment();
                            inc_tcp_discards();
                            MODULE_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }

                        /* No data to add on the left of right, so continue
                         * since some of the other non-first targets may have
                         * fallen into this case */
                        continue;
                    }

                    /* seq is less than right->seq */

                    /* trunc is reset to 0 at beginning of loop */
                    trunc = overlap;

                    /* insert this one, and see if we need to chunk it up
                       Adjust slide so that is correct relative to orig seq */
                    slide = seq - tdb->seq;
                    ret = AddStreamNode(st, p, tdb, len, slide, trunc, seq, left);
                    if (ret != STREAM_INSERT_OK)
                    {
                        /* no warning, already done above */
                        MODULE_PROFILE_END(s5TcpInsertPerfStats);
                        return ret;
                    }

                    /* Set seq to end of right since overlap was greater than
                     * or equal to right->size and inserted seq has been
                     * truncated to beginning of right
                     * And reset trunc to 0 since we may fall out of loop if
                     * next right is NULL */
                    seq = right->seq + right->size;
                    left = right;
                    right = right->next;
                    trunc = 0;

                    /* Keep looping since in IPS we may need to copy old
                     * data into packet */
                    break;

                case REASSEMBLY_POLICY_HPUX11:
                case REASSEMBLY_POLICY_SOLARIS:
                    /* If this packet is wholly overlapping and the same size
                     * as a previous one and we have not received the one
                     * immediately preceeding, we take the FIRST. */
                    if (SEQ_EQ(right->seq, seq) && (right->size == len) && (left && !SEQ_EQ(left->seq + left->size, seq)))
                    {
                        trunc += overlap;
                        if (SEQ_LEQ((int )(seq_end - trunc), seq))
                        {
                            DebugFormat(DEBUG_STREAM_STATE, "StreamQueue got full right overlap with "
                                    "resulting seq too high, bad segment (seq: %X  seq_end: %X overlap: %lu\n",
                                    seq, seq_end, overlap);
                            EventBadSegment();
                            inc_tcp_discards();
                            MODULE_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }
                        break;
                    }
                    /* Fall through */
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_LAST:
right_overlap_last:
                    DebugMessage(DEBUG_STREAM_STATE, "Got full right overlap of old, dropping old\n");
                    dump_me = right;
                    right = right->next;
                    StreamSeglistDeleteNode(st, dump_me);
                    break;
            }
        }
    }

    if (addthis)
    {
        /* Adjust slide so that is correct relative to orig seq */
        slide = seq - tdb->seq;
        ret = AddStreamNode(st, p, tdb, len, slide, trunc, seq, left);
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "Fully truncated right overlap\n");
    }

    DebugMessage(DEBUG_STREAM_STATE, "StreamQueue returning normally\n");

    MODULE_PROFILE_END(s5TcpInsertPerfStats);
    return ret;
}

