//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_overlap_resolver.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 11, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_overlap_resolver.h"

#include "detection/detection_engine.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_segment_node.h"
#include "tcp_session.h"

using namespace snort;

TcpOverlapState::TcpOverlapState(TcpReassemblySegments& seglist)
    : seglist(seglist)
{
    tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
}

void TcpOverlapState::init(TcpSegmentDescriptor& tsd)
{
    int32_t dist_head = 0, dist_tail = 0;

    if ( seglist.head && seglist.tail )
    {
        if ( SEQ_GT(tsd.get_seq(), seglist.head->start_seq()) )
            dist_head = tsd.get_seq() - seglist.head->start_seq();
        else
            dist_head = seglist.head->start_seq() - tsd.get_seq();

        if ( SEQ_GT(tsd.get_seq(), seglist.tail->start_seq()) )
            dist_tail = tsd.get_seq() - seglist.tail->start_seq();
        else
            dist_tail = seglist.tail->start_seq() - tsd.get_seq();
    }

    left = right = nullptr;
    if ( dist_head < dist_tail )
    {
        right = seglist.head;
        while ( right and SEQ_LT(right->start_seq(), tsd.get_seq()) )
        {
            left = right;
            right = right->next;
        }
    }
    else
    {
        left = seglist.tail;
        while ( left and SEQ_GEQ(left->start_seq(), tsd.get_seq()) )
        {
            right = left;
            left = left->prev;
        }
    }

    this->tsd = &tsd;
    seq = tsd.get_seq();
    seq_end = tsd.get_end_seq();
    len = tsd.get_len();

    overlap = 0;
    slide = 0;
    trunc_len = 0;

    rdata = tsd.get_pkt()->data;
    rsize = tsd.get_len();
    rseq = tsd.get_seq();

    keep_segment = true;
}

bool TcpOverlapResolver::is_segment_retransmit(TcpOverlapState& tos, bool* full_retransmit)
{
    // Don't want to count retransmits as overlaps or do anything
    // else with them.  Account for retransmits of multiple PDUs
    // in one segment.
    bool* pb = (tos.rseq == tos.tsd->get_seq()) ? full_retransmit : nullptr;

    if ( tos.right->is_retransmit(tos.rdata, tos.rsize,
        tos.rseq, tos.right->length, pb) )
    {
        tos.tsd->set_retransmit_flag();

        if ( !(*full_retransmit) )
        {
            tos.rdata += tos.right->length;
            tos.rsize -= tos.right->length;
            tos.rseq += tos.right->length;
            tos.slide += tos.right->length;
            tos.left = tos.right;
            tos.right = tos.right->next;
        }
        else
            tos.rsize = 0;

        if ( tos.rsize == 0 )
        {
            // All data was retransmitted
            snort::DetectionEngine::disable_content(tos.tsd->get_pkt());
            tos.keep_segment = false;
        }

        return true;
    }

    return false;
}

void TcpOverlapResolver::eval_left(TcpOverlapState& tos)
{
    if ( tos.left )
        insert_left_overlap(tos);
}

void TcpOverlapResolver::eval_right(TcpOverlapState& tos)
{
    while ( tos.right && SEQ_LT(tos.right->start_seq(), tos.seq_end) )
    {
        tos.trunc_len = 0;

        assert(SEQ_LEQ(tos.slide_seq(), tos.right->start_seq()));
        tos.overlap = ( int )( tos.seq_end - tos.right->start_seq() );

        // Treat sequence number overlap as a retransmission,
        // only check right side since left side happens rarely
        tos.seglist.session->flow->call_handlers(tos.tsd->get_pkt(), false);
        if ( tos.overlap < tos.right->length )
        {
            if ( tos.right->is_retransmit(tos.rdata, tos.rsize,
                tos.rseq, tos.right->length, nullptr) )
            {
                // All data was retransmitted
                tos.tsd->set_retransmit_flag();
                snort::DetectionEngine::disable_content(tos.tsd->get_pkt());
                tos.keep_segment = false;
                tcpStats.full_retransmits++;
            }
            else
            {
                tcpStats.overlaps++;
                tos.seglist.overlap_count++;
                insert_right_overlap(tos);
            }

            break;
        }
        else  // Full overlap
        {
            bool full_retransmit = false;
            // Don't want to count retransmits as overlaps or do anything
            // else with them.  Account for retransmits of multiple PDUs
            // in one segment.
            if ( is_segment_retransmit(tos, &full_retransmit) )
            {
                if ( full_retransmit )
                {
                    tcpStats.full_retransmits++;
                    break;
                }
                continue;
            }

            tcpStats.overlaps++;
            tos.seglist.overlap_count++;
            insert_full_overlap(tos);

            if ( !tos.keep_segment )
                return;
        }
    }
}

void TcpOverlapResolver::drop_old_segment(TcpOverlapState& tos)
{
    TcpSegmentNode* drop_seg = tos.right;
    tos.right = tos.right->next;
    tos.seglist.delete_reassembly_segment(drop_seg);
}

void TcpOverlapResolver::left_overlap_keep_first(TcpOverlapState& tos)
{
    // NOTE that overlap will always be less than left->size since
    // seq is always greater than left->seq
    assert(SEQ_GT(tos.seq, tos.left->start_seq()));

    tos.overlap = tos.left->next_seq() - tos.seq;
    if ( tos.len < tos.overlap )
        tos.overlap = tos.len;

    if ( tos.overlap > 0 )
    {
        tcpStats.overlaps++;
        tos.seglist.overlap_count++;

        if ( SEQ_GT(tos.left->next_seq(), tos.seq_end) )
        {
            if (tos.tcp_ips_data == NORM_MODE_ON)
            {
            	unsigned offset = tos.tsd->get_seq() - tos.left->start_seq();
                tos.tsd->rewrite_payload(0, tos.left->payload() + offset);
            }
            norm_stats[PC_TCP_IPS_DATA][tos.tcp_ips_data]++;
        }
        else
        {
            if ( tos.tcp_ips_data == NORM_MODE_ON )
            {
                unsigned offset = tos.tsd->get_seq() - tos.left->start_seq();
                unsigned length = tos.left->next_seq() - tos.tsd->get_seq();
                tos.tsd->rewrite_payload(0, tos.left->payload() + offset, length);
            }

            norm_stats[PC_TCP_IPS_DATA][tos.tcp_ips_data]++;
        }

        tos.slide = tos.overlap;
    }
}

void TcpOverlapResolver::left_overlap_trim_first(TcpOverlapState& tos)
{
    assert(SEQ_GT(tos.seq, tos.left->start_seq()));

    tos.overlap =  tos.left->next_seq() - tos.seq;
    if ( tos.overlap > 0 )
    {
        tcpStats.overlaps++;
        tos.seglist.overlap_count++;

        if ( SEQ_GEQ(tos.left->next_seq(), tos.seq + tos.len)  )
        {
            // existing packet overlaps new on both sides.  Drop the new data.
            tos.slide += tos.len;
        }
        else
        {
            /* Otherwise, trim the old data accordingly */
            tos.left->length -= ( int16_t )tos.overlap;
            tos.seglist.seg_bytes_logical -= tos.overlap;
        }
    }
}

void TcpOverlapResolver::left_overlap_keep_last(TcpOverlapState& tos)
{
    assert(SEQ_GT(tos.seq, tos.left->seq));

    tos.overlap = tos.left->next_seq() - tos.seq;
    if ( tos.overlap > 0 )
    {
        tcpStats.overlaps++;
        tos.seglist.overlap_count++;

        /* True "Last" policy" */
        if (SEQ_GT(tos.left->next_seq(), tos.seq + tos.len) )
        {
            /* New data is overlapped on both sides by existing data.  Existing data needs to be
             * split and the new data inserted in the middle.
             * Need to duplicate left. Adjust that seq by + (seq + len) and
             * size by - (seq + len - left->start_seq()).
             */
            tos.seglist.dup_reassembly_segment(tos.left, &tos.right);

            tos.left->length -= tos.overlap;
            uint16_t delta = tos.seq_end - tos.left->start_seq();
            tos.right->length -= delta;
            tos.right->offset += delta;
            tos.seglist.seg_bytes_logical -= tos.len;
        }
        else
        {
            tos.left->length -= (int16_t)tos.overlap;
            tos.seglist.seg_bytes_logical -= tos.overlap;
        }
    }
}

void TcpOverlapResolver::right_overlap_truncate_existing(TcpOverlapState& tos)
{
    if ( SEQ_EQ(tos.right->start_seq(), tos.slide_seq()) )
    {
        tos.slide += tos.overlap;
    }
    else
    {
        /* partial overlap */
        tos.right->offset += tos.overlap;
        tos.right->length -= ( int16_t )tos.overlap;
        tos.seglist.seg_bytes_logical -= tos.overlap;
    }
}

void TcpOverlapResolver::right_overlap_truncate_new(TcpOverlapState& tos)
{
    if (tos.tcp_ips_data == NORM_MODE_ON)
    {
        unsigned offset = tos.right->start_seq() - tos.tsd->get_seq();
        unsigned length = tos.tsd->get_seq() + tos.tsd->get_len() - tos.right->start_seq();
        tos.tsd->rewrite_payload(offset, tos.right->payload(), length);
    }

    norm_stats[PC_TCP_IPS_DATA][tos.tcp_ips_data]++;
    tos.trunc_len = tos.overlap;
}

// REASSEMBLY_POLICY_FIRST:
// REASSEMBLY_POLICY_VISTA:
void TcpOverlapResolver::full_right_overlap_truncate_new(TcpOverlapState& tos)
{

    if ( tos.tcp_ips_data == NORM_MODE_ON )
    {
        unsigned offset = tos.right->start_seq() - tos.tsd->get_seq();
        if ( !offset && zwp_data_mismatch(tos, *tos.tsd, tos.right->length))
        {
            tos.seglist.tracker->normalizer.session_blocker(*tos.tsd);
            tos.keep_segment = false;
            return;
        }

        tos.tsd->rewrite_payload(offset, tos.right->payload(), tos.right->length);
    }

    norm_stats[PC_TCP_IPS_DATA][tos.tcp_ips_data]++;

    if ( SEQ_EQ(tos.right->start_seq(), tos.slide_seq()) )
    {
        // Overlap is greater than or equal to right->size slide gets set before insertion
        tos.slide += tos.right->length;
        tos.left = tos.right;
        tos.right = tos.right->next;
    }
    else
    {
        // seq is less than right->start_seq(),  set trunc length and slide
        //  and insert chunk before current right segment...
        tos.trunc_len = tos.overlap;
        tos.seglist.add_reassembly_segment(*tos.tsd, tos.len, tos.slide,
            tos.trunc_len, tos.seq, tos.left);

        // adjust slide and trunc_len and move to next node to the right...
        tos.slide += tos.right->next_seq() - tos.slide_seq();
        tos.trunc_len = 0;
        tos.left = tos.right;
        tos.right = tos.right->next;
    }
}

// REASSEMBLY_POLICY_WINDOWS:
// REASSEMBLY_POLICY_WINDOWS2K3:
// REASSEMBLY_POLICY_BSD:
// REASSEMBLY_POLICY_MACOS:
void TcpOverlapResolver::full_right_overlap_os1(TcpOverlapState& tos)
{
    if ( SEQ_GEQ(tos.seq_end, tos.right->next_seq()) and
        SEQ_LT(tos.slide_seq(), tos.right->start_seq()) )
    {
        drop_old_segment(tos);
    }
    else
        full_right_overlap_truncate_new(tos);
}

// REASSEMBLY_POLICY_LINUX:
// REASSEMBLY_POLICY_HPUX10:
// REASSEMBLY_POLICY_IRIX:
void TcpOverlapResolver::full_right_overlap_os2(TcpOverlapState& tos)
{
    if ( SEQ_GEQ(tos.seq_end, tos.right->next_seq()) and
        SEQ_LT(tos.slide_seq(), tos.right->start_seq()) )
    {
        drop_old_segment(tos);
    }
    else if ( SEQ_GT(tos.seq_end, tos.right->next_seq()) and
        SEQ_EQ(tos.slide_seq(), tos.right->start_seq()) )
    {
        drop_old_segment(tos);
    }
    else
        full_right_overlap_truncate_new(tos);
}

// REASSEMBLY_POLICY_HPUX11:
// REASSEMBLY_POLICY_SOLARIS:
void TcpOverlapResolver::full_right_overlap_os3(TcpOverlapState& tos)
{
    // If this packet is wholly overlapping and the same size as a previous one and we have not
    // received the one immediately preceding, we take the FIRST.
    if ( SEQ_EQ(tos.right->start_seq(), tos.seq) && (tos.right->length == tos.len)
        && (tos.left && !SEQ_EQ(tos.left->next_seq(), tos.seq)) )
    {
        right_overlap_truncate_new(tos);

        tos.rdata += tos.right->length;
        tos.rsize -= tos.right->length;
        tos.rseq += tos.right->length;
        tos.left = tos.right;
        tos.right = tos.right->next;
    }
    else
        drop_old_segment(tos);
}

//  REASSEMBLY_POLICY_OLD_LINUX:
//  REASSEMBLY_POLICY_LAST:
void TcpOverlapResolver::full_right_overlap_os4(TcpOverlapState& tos)
{ drop_old_segment(tos); }

void TcpOverlapResolver::full_right_overlap_os5(TcpOverlapState& tos)
{
    full_right_overlap_truncate_new(tos);
}

bool TcpOverlapResolver::zwp_data_mismatch(TcpOverlapState& tos, TcpSegmentDescriptor& tsd, uint32_t overlap)
{
    if ( overlap == MAX_ZERO_WIN_PROBE_LEN
        and tos.right->start_seq() == tos.seglist.tracker->normalizer.get_zwp_seq()
        and (tos.right->data[0] != tsd.get_pkt()->data[0]) )
    {
        return tsd.is_nap_policy_inline();
    }

    return false;
}

class TcpOverlapResolverFirst : public TcpOverlapResolver
{
public:
    TcpOverlapResolverFirst()
    { overlap_policy = StreamPolicy::OS_FIRST; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_new(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os5(tos); }
};

class TcpOverlapResolverLast : public TcpOverlapResolver
{
public:
    TcpOverlapResolverLast()
    { overlap_policy = StreamPolicy::OS_LAST; }

private:
    void right_overlap_truncate_existing(TcpOverlapState& tos) override
     {
         tos.right->offset += tos.overlap;
         tos.right->length -= ( int16_t )tos.overlap;
         tos.seglist.seg_bytes_logical -= tos.overlap;
     }

    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_last(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os4(tos); }
};

class TcpOverlapResolverLinux : public TcpOverlapResolver
{
public:
    TcpOverlapResolverLinux()
    { overlap_policy = StreamPolicy::OS_LINUX; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os2(tos); }
};

class TcpOverlapResolverOldLinux : public TcpOverlapResolver
{
public:
    TcpOverlapResolverOldLinux()
    { overlap_policy = StreamPolicy::OS_OLD_LINUX; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os4(tos); }
};

class TcpOverlapResolverBSD : public TcpOverlapResolver
{
public:
    TcpOverlapResolverBSD()
    { overlap_policy = StreamPolicy::OS_BSD; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os1(tos); }
};

class TcpOverlapResolverMacOS : public TcpOverlapResolver
{
public:
    TcpOverlapResolverMacOS()
    { overlap_policy = StreamPolicy::OS_MACOS; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os1(tos); }
};

class TcpOverlapResolverSolaris : public TcpOverlapResolver
{
public:
    TcpOverlapResolverSolaris()
    { overlap_policy = StreamPolicy::OS_SOLARIS; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_trim_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_new(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os3(tos); }
};

class TcpOverlapResolverIrix : public TcpOverlapResolver
{
public:
    TcpOverlapResolverIrix()
    { overlap_policy = StreamPolicy::OS_IRIX; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos);  }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os2(tos); }
};

class TcpOverlapResolverHpux11 : public TcpOverlapResolver
{
public:
    TcpOverlapResolverHpux11()
    { overlap_policy = StreamPolicy::OS_HPUX11; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_trim_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_new(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os3(tos); }
};

class TcpOverlapResolverHpux10 : public TcpOverlapResolver
{
public:
    TcpOverlapResolverHpux10()
    { overlap_policy = StreamPolicy::OS_HPUX10; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os2(tos); }
};

class TcpOverlapResolverWindows : public TcpOverlapResolver
{
public:
    TcpOverlapResolverWindows()
    { overlap_policy = StreamPolicy::OS_WINDOWS; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os1(tos); }
};

class TcpOverlapResolverWindows2K3 : public TcpOverlapResolver
{
public:
    TcpOverlapResolverWindows2K3()
    { overlap_policy = StreamPolicy::OS_WINDOWS2K3; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_existing(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os1(tos); }
};

class TcpOverlapResolverVista : public TcpOverlapResolver
{
public:
    TcpOverlapResolverVista()
    { overlap_policy = StreamPolicy::OS_VISTA; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_new(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os5 (tos); }
};

class TcpOverlapResolverProxy : public TcpOverlapResolverFirst
{
public:
    TcpOverlapResolverProxy()
    { overlap_policy = StreamPolicy::OS_PROXY; }

private:
    void insert_left_overlap(TcpOverlapState& tos) override
    { left_overlap_keep_first(tos); }

    void insert_right_overlap(TcpOverlapState& tos) override
    { right_overlap_truncate_new(tos); }

    void insert_full_overlap(TcpOverlapState& tos) override
    { full_right_overlap_os5(tos); }
};

TcpOverlapResolver* TcpOverlapResolverFactory::overlap_resolvers[StreamPolicy::OS_END_OF_LIST];

void TcpOverlapResolverFactory::initialize()
{
    overlap_resolvers[StreamPolicy::OS_FIRST] = new TcpOverlapResolverFirst;
    overlap_resolvers[StreamPolicy::OS_LAST] = new TcpOverlapResolverLast;
    overlap_resolvers[StreamPolicy::OS_LINUX] = new TcpOverlapResolverLinux;
    overlap_resolvers[StreamPolicy::OS_OLD_LINUX] = new TcpOverlapResolverOldLinux;
    overlap_resolvers[StreamPolicy::OS_BSD] = new TcpOverlapResolverBSD;
    overlap_resolvers[StreamPolicy::OS_MACOS] = new TcpOverlapResolverMacOS;
    overlap_resolvers[StreamPolicy::OS_SOLARIS] = new TcpOverlapResolverSolaris;
    overlap_resolvers[StreamPolicy::OS_IRIX] = new TcpOverlapResolverIrix;
    overlap_resolvers[StreamPolicy::OS_HPUX11] = new TcpOverlapResolverHpux11;
    overlap_resolvers[StreamPolicy::OS_HPUX10] = new TcpOverlapResolverHpux10;
    overlap_resolvers[StreamPolicy::OS_WINDOWS] = new TcpOverlapResolverWindows;
    overlap_resolvers[StreamPolicy::OS_WINDOWS2K3] = new TcpOverlapResolverWindows2K3;
    overlap_resolvers[StreamPolicy::OS_VISTA] = new TcpOverlapResolverVista;
    overlap_resolvers[StreamPolicy::OS_PROXY] = new TcpOverlapResolverProxy;
}

void TcpOverlapResolverFactory::term()
{
    for ( auto sp = StreamPolicy::OS_FIRST; sp <= StreamPolicy::OS_PROXY; sp++ )
        delete overlap_resolvers[sp];
}

TcpOverlapResolver* TcpOverlapResolverFactory::get_instance(StreamPolicy os_policy)
{
    NormMode tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
    StreamPolicy sp = (tcp_ips_data == NORM_MODE_ON) ? StreamPolicy::OS_FIRST : os_policy;

    assert( sp <= StreamPolicy::OS_PROXY );
    return overlap_resolvers[sp];
}
