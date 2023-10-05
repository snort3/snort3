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

// segment_overlap_editor.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 11, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "segment_overlap_editor.h"

#include "detection/detection_engine.h"
#include "log/messages.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

void SegmentOverlapState::init_sos(TcpSession* ssn, StreamPolicy pol)
{
    session = ssn;
    reassembly_policy = pol;

    seglist.reset();

    seglist_base_seq = 0;
    seg_count = 0;
    seg_bytes_total = 0;
    seg_bytes_logical = 0;
    total_bytes_queued = 0;
    total_segs_queued = 0;
    overlap_count = 0;

    tsd = nullptr;
    left = nullptr;
    right = nullptr;
    rdata = nullptr;

    seq = 0;
    seq_end = 0;
    len = 0;
    overlap = 0;
    slide = 0;
    trunc_len = 0;
    rsize = 0;
    rseq = 0;
    keep_segment = true;

    tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
}

void SegmentOverlapState::init_soe(
    TcpSegmentDescriptor& tsd, TcpSegmentNode* left, TcpSegmentNode* right)
{
    this->tsd = &tsd;
    this->left = left;
    this->right = right;

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

bool SegmentOverlapEditor::is_segment_retransmit(
    TcpReassemblerState& trs, bool* full_retransmit)
{
    // Don't want to count retransmits as overlaps or do anything
    // else with them.  Account for retransmits of multiple PDUs
    // in one segment.
    bool* pb = (trs.sos.rseq == trs.sos.tsd->get_seq()) ? full_retransmit : nullptr;

    if ( trs.sos.right->is_retransmit(trs.sos.rdata, trs.sos.rsize,
        trs.sos.rseq, trs.sos.right->i_len, pb) )
    {
        trs.sos.tsd->set_retransmit_flag();

        if ( !(*full_retransmit) )
        {
            trs.sos.rdata += trs.sos.right->i_len;
            trs.sos.rsize -= trs.sos.right->i_len;
            trs.sos.rseq += trs.sos.right->i_len;
            trs.sos.seq += trs.sos.right->i_len;
            trs.sos.left = trs.sos.right;
            trs.sos.right = trs.sos.right->next;
        }
        else
            trs.sos.rsize = 0;

        if ( trs.sos.rsize == 0 )
        {
            // All data was retransmitted
            snort::DetectionEngine::disable_content(trs.sos.tsd->get_pkt());
            trs.sos.keep_segment = false;
        }

        return true;
    }

    return false;
}

void SegmentOverlapEditor::eval_left(TcpReassemblerState& trs)
{
    if ( trs.sos.left )
        insert_left_overlap(trs);
}

void SegmentOverlapEditor::eval_right(TcpReassemblerState& trs)
{
    while ( trs.sos.right && SEQ_LT(trs.sos.right->i_seq, trs.sos.seq_end) )
    {
        trs.sos.trunc_len = 0;

        assert(SEQ_LEQ(trs.sos.seq, trs.sos.right->i_seq));
        trs.sos.overlap = ( int )( trs.sos.seq_end - trs.sos.right->i_seq );

        // Treat sequence number overlap as a retransmission,
        // only check right side since left side happens rarely
        trs.sos.session->flow->call_handlers(trs.sos.tsd->get_pkt(), false);
        if ( trs.sos.overlap < trs.sos.right->i_len )
        {
            if ( trs.sos.right->is_retransmit(trs.sos.rdata, trs.sos.rsize,
                trs.sos.rseq, trs.sos.right->i_len, nullptr) )
            {
                // All data was retransmitted
                trs.sos.tsd->set_retransmit_flag();
                snort::DetectionEngine::disable_content(trs.sos.tsd->get_pkt());
                trs.sos.keep_segment = false;
            }
            else
            {
                tcpStats.overlaps++;
                trs.sos.overlap_count++;
                insert_right_overlap(trs);
            }

            break;
        }
        else  // Full overlap
        {
            bool full_retransmit = false;
            // Don't want to count retransmits as overlaps or do anything
            // else with them.  Account for retransmits of multiple PDUs
            // in one segment.
            if ( is_segment_retransmit(trs, &full_retransmit) )
            {
                if ( full_retransmit )
                    break;
                continue;
            }

            tcpStats.overlaps++;
            trs.sos.overlap_count++;
            insert_full_overlap(trs);

            if ( trs.sos.keep_segment == false )
                return;
        }
    }
}

void SegmentOverlapEditor::drop_old_segment(TcpReassemblerState& trs)
{
    TcpSegmentNode* drop_seg = trs.sos.right;
    trs.sos.right = trs.sos.right->next;
    delete_reassembly_segment(trs, drop_seg);
}

void SegmentOverlapEditor::left_overlap_keep_first(TcpReassemblerState& trs)
{
    // NOTE that overlap will always be less than left->size since
    // seq is always greater than left->seq
    assert(SEQ_GT(trs.sos.seq, trs.sos.left->i_seq));

    trs.sos.len = trs.sos.tsd->get_len();
    trs.sos.overlap = trs.sos.left->i_seq + trs.sos.left->i_len - trs.sos.seq;

    if ( trs.sos.len < trs.sos.overlap )
        trs.sos.overlap = trs.sos.len;

    if ( trs.sos.overlap > 0 )
    {
        tcpStats.overlaps++;
        trs.sos.overlap_count++;

        if ( SEQ_GT(trs.sos.left->i_seq + trs.sos.left->i_len, trs.sos.seq_end) )
        {
            if (trs.sos.tcp_ips_data == NORM_MODE_ON)
            {
                unsigned offset = trs.sos.tsd->get_seq() - trs.sos.left->i_seq;
                trs.sos.tsd->rewrite_payload(0, trs.sos.left->data + offset);
            }
            norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;
        }
        else
        {
            if ( trs.sos.tcp_ips_data == NORM_MODE_ON )
            {
                unsigned offset = trs.sos.tsd->get_seq() - trs.sos.left->i_seq;
                unsigned length =
                    trs.sos.left->i_seq + trs.sos.left->i_len - trs.sos.tsd->get_seq();
                trs.sos.tsd->rewrite_payload(0, trs.sos.left->data + offset, length);
            }

            norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;
        }

        trs.sos.seq += trs.sos.overlap;
    }
}

void SegmentOverlapEditor::left_overlap_trim_first(TcpReassemblerState& trs)
{
    assert(SEQ_GT(trs.sos.seq, trs.sos.left->i_seq));

    trs.sos.len = trs.sos.tsd->get_len();
    trs.sos.overlap = trs.sos.left->i_seq + trs.sos.left->i_len - trs.sos.seq;

    if ( trs.sos.overlap > 0 )
    {
        tcpStats.overlaps++;
        trs.sos.overlap_count++;

        if ( SEQ_GEQ(trs.sos.left->i_seq + trs.sos.left->i_len, trs.sos.seq + trs.sos.len)  )
        {
            // existing packet overlaps new on both sides.  Drop the new data.
            trs.sos.seq += trs.sos.len;
        }
        else
        {
            /* Otherwise, trim the old data accordingly */
            trs.sos.left->c_len -= ( int16_t )trs.sos.overlap;
            trs.sos.left->i_len -= ( int16_t )trs.sos.overlap;
            trs.sos.seg_bytes_logical -= trs.sos.overlap;
        }
    }
}

void SegmentOverlapEditor::left_overlap_keep_last(TcpReassemblerState& trs)
{
    assert(SEQ_GT(trs.sos.seq, trs.sos.left->i_seq));

    trs.sos.len = trs.sos.tsd->get_len();
    trs.sos.overlap = trs.sos.left->i_seq + trs.sos.left->i_len - trs.sos.seq;

    if ( trs.sos.overlap > 0 )
    {
        tcpStats.overlaps++;
        trs.sos.overlap_count++;

        /* True "Last" policy" */
        if ( SEQ_GT(trs.sos.left->i_seq + trs.sos.left->i_len, trs.sos.seq + trs.sos.len) )
        {
            /* New data is overlapped on both sides by existing data.  Existing data needs to be
             * split and the new data inserted in the middle.
             * Need to duplicate left. Adjust that seq by + (seq + len) and
             * size by - (seq + len - left->i_seq).
             */
            dup_reassembly_segment(trs, trs.sos.left, &trs.sos.right);

            trs.sos.left->c_len -= (int16_t)trs.sos.overlap;
            trs.sos.left->i_len -= (int16_t)trs.sos.overlap;

            trs.sos.right->i_seq = trs.sos.seq + trs.sos.len;
            trs.sos.right->c_seq = trs.sos.right->i_seq;
            uint16_t delta = (int16_t)(trs.sos.right->i_seq - trs.sos.left->i_seq);
            trs.sos.right->c_len -= delta;
            trs.sos.right->i_len -= delta;
            trs.sos.right->offset += delta;

            trs.sos.seg_bytes_logical -= delta;
        }
        else
        {
            trs.sos.left->c_len -= (int16_t)trs.sos.overlap;
            trs.sos.left->i_len -= (int16_t)trs.sos.overlap;
            trs.sos.seg_bytes_logical -= trs.sos.overlap;
        }
    }
}

void SegmentOverlapEditor::right_overlap_truncate_existing(TcpReassemblerState& trs)
{
    if ( SEQ_EQ(trs.sos.right->i_seq, trs.sos.seq) &&
        ( trs.sos.reassembly_policy != StreamPolicy::OS_LAST ) )
    {
        trs.sos.slide = ( trs.sos.right->i_seq + trs.sos.right->i_len - trs.sos.seq );
        trs.sos.seq += trs.sos.slide;
    }
    else
    {
        /* partial overlap */
        trs.sos.right->i_seq += trs.sos.overlap;
        trs.sos.right->c_seq = trs.sos.right->i_seq;
        trs.sos.right->offset += trs.sos.overlap;
        trs.sos.right->c_len -= (int16_t)trs.sos.overlap;
        trs.sos.right->i_len -= ( int16_t )trs.sos.overlap;
        trs.sos.seg_bytes_logical -= trs.sos.overlap;
        trs.sos.total_bytes_queued -= trs.sos.overlap;
    }
}

void SegmentOverlapEditor::right_overlap_truncate_new(TcpReassemblerState& trs)
{
    if (trs.sos.tcp_ips_data == NORM_MODE_ON)
    {
        unsigned offset = trs.sos.right->i_seq - trs.sos.tsd->get_seq();
        unsigned length =
            trs.sos.tsd->get_seq() + trs.sos.tsd->get_len() - trs.sos.right->i_seq;
        trs.sos.tsd->rewrite_payload(offset, trs.sos.right->data, length);
    }

    norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;
    trs.sos.trunc_len = trs.sos.overlap;
}

// REASSEMBLY_POLICY_FIRST:
// REASSEMBLY_POLICY_VISTA:
void SegmentOverlapEditor::full_right_overlap_truncate_new(TcpReassemblerState& trs)
{

    if ( trs.sos.tcp_ips_data == NORM_MODE_ON )
    {
        unsigned offset = trs.sos.right->i_seq - trs.sos.tsd->get_seq();

        if ( !offset && zwp_data_mismatch(trs, *trs.sos.tsd, trs.sos.right->i_len))
        {
            trs.tracker->normalizer.session_blocker(*trs.sos.tsd);
            trs.sos.keep_segment = false;
            return;
        }

        trs.sos.tsd->rewrite_payload(offset, trs.sos.right->data, trs.sos.right->i_len);
    }

    norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;

    if ( SEQ_EQ(trs.sos.right->i_seq, trs.sos.seq) )
    {
        /* Overlap is greater than or equal to right->size
         * slide gets set before insertion */
        trs.sos.seq += trs.sos.right->i_len;
        trs.sos.left = trs.sos.right;
        trs.sos.right = trs.sos.right->next;

        /* Adjusted seq is fully overlapped */
        if ( SEQ_EQ(trs.sos.seq, trs.sos.seq_end) )
            return;
    }
    else
    {
        /* seq is less than right->i_seq,  trunc length is reset to 0 at beginning of loop */
        trs.sos.trunc_len = trs.sos.overlap;

        /* insert this one, and see if we need to chunk it up
          Adjust slide so that is correct relative to orig seq */
        trs.sos.slide = trs.sos.seq - trs.sos.tsd->get_seq();
        add_reassembly_segment(trs, *trs.sos.tsd, trs.sos.len, trs.sos.slide,
            trs.sos.trunc_len, trs.sos.seq, trs.sos.left);

        // Set seq to end of right since overlap was greater than or equal to right->size and
        // inserted seq has been truncated to beginning of right and reset trunc length to 0
        // since we may fall out of loop if next right is null
        trs.sos.seq = trs.sos.right->i_seq + trs.sos.right->i_len;
        trs.sos.left = trs.sos.right;
        trs.sos.right = trs.sos.right->next;
        trs.sos.trunc_len = 0;
    }
}

// REASSEMBLY_POLICY_WINDOWS:
// REASSEMBLY_POLICY_WINDOWS2K3:
// REASSEMBLY_POLICY_BSD:
// REASSEMBLY_POLICY_MACOS:
void SegmentOverlapEditor::full_right_overlap_os1(TcpReassemblerState& trs)
{
    if ( SEQ_GEQ(trs.sos.seq_end, trs.sos.right->i_seq + trs.sos.right->i_len) and
        SEQ_LT(trs.sos.seq, trs.sos.right->i_seq) )
    {
        drop_old_segment(trs);
    }
    else
        full_right_overlap_truncate_new(trs);
}

// REASSEMBLY_POLICY_LINUX:
// REASSEMBLY_POLICY_HPUX10:
// REASSEMBLY_POLICY_IRIX:
void SegmentOverlapEditor::full_right_overlap_os2(TcpReassemblerState& trs)
{
    if ( SEQ_GEQ(trs.sos.seq_end, trs.sos.right->i_seq + trs.sos.right->i_len) and
        SEQ_LT(trs.sos.seq, trs.sos.right->i_seq) )
    {
        drop_old_segment(trs);
    }
    else if ( SEQ_GT(trs.sos.seq_end, trs.sos.right->i_seq + trs.sos.right->i_len) and
        SEQ_EQ(trs.sos.seq, trs.sos.right->i_seq) )
    {
        drop_old_segment(trs);
    }
    else
        full_right_overlap_truncate_new(trs);
}

// REASSEMBLY_POLICY_HPUX11:
// REASSEMBLY_POLICY_SOLARIS:
void SegmentOverlapEditor::full_right_overlap_os3(TcpReassemblerState& trs)
{
    // If this packet is wholly overlapping and the same size as a previous one and we have not
    // received the one immediately preceding, we take the FIRST.
    if ( SEQ_EQ(trs.sos.right->i_seq, trs.sos.seq) && (trs.sos.right->i_len == trs.sos.len)
        && (trs.sos.left && !SEQ_EQ(trs.sos.left->i_seq + trs.sos.left->i_len, trs.sos.seq)) )
    {
        right_overlap_truncate_new(trs);

        trs.sos.rdata += trs.sos.right->i_len;
        trs.sos.rsize -= trs.sos.right->i_len;
        trs.sos.rseq += trs.sos.right->i_len;
        trs.sos.seq += trs.sos.right->i_len;
        trs.sos.left = trs.sos.right;
        trs.sos.right = trs.sos.right->next;
    }
    else
        drop_old_segment(trs);
}

//  REASSEMBLY_POLICY_OLD_LINUX:
//  REASSEMBLY_POLICY_LAST:
void SegmentOverlapEditor::full_right_overlap_os4(TcpReassemblerState& trs)
{ drop_old_segment(trs); }

void SegmentOverlapEditor::full_right_overlap_os5(TcpReassemblerState& trs)
{
    full_right_overlap_truncate_new(trs);
}

bool SegmentOverlapEditor::zwp_data_mismatch(
    TcpReassemblerState& trs, TcpSegmentDescriptor& tsd, uint32_t overlap)
{
    if ( overlap == MAX_ZERO_WIN_PROBE_LEN
        and trs.sos.right->i_seq == trs.tracker->normalizer.get_zwp_seq()
        and (trs.sos.right->data[0] != tsd.get_pkt()->data[0]) )
    {
        return tsd.is_nap_policy_inline();
    }

    return false;
}

void SegmentOverlapEditor::print(TcpReassemblerState& trs)
{
    LogMessage("    seglist_base_seq:   %X\n", trs.sos.seglist_base_seq);
    LogMessage("    seglist head:       %p\n", (void*)trs.sos.seglist.head);
    LogMessage("    seglist tail:       %p\n", (void*)trs.sos.seglist.tail);
    LogMessage("    seglist current:    %p\n", (void*)trs.sos.seglist.cur_rseg);
    LogMessage("    seg_count:          %d\n", trs.sos.seg_count);
    LogMessage("    seg_bytes_total:    %d\n", trs.sos.seg_bytes_total);
    LogMessage("    seg_bytes_logical:  %d\n", trs.sos.seg_bytes_logical);
}
