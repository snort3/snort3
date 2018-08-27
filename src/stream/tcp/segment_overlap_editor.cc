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

// segment_overlap_editor.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 11, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "segment_overlap_editor.h"

#include "log/messages.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_session.h"

void SegmentOverlapState::init_sos(TcpSession* ssn, ReassemblyPolicy pol)
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

    seq = tsd.get_seg_seq();
    seq_end = tsd.get_end_seq();
    len = tsd.get_seg_len();

    overlap = 0;
    slide = 0;
    trunc_len = 0;

    rdata = tsd.get_pkt()->data;
    rsize = tsd.get_seg_len();
    rseq = tsd.get_seg_seq();

    keep_segment = true;
}

bool SegmentOverlapEditor::is_segment_retransmit(
    TcpReassemblerState& trs, bool* full_retransmit)
{
    // Don't want to count retransmits as overlaps or do anything
    // else with them.  Account for retransmits of multiple PDUs
    // in one segment.
    bool* pb = (trs.sos.rseq == trs.sos.tsd->get_seg_seq()) ? full_retransmit : nullptr;

    if ( trs.sos.right->is_retransmit(
        trs.sos.rdata, trs.sos.rsize, trs.sos.rseq, trs.sos.right->i_len, pb) )
    {
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
            trs.sos.session->retransmit_process(trs.sos.tsd->get_pkt());
            trs.sos.keep_segment = false;
        }

        return true;
    }

    return false;
}

int SegmentOverlapEditor::eval_left(TcpReassemblerState& trs)
{
    int rc = STREAM_INSERT_OK;

    if ( trs.sos.left )
        rc = insert_left_overlap(trs);

    return rc;
}

int SegmentOverlapEditor::eval_right(TcpReassemblerState& trs)
{
    while ( trs.sos.right && SEQ_LT(trs.sos.right->i_seq, trs.sos.seq_end) )
    {
        trs.sos.trunc_len = 0;

        assert(SEQ_LEQ(trs.sos.seq, trs.sos.right->i_seq));
        trs.sos.overlap = ( int )( trs.sos.seq_end - trs.sos.right->i_seq );

        // Treat sequence number overlap as a retransmission, only check right side since
        //  left side happens rarely
        trs.sos.session->retransmit_handle(trs.sos.tsd->get_pkt());

        if ( trs.sos.overlap < trs.sos.right->i_len )
        {
            if ( trs.sos.right->is_retransmit(
                trs.sos.rdata, trs.sos.rsize, trs.sos.rseq, trs.sos.right->i_len, nullptr) )
            {
                // All data was retransmitted
                trs.sos.session->retransmit_process(trs.sos.tsd->get_pkt());
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
            int rc = insert_full_overlap(trs);
            if ( rc != STREAM_INSERT_OK )
                return rc;
        }
    }

    return STREAM_INSERT_OK;
}

void SegmentOverlapEditor::drop_old_segment(TcpReassemblerState& trs)
{
    TcpSegmentNode* drop_seg = trs.sos.right;
    trs.sos.right = trs.sos.right->next;
    delete_reassembly_segment(trs, drop_seg);
}

int SegmentOverlapEditor::left_overlap_keep_first(TcpReassemblerState& trs)
{
    // NOTE that overlap will always be less than left->size since
    // seq is always greater than left->seq
    assert(SEQ_GT(trs.sos.seq, trs.sos.left->i_seq));

    trs.sos.len = trs.sos.tsd->get_seg_len();
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
                unsigned offset = trs.sos.tsd->get_seg_seq() - trs.sos.left->i_seq;
                memcpy(const_cast<uint8_t*>(trs.sos.tsd->get_pkt()->data),
                    trs.sos.left->data + offset, trs.sos.tsd->get_seg_len());
                trs.sos.tsd->get_pkt()->packet_flags |= PKT_MODIFIED;
            }
            tcp_norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;
        }
        else
        {
            if ( trs.sos.tcp_ips_data == NORM_MODE_ON )
            {
                unsigned offset = trs.sos.tsd->get_seg_seq() - trs.sos.left->i_seq;
                unsigned length = trs.sos.left->i_seq + trs.sos.left->i_len -
                    trs.sos.tsd->get_seg_seq();
                memcpy(const_cast<uint8_t*>(trs.sos.tsd->get_pkt()->data),
                    trs.sos.left->data + offset, length);
                trs.sos.tsd->get_pkt()->packet_flags |= PKT_MODIFIED;
            }

            tcp_norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;
        }

        trs.sos.seq += trs.sos.overlap;
    }

    return STREAM_INSERT_OK;
}

int SegmentOverlapEditor::left_overlap_trim_first(TcpReassemblerState& trs)
{
    assert(SEQ_GT(trs.sos.seq, trs.sos.left->i_seq));

    trs.sos.len = trs.sos.tsd->get_seg_len();
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

    return STREAM_INSERT_OK;
}

int SegmentOverlapEditor::left_overlap_keep_last(TcpReassemblerState& trs)
{
    assert(SEQ_GT(trs.sos.seq, trs.sos.left->i_seq));

    trs.sos.len = trs.sos.tsd->get_seg_len();
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
            int rc = dup_reassembly_segment(trs, trs.sos.left, &trs.sos.right);

            if ( rc != STREAM_INSERT_OK )
                return rc;

            trs.sos.left->c_len -= ( int16_t )trs.sos.overlap;
            trs.sos.left->i_len -= ( int16_t )trs.sos.overlap;

            trs.sos.right->i_seq = trs.sos.seq + trs.sos.len;
            trs.sos.right->c_seq = trs.sos.right->i_seq;
            uint16_t delta = ( int16_t )( trs.sos.right->i_seq - trs.sos.left->i_seq );
            trs.sos.right->c_len -= delta;
            trs.sos.right->i_len -= delta;
            trs.sos.right->offset += delta;

            trs.sos.seg_bytes_logical -= delta;
        }
        else
        {
            trs.sos.left->c_len -= (int16_t)trs.sos.overlap;
            trs.sos.left->i_len -= ( int16_t )trs.sos.overlap;
            trs.sos.seg_bytes_logical -= trs.sos.overlap;
        }
    }

    return STREAM_INSERT_OK;
}

void SegmentOverlapEditor::right_overlap_truncate_existing(TcpReassemblerState& trs)
{
    if ( SEQ_EQ(trs.sos.right->i_seq, trs.sos.seq) &&
        ( trs.sos.reassembly_policy != ReassemblyPolicy::OS_LAST ) )
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
        unsigned offset = trs.sos.right->i_seq - trs.sos.tsd->get_seg_seq();
        unsigned length = trs.sos.tsd->get_seg_seq() + trs.sos.tsd->get_seg_len() -
            trs.sos.right->i_seq;
        memcpy(const_cast<uint8_t*>(trs.sos.tsd->get_pkt()->data) + offset,
            trs.sos.right->data, length);
        trs.sos.tsd->get_pkt()->packet_flags |= PKT_MODIFIED;
    }

    tcp_norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;
    trs.sos.trunc_len = trs.sos.overlap;
}

// REASSEMBLY_POLICY_FIRST:
// REASSEMBLY_POLICY_VISTA:
int SegmentOverlapEditor::full_right_overlap_truncate_new(TcpReassemblerState& trs)
{
    if ( trs.sos.tcp_ips_data == NORM_MODE_ON )
    {
        unsigned offset = trs.sos.right->i_seq - trs.sos.tsd->get_seg_seq();
        memcpy(const_cast<uint8_t*>(trs.sos.tsd->get_pkt()->data) + offset,
            trs.sos.right->data, trs.sos.right->i_len);
        trs.sos.tsd->get_pkt()->packet_flags |= PKT_MODIFIED;
    }

    tcp_norm_stats[PC_TCP_IPS_DATA][trs.sos.tcp_ips_data]++;

    if ( SEQ_EQ(trs.sos.right->i_seq, trs.sos.seq) )
    {
        /* Overlap is greater than or equal to right->size
         * slide gets set before insertion */
        trs.sos.seq += trs.sos.right->i_len;
        trs.sos.left = trs.sos.right;
        trs.sos.right = trs.sos.right->next;

        /* Adjusted seq is fully overlapped */
        if ( SEQ_EQ(trs.sos.seq, trs.sos.seq_end) )
            return STREAM_INSERT_OK;
    }
    else
    {
        /* seq is less than right->i_seq,  trunc length is reset to 0 at beginning of loop */
        trs.sos.trunc_len = trs.sos.overlap;

        /* insert this one, and see if we need to chunk it up
          Adjust slide so that is correct relative to orig seq */
        trs.sos.slide = trs.sos.seq - trs.sos.tsd->get_seg_seq();
        int rc = add_reassembly_segment(trs, *trs.sos.tsd, trs.sos.len, trs.sos.slide,
            trs.sos.trunc_len, trs.sos.seq, trs.sos.left);
        if ( rc != STREAM_INSERT_OK )
            return rc;

        // Set seq to end of right since overlap was greater than or equal to right->size and
        // inserted seq has been truncated to beginning of right and reset trunc length to 0
        // since we may fall out of loop if next right is NULL
        trs.sos.seq = trs.sos.right->i_seq + trs.sos.right->i_len;
        trs.sos.left = trs.sos.right;
        trs.sos.right = trs.sos.right->next;
        trs.sos.trunc_len = 0;
    }

    return STREAM_INSERT_OK;
}

// REASSEMBLY_POLICY_WINDOWS:
// REASSEMBLY_POLICY_WINDOWS2K3:
// REASSEMBLY_POLICY_BSD:
// REASSEMBLY_POLICY_MACOS:
int SegmentOverlapEditor::full_right_overlap_os1(TcpReassemblerState& trs)
{
    if ( SEQ_GEQ(trs.sos.seq_end, trs.sos.right->i_seq + trs.sos.right->i_len) and
        SEQ_LT(trs.sos.seq, trs.sos.right->i_seq) )
    {
        drop_old_segment(trs);
    }
    else
    {
        int rc = full_right_overlap_truncate_new(trs);
        if ( rc != STREAM_INSERT_OK )
            return rc;
    }

    return STREAM_INSERT_OK;
}

// REASSEMBLY_POLICY_LINUX:
// REASSEMBLY_POLICY_HPUX10:
// REASSEMBLY_POLICY_IRIX:
int SegmentOverlapEditor::full_right_overlap_os2(TcpReassemblerState& trs)
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
    {
        int rc = full_right_overlap_truncate_new(trs);
        if ( rc != STREAM_INSERT_OK )
            return rc;
    }

    return STREAM_INSERT_OK;
}

// REASSEMBLY_POLICY_HPUX11:
// REASSEMBLY_POLICY_SOLARIS:
int SegmentOverlapEditor::full_right_overlap_os3(TcpReassemblerState& trs)
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
    {
        drop_old_segment(trs);
    }

    return STREAM_INSERT_OK;
}

//  REASSEMBLY_POLICY_OLD_LINUX:
//  REASSEMBLY_POLICY_LAST:
int SegmentOverlapEditor::full_right_overlap_os4(TcpReassemblerState& trs)
{
    drop_old_segment(trs);
    return STREAM_INSERT_OK;
}

int SegmentOverlapEditor::full_right_overlap_os5(TcpReassemblerState& trs)
{
    return full_right_overlap_truncate_new(trs);
}

void SegmentOverlapEditor::print(TcpReassemblerState& trs)
{
    snort::LogMessage("    seglist_base_seq:   %X\n", trs.sos.seglist_base_seq);
    snort::LogMessage("    seglist head:       %p\n", (void*)trs.sos.seglist.head);
    snort::LogMessage("    seglist tail:       %p\n", (void*)trs.sos.seglist.tail);
    snort::LogMessage("    seglist current:    %p\n", (void*)trs.sos.seglist.cur_rseg);
    snort::LogMessage("    seg_count:          %d\n", trs.sos.seg_count);
    snort::LogMessage("    seg_bytes_total:    %d\n", trs.sos.seg_bytes_total);
    snort::LogMessage("    seg_bytes_logical:  %d\n", trs.sos.seg_bytes_logical);
}

