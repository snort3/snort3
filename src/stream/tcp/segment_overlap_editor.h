//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// segment_overlap_editor.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 11, 2015

#ifndef SEGMENT_OVERLAP_EDITOR_H
#define SEGMENT_OVERLAP_EDITOR_H

#include "tcp_defs.h"
#include "tcp_segment_node.h"
#include "tcp_session.h"

#define STREAM_INSERT_OK            0
#define STREAM_INSERT_ANOMALY       1
#define STREAM_INSERT_TIMEOUT       2
#define STREAM_INSERT_FAILED        3

class SegmentOverlapEditor
{
protected:

    SegmentOverlapEditor(void)
        : session(nullptr), reassembly_policy(ReassemblyPolicy::OS_DEFAULT), seglist_base_seq(0),
        seg_count(0), seg_bytes_total(0), seg_bytes_logical(0), total_bytes_queued(0),
        total_segs_queued(0), overlap_count(0),
        tsd(nullptr), left(nullptr), right(nullptr), seq(0), seq_end(0),
        len(0), overlap(0), slide(0), trunc_len(0), rdata(nullptr),
        rsize(0), rseq(0), keep_segment(true)
    {
        tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
    }

    virtual ~SegmentOverlapEditor(void) { }

    void init_soe(TcpSegmentDescriptor& tsd, TcpSegmentNode* left, TcpSegmentNode* right)
    {
        this->tsd = &tsd;
        this->left = left;
        this->right = right;
        seq = tsd.get_seq();
        seq_end = tsd.get_end_seq();
        len = tsd.get_data_len();
        overlap = 0;
        slide = 0;
        trunc_len = 0;
        rdata = tsd.get_pkt()->data;
        rsize = tsd.get_data_len();
        rseq = tsd.get_seq();
        keep_segment = true;
    }

    int eval_left(void);
    int eval_right(void);

    virtual bool is_segment_retransmit(void);
    virtual void drop_old_segment(void);
    virtual int generate_bad_segment_event(void);

    virtual int left_overlap_keep_first(void);
    virtual int left_overlap_trim_first(void);
    virtual int left_overlap_keep_last(void);
    virtual void right_overlap_truncate_existing(void);
    virtual void right_overlap_truncate_new(void);
    virtual int full_right_overlap_truncate_new(void);
    virtual int full_right_overlap_os1(void);
    virtual int full_right_overlap_os2(void);
    virtual int full_right_overlap_os3(void);
    virtual int full_right_overlap_os4(void);
    virtual int full_right_overlap_os5(void);

    virtual int insert_left_overlap(void) = 0;
    virtual void insert_right_overlap(void) = 0;
    virtual int insert_full_overlap(void) = 0;
    virtual int add_reassembly_segment(TcpSegmentDescriptor&, int16_t len, uint32_t slide, uint32_t
        trunc,
        uint32_t seq, TcpSegmentNode*) = 0;
    virtual int dup_reassembly_segment(Packet* p, TcpSegmentNode* left, TcpSegmentNode** retSeg) =
        0;
    virtual int delete_reassembly_segment(TcpSegmentNode* seg) = 0;

    virtual void print(void);

    TcpSession* session;
    ReassemblyPolicy reassembly_policy;
    NormMode tcp_ips_data;

    TcpSegmentList seglist;
    uint32_t seglist_base_seq; /* seq of first queued segment */
    uint32_t seg_count; /* number of current queued segments */
    uint32_t seg_bytes_total; /* total bytes currently queued */
    uint32_t seg_bytes_logical; /* logical bytes queued (total - overlaps) */
    uint32_t total_bytes_queued; /* total bytes queued (life of session) */
    uint32_t total_segs_queued; /* number of segments queued (life) */
    uint32_t overlap_count; /* overlaps encountered */

    TcpSegmentDescriptor* tsd;
    TcpSegmentNode* left;
    TcpSegmentNode* right;
    uint32_t seq;
    uint32_t seq_end;
    uint16_t len;
    int32_t overlap;
    int32_t slide;
    int32_t trunc_len;
    const uint8_t* rdata;
    uint16_t rsize;
    uint32_t rseq;
    bool keep_segment;
};

#endif

