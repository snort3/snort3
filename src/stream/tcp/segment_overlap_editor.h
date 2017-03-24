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

// segment_overlap_editor.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 11, 2015

#ifndef SEGMENT_OVERLAP_EDITOR_H
#define SEGMENT_OVERLAP_EDITOR_H

#include "normalize/normalize.h"
#include "stream/tcp/tcp_segment_node.h"

class TcpSession;

#define STREAM_INSERT_OK  0  // FIXIT-L replace with bool

class SegmentOverlapEditor
{
protected:

    SegmentOverlapEditor()
    {
        tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
    }

    virtual ~SegmentOverlapEditor() { }

    void init_soe(TcpSegmentDescriptor& tsd, TcpSegmentNode* left, TcpSegmentNode* right)
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

    int eval_left();
    int eval_right();

    virtual bool is_segment_retransmit(bool*);
    virtual void drop_old_segment();

    virtual int left_overlap_keep_first();
    virtual int left_overlap_trim_first();
    virtual int left_overlap_keep_last();
    virtual void right_overlap_truncate_existing();
    virtual void right_overlap_truncate_new();
    virtual int full_right_overlap_truncate_new();
    virtual int full_right_overlap_os1();
    virtual int full_right_overlap_os2();
    virtual int full_right_overlap_os3();
    virtual int full_right_overlap_os4();
    virtual int full_right_overlap_os5();

    virtual int insert_left_overlap() = 0;
    virtual void insert_right_overlap() = 0;
    virtual int insert_full_overlap() = 0;
    virtual int add_reassembly_segment(TcpSegmentDescriptor&, int16_t, uint32_t, uint32_t,
        uint32_t, TcpSegmentNode*) = 0;
    virtual int dup_reassembly_segment(TcpSegmentNode*, TcpSegmentNode**) = 0;
    virtual int delete_reassembly_segment(TcpSegmentNode*) = 0;
    virtual void print();

    TcpSession* session = nullptr;
    ReassemblyPolicy reassembly_policy = ReassemblyPolicy::OS_DEFAULT;
    NormMode tcp_ips_data;

    TcpSegmentList seglist;
    uint32_t seglist_base_seq = 0;      /* seq of first queued segment */
    uint32_t seg_count = 0;             /* number of current queued segments */
    uint32_t seg_bytes_total = 0;       /* total bytes currently queued */
    uint32_t seg_bytes_logical = 0;     /* logical bytes queued (total - overlaps) */
    uint32_t total_bytes_queued = 0;    /* total bytes queued (life of session) */
    uint32_t total_segs_queued = 0;     /* number of segments queued (life) */
    uint32_t overlap_count = 0;         /* overlaps encountered */

    TcpSegmentDescriptor* tsd = nullptr;
    TcpSegmentNode* left = nullptr;
    TcpSegmentNode* right = nullptr;
    const uint8_t* rdata = nullptr;
    uint32_t seq = 0;
    uint32_t seq_end = 0;
    uint16_t len = 0;
    int32_t overlap = 0;
    int32_t slide = 0;
    int32_t trunc_len = 0;
    uint16_t rsize = 0;
    uint32_t rseq = 0;
    bool keep_segment = true;
};

#endif

