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

// segment_overlap_editor.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 11, 2015

#ifndef SEGMENT_OVERLAP_EDITOR_H
#define SEGMENT_OVERLAP_EDITOR_H

#include "normalize/normalize.h"
#include "tcp_segment_node.h"

class TcpSession;
class TcpStreamTracker;

#define STREAM_INSERT_OK  0  // FIXIT-L replace with bool

struct SegmentOverlapState
{
    TcpSession* session;
    TcpSegmentDescriptor* tsd;
    TcpSegmentNode* left;
    TcpSegmentNode* right;
    const uint8_t* rdata;

    TcpSegmentList seglist;
    ReassemblyPolicy reassembly_policy;

    uint32_t seglist_base_seq;      /* seq of first queued segment */
    uint32_t seg_count;             /* number of current queued segments */
    uint32_t seg_bytes_total;       /* total bytes currently queued */
    uint32_t seg_bytes_logical;     /* logical bytes queued (total - overlaps) */
    uint32_t total_bytes_queued;    /* total bytes queued (life of session) */
    uint32_t total_segs_queued;     /* number of segments queued (life) */
    uint32_t overlap_count;         /* overlaps encountered */

    uint32_t seq;
    uint32_t seq_end;
    uint32_t rseq;

    int32_t overlap;
    int32_t slide;
    int32_t trunc_len;

    uint16_t len;
    uint16_t rsize;
    int8_t tcp_ips_data;

    bool keep_segment;

    ~SegmentOverlapState()
    {
        seglist.reset();
    }

    void init_sos(TcpSession*, ReassemblyPolicy);
    void init_soe(TcpSegmentDescriptor& tsd, TcpSegmentNode* left, TcpSegmentNode* right);
};

struct TcpReassemblerState
{
    SegmentOverlapState sos;
    TcpStreamTracker* tracker;
    uint32_t flush_count;   // number of flushed queued segments
    uint32_t xtradata_mask; // extra data available to log
    bool server_side;
    uint8_t ignore_dir;
    uint8_t packet_dir;
};

class SegmentOverlapEditor
{
protected:
    SegmentOverlapEditor() { }
    virtual ~SegmentOverlapEditor() = default;

    int eval_left(TcpReassemblerState&);
    int eval_right(TcpReassemblerState&);

    virtual bool is_segment_retransmit(TcpReassemblerState&, bool*);
    virtual void drop_old_segment(TcpReassemblerState&);

    virtual int left_overlap_keep_first(TcpReassemblerState&);
    virtual int left_overlap_trim_first(TcpReassemblerState&);
    virtual int left_overlap_keep_last(TcpReassemblerState&);
    virtual void right_overlap_truncate_existing(TcpReassemblerState&);
    virtual void right_overlap_truncate_new(TcpReassemblerState&);
    virtual int full_right_overlap_truncate_new(TcpReassemblerState&);
    virtual int full_right_overlap_os1(TcpReassemblerState&);
    virtual int full_right_overlap_os2(TcpReassemblerState&);
    virtual int full_right_overlap_os3(TcpReassemblerState&);
    virtual int full_right_overlap_os4(TcpReassemblerState&);
    virtual int full_right_overlap_os5(TcpReassemblerState&);

    virtual int insert_left_overlap(TcpReassemblerState&) = 0;
    virtual void insert_right_overlap(TcpReassemblerState&) = 0;
    virtual int insert_full_overlap(TcpReassemblerState&) = 0;

    virtual int add_reassembly_segment(
        TcpReassemblerState&, TcpSegmentDescriptor&, int16_t, uint32_t,
        uint32_t, uint32_t, TcpSegmentNode*) = 0;

    virtual int dup_reassembly_segment(TcpReassemblerState&, TcpSegmentNode*, TcpSegmentNode**) = 0;
    virtual int delete_reassembly_segment(TcpReassemblerState&, TcpSegmentNode*) = 0;
    virtual void print(TcpReassemblerState&);
};

#endif

