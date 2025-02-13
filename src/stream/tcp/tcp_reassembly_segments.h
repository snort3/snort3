//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembly_segments.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 9, 2015

#ifndef TCP_REASSEMBLERS_H
#define TCP_REASSEMBLERS_H

#include <cstdint>

#include "tcp_defs.h"

#include "tcp_segment_node.h"

class TcpOverlapResolver;
class TcpOverlapState;
class TcpSegmentDescriptor;
class TcpSession;
class TcpStreamTracker;

class TcpReassemblySegments
{
public:
    TcpReassemblySegments() = default;
    ~TcpReassemblySegments();

    void init(TcpSession* ssn, TcpStreamTracker* trk, StreamPolicy pol);
    void reset();

    void update_next(TcpSegmentNode*);
    bool segment_within_seglist_window(TcpSegmentDescriptor&);
    void queue_reassembly_segment(TcpSegmentDescriptor&);
    void add_reassembly_segment(TcpSegmentDescriptor&, uint16_t, uint32_t,
        uint32_t, uint32_t, TcpSegmentNode*);
    void dup_reassembly_segment(TcpSegmentNode*, TcpSegmentNode**);
    int delete_reassembly_segment(TcpSegmentNode*);
    void advance_rcv_nxt(TcpSegmentNode *tsn = nullptr);
    void purge_flushed_segments(uint32_t flush_seq);
    void skip_holes();
    void skip_midstream_pickup_seglist_hole(TcpSegmentDescriptor&);
    bool skip_hole_at_beginning(TcpSegmentNode*);
    void purge_segment_list();

    bool is_segment_pending_flush() const;

    void set_seglist_base_seq(uint32_t base_seq)
    { seglist_base_seq = base_seq; }

    uint32_t get_seglist_base_seq() const
    { return seglist_base_seq; }

    bool data_was_queued() const
    { return total_bytes_queued > 0; }

    uint32_t get_seg_count() const
    { return seg_count; }

    uint32_t get_seg_bytes_total() const
    { return seg_bytes_total; }

    uint32_t get_overlap_count() const
    { return overlap_count; }

    void set_overlap_count(uint32_t count)
    { overlap_count = count;  }

    uint32_t get_flush_count() const
    { return flush_count; }

    uint32_t get_seg_bytes_logical() const
    { return seg_bytes_logical; }

private:
    void insert_segment_data(TcpSegmentNode* prev, TcpSegmentNode*);
    void purge_segments_left_of_hole(const TcpSegmentNode*);

    void insert(TcpSegmentNode* prev, TcpSegmentNode* ss)
    {
        if ( prev )
        {
            ss->next = prev->next;
            ss->prev = prev;
            prev->next = ss;

            if ( ss->next )
                ss->next->prev = ss;
            else
                tail = ss;
        }
        else
        {
            ss->next = head;

            if ( ss->next )
                ss->next->prev = ss;
            else
                tail = ss;
            head = ss;
        }

        seg_count++;
    }

    void remove(TcpSegmentNode* ss)
    {
        if ( ss->prev )
            ss->prev->next = ss->next;
        else
            head = ss->next;

        if ( ss->next )
            ss->next->prev = ss->prev;
        else
            tail = ss->prev;

        seg_count--;
    }

    uint32_t purge()
    {
        int i = 0;

        while ( head )
        {
            i++;
            TcpSegmentNode* dump_me = head;
            head = head->next;
            dump_me->term();
        }

        head = tail = cur_rseg = cur_sseg = nullptr;
        seg_count = 0;
        flush_count = 0;
        seg_bytes_total = 0;
        seg_bytes_logical = 0;
        total_bytes_queued = 0;
        total_segs_queued = 0;
        overlap_count = 0;
        return i;
    }

public:
    TcpSegmentNode* head = nullptr;
    TcpSegmentNode* tail = nullptr;

    TcpSegmentNode* cur_rseg = nullptr;
    TcpSegmentNode* cur_sseg = nullptr;

    uint32_t seg_count = 0;             /* number of current queued segments */
    uint32_t flush_count = 0;           /* queued segments already flushed */

    uint32_t seglist_base_seq = 0;      /* seq of first queued segment */
    uint32_t seg_bytes_total = 0;       /* total bytes currently queued */
    uint32_t seg_bytes_logical = 0;     /* logical bytes queued (total - overlaps) */
    uint32_t total_bytes_queued = 0;    /* total bytes queued (life of session) */
    uint32_t total_segs_queued = 0;     /* number of segments queued (life) */
    uint32_t overlap_count = 0;         /* overlaps encountered */

    TcpSession* session = nullptr;
    TcpStreamTracker* tracker = nullptr;
    TcpOverlapResolver* overlap_resolver = nullptr;
    TcpOverlapState* tos = nullptr;

private:
    void insert_segment_in_empty_seglist(TcpSegmentDescriptor&);
    void insert_segment_in_seglist(TcpSegmentDescriptor&);

    bool is_segment_fasttrack(TcpSegmentNode*, const TcpSegmentDescriptor&);
    uint32_t get_pending_segment_count(const unsigned max) const;

};

#endif

