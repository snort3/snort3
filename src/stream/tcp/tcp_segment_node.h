//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment_node.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Sep 21, 2015

#ifndef TCP_SEGMENT_NODE_H
#define TCP_SEGMENT_NODE_H

#include <cassert>

#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "tcp_defs.h"

class TcpSegmentDescriptor;

//-----------------------------------------------------------------
// we make a lot of TcpSegments so it is organized by member
// size/alignment requirements to minimize unused space
// ... however, use of padding below is critical, adjust if needed
// and we use the struct hack to avoid 2 allocs per node
//-----------------------------------------------------------------

class TcpSegmentNode
{
private:
    static TcpSegmentNode* create(const struct timeval& tv, const uint8_t* segment, uint16_t len);

public:
    static TcpSegmentNode* init(const TcpSegmentDescriptor&);
    static TcpSegmentNode* init(TcpSegmentNode&);

    void term();

    static void setup();
    static void clear();

    bool is_retransmit(const uint8_t*, uint16_t size, uint32_t, uint16_t, bool*);

    uint8_t* payload()
    { return data + offset; }

    uint8_t* paf_data()
    { return data + offset + cursor; }

    uint32_t start_seq() const
    { return seq + offset; }

    uint32_t next_seq() const
    { return start_seq() + length; }

    uint32_t scan_seq() const
    { return start_seq() + cursor; }

    bool is_packet_missing(uint32_t to_seq)
    {
        if ( next )
            return !(SEQ_EQ(next_seq(), next->start_seq()));
        else
            return SEQ_LT(next_seq(), to_seq);
    }

    void advance_cursor(uint16_t bytes)
    { cursor += bytes; }

    unsigned unscanned() const
    {
        assert(cursor <= length);
        return length - cursor;
    }

    bool next_no_gap()
    {
        return next and SEQ_EQ(next_seq(), next->start_seq());
    }

    bool next_acked_no_gap(uint32_t seq_acked)
    {
        if ( !next_no_gap() )
            return false;

        return SEQ_LT(next->start_seq() + next->cursor, seq_acked);
    }

public:
    TcpSegmentNode* prev;
    TcpSegmentNode* next;

    struct timeval tv;
    uint32_t ts;

    uint32_t seq;           // initial seq # of the data segment (fixed)
    uint16_t length;        // working length of the segment data (relative to offset)
    uint16_t offset;        // working start of segment data
    uint16_t cursor;        // scan position (relative to offset)
    uint16_t size;          // allocated payload size
    uint8_t data[1];
};

#endif

