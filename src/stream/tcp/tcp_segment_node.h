//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment_node.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 21, 2015

#ifndef TCP_SEGMENT_H
#define TCP_SEGMENT_H

#include "main/snort_debug.h"
#include "stream/libtcp/tcp_segment_descriptor.h"
#include "stream/tcp/tcp_defs.h"

class TcpSegmentDescriptor;

//-----------------------------------------------------------------
// we make a lot of TcpSegments so it is organized by member
// size/alignment requirements to minimize unused space
// ... however, use of padding below is critical, adjust if needed
//-----------------------------------------------------------------

class TcpSegmentNode
{
public:
	TcpSegmentNode(const struct timeval& tv, const uint8_t* segment, uint16_t len);

    static TcpSegmentNode* init(TcpSegmentDescriptor& tsd);
    static TcpSegmentNode* init(TcpSegmentNode& tns);
    static TcpSegmentNode* init(const struct timeval&, const uint8_t*, unsigned);

    void term();
    bool is_retransmit(const uint8_t*, uint16_t size, uint32_t, uint16_t, bool*);
    uint8_t* payload()
    { return data + offset; }

    bool is_packet_missing(uint32_t to_seq)
    {
        if ( next )
            return (i_seq + i_len) != next->i_seq;
        else
            return (c_seq + c_len) < to_seq;
    }

    TcpSegmentNode* prev;
    TcpSegmentNode* next;

    uint8_t* data;

    struct timeval tv;
    uint32_t ts;
    uint32_t i_seq;             // initial seq # of the data segment
    uint32_t c_seq;             // current seq # of data for reassembly
    uint16_t i_len;             // initial length of the data segment
    uint16_t c_len;             // length of data remaining for reassembly
    uint16_t offset;
    uint16_t last_flush_len;
    uint16_t urg_offset;
};

class TcpSegmentList
{
public:
    uint32_t reset()
    {
        int i = 0;

        while ( head )
        {
            i++;
            TcpSegmentNode* dump_me = head;
            head = head->next;
            dump_me->term();
        }

        head = tail = cur_rseg = nullptr;
        count = 0;
        return i;
    }

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

        count++;
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

        count--;
    }

    TcpSegmentNode* head = nullptr;
    TcpSegmentNode* tail = nullptr;
    TcpSegmentNode* cur_rseg = nullptr;
    uint32_t count = 0;
};

#endif

