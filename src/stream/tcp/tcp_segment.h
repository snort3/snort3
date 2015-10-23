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

// tcp_segment.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 21, 2015

#ifndef TCP_SEGMENT_H
#define TCP_SEGMENT_H

#include "protocols/packet.h"
#include "flow/memcap.h"

extern THREAD_LOCAL Memcap* tcp_memcap;

//-----------------------------------------------------------------
// we make a lot of TcpSegments so it is organized by member
// size/alignment requirements to minimize unused space
// ... however, use of padding below is critical, adjust if needed
//-----------------------------------------------------------------


class TcpSegment
{
public:
    TcpSegment();
    virtual ~TcpSegment();

    static TcpSegment* init( const struct timeval&, const uint8_t*, unsigned );
    static bool needs_pruning( void )
    {
        return tcp_memcap->at_max();
    }

    void term( void );
    bool is_retransmit( const uint8_t*, uint16_t size, uint32_t );

    TcpSegment *prev;
    TcpSegment *next;

    struct timeval tv;
    uint32_t ts;
    uint32_t seq;
    uint16_t orig_dsize;
    uint16_t payload_size;
    uint16_t urg_offset;
    bool buffered;

    uint8_t* data;
    uint8_t* payload;

};

class TcpSegmentList
{
public:
    TcpSegment *head;
    TcpSegment *tail;

    // FIXIT-P seglist_base_seq is the sequence number to flush from
    // and is valid even when seglist is empty.  next points to
    // the segment to flush from and is set per packet.  should keep
    // up to date.
    TcpSegment* next;

    uint32_t clear( void )
    {
        TcpSegment *dump_me;
        int i = 0;

        DebugMessage(DEBUG_STREAM_STATE, "Clearing ssment list.\n");
        while ( head )
        {
            i++;
            dump_me = head;
            head = head->next;
            dump_me->term( );
        }

        head = tail = next = nullptr;
        DebugFormat(DEBUG_STREAM_STATE, "Dropped %d segments\n", i);
        return i;
    }

    void insert( TcpSegment *prev, TcpSegment *ss )
    {
        if( prev )
        {
            ss->next = prev->next;
            ss->prev = prev;
            prev->next = ss;
            if( ss->next )
                ss->next->prev = ss;
            else
                tail = ss;
        }
        else
        {
            ss->next = head;
            if( ss->next )
                ss->next->prev = ss;
            else
                tail = ss;
            head = ss;
        }
    }

    void remove( TcpSegment *ss )
    {
        if (ss->prev)
            ss->prev->next = ss->next;
        else
           head = ss->next;

        if (ss->next)
            ss->next->prev = ss->prev;
        else
            tail = ss->prev;
    }
};

#endif
