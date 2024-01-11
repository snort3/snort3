//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Sep 21, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_segment_node.h"

#include "main/thread.h"
#include "utils/util.h"

#include "segment_overlap_editor.h"
#include "tcp_module.h"

#define USE_RESERVE
#ifdef USE_RESERVE
static THREAD_LOCAL TcpSegmentNode* reserved = nullptr;
static THREAD_LOCAL unsigned reserve_sz = 0;

static constexpr unsigned num_res = 4096;
static constexpr unsigned res_min = 1024;
static constexpr unsigned res_max = 1460;
#endif

void TcpSegmentNode::setup()
{
#ifdef USE_RESERVE
    reserved = nullptr;
    reserve_sz = 0;
#endif
}

void TcpSegmentNode::clear()
{
#ifdef USE_RESERVE
    while ( reserved )
    {
        TcpSegmentNode* tsn = reserved;
        reserved = reserved->next;
        tcpStats.mem_in_use -= tsn->size;
        snort_free(tsn);
    }
    reserve_sz = 0;
#endif
}

//-------------------------------------------------------------------------
// TcpSegment stuff
//-------------------------------------------------------------------------

TcpSegmentNode* TcpSegmentNode::create(
    const struct timeval& tv, const uint8_t* payload, uint16_t len)
{
    TcpSegmentNode* tsn;

#ifdef USE_RESERVE
    if ( reserved and len > res_min and len <= res_max )
    {
        tsn = reserved;
        reserved = tsn->next;
        --reserve_sz;
    }
    else
#endif
    {
        size_t size = sizeof(*tsn) + len;
        tsn = (TcpSegmentNode*)snort_alloc(size);
        tsn->size = len;
        tcpStats.mem_in_use += len;
    }
    tsn->tv = tv;
    tsn->i_len = tsn->c_len = len;
    memcpy(tsn->data, payload, len);

    tsn->prev = tsn->next = nullptr;
    tsn->i_seq = tsn->c_seq = 0;
    tsn->offset = 0;
    tsn->ts = 0;

    return tsn;
}

TcpSegmentNode* TcpSegmentNode::init(const TcpSegmentDescriptor& tsd)
{
    return create(tsd.get_pkt()->pkth->ts, tsd.get_pkt()->data, tsd.get_len());
}

TcpSegmentNode* TcpSegmentNode::init(TcpSegmentNode& tns)
{
    return create(tns.tv, tns.payload(), tns.c_len);
}

void TcpSegmentNode::term()
{
#ifdef USE_RESERVE
    if ( size == res_max and reserve_sz < num_res )
    {
        next = reserved;
        reserved = this;
        reserve_sz++;
    }
    else
#endif
    {
        tcpStats.mem_in_use -= size;
        snort_free(this);
    }
    tcpStats.segs_released++;
}

bool TcpSegmentNode::is_retransmit(const uint8_t* rdata, uint16_t rsize,
    uint32_t rseq, uint16_t orig_dsize, bool *full_retransmit)
{
    // retransmit must have same payload at same place
    if ( !SEQ_EQ(i_seq, rseq) )
        return false;

    if ( orig_dsize == c_len )
    {
        uint16_t cmp_len = ( c_len <= rsize ) ? c_len : rsize;
        if ( !memcmp(data, rdata, cmp_len) )
            return true;
    }
    //Checking for a possible split of segment in which case
    //we compare complete data of the segment to find a retransmission
    else if ( (orig_dsize == rsize) and !memcmp(data, rdata, rsize) )
    {
        if ( full_retransmit )
            *full_retransmit = true;
        return true;
    }

    return false;
}
