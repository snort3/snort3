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

// tcp_segment.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 21, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_segment_node.h"

#include "utils/util.h"

#include "segment_overlap_editor.h"
#include "tcp_module.h"

TcpSegmentNode::TcpSegmentNode(const struct timeval& tv, const uint8_t* payload, uint16_t len) :
    prev(nullptr), next(nullptr), tv(tv), ts(0), i_seq(0), c_seq(0), i_len(len),
    c_len(len), offset(0), last_flush_len(0), urg_offset(0)
{
    data = ( uint8_t* )snort_alloc(len);
    memcpy(data, payload, len);
    tcpStats.mem_in_use += len;
}

//-------------------------------------------------------------------------
// TcpSegment stuff
//-------------------------------------------------------------------------
TcpSegmentNode* TcpSegmentNode::init(TcpSegmentDescriptor& tsd)
{
    return new TcpSegmentNode(tsd.get_pkt()->pkth->ts, tsd.get_pkt()->data, tsd.get_seg_len());
}

TcpSegmentNode* TcpSegmentNode::init(TcpSegmentNode& tns)
{
    return new TcpSegmentNode(tns.tv, tns.payload(), tns.c_len);
}

void TcpSegmentNode::term()
{
    snort_free(data);
    tcpStats.segs_released++;
    tcpStats.mem_in_use -= i_len;
    delete this;
}

bool TcpSegmentNode::is_retransmit(const uint8_t* rdata, uint16_t rsize, uint32_t rseq, uint16_t orig_dsize, bool *full_retransmit)
{
    // retransmit must have same payload at same place
    if ( !SEQ_EQ(i_seq, rseq) )
        return false;

    if( orig_dsize == c_len )
    {
        if ( ( ( c_len <= rsize )and !memcmp(data, rdata, c_len) )
            or ( ( c_len > rsize )and !memcmp(data, rdata, rsize) ) )
        {
            return true;
        }
    }
    //Checking for a possible split of segment in which case
    //we compare complete data of the segment to find a retransmission
    else if(full_retransmit and (orig_dsize == rsize) and !memcmp(data, rdata, rsize) )
    {
        *full_retransmit = true;
        return true;
    }

    return false;
}
