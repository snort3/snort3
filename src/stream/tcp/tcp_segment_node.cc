//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "tcp_segment_node.h"

#include "flow/flow_control.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "tcp_module.h"

TcpSegmentNode::TcpSegmentNode() :
    prev(nullptr), next(nullptr), tv({ 0, 0 }), ts(0), seq(0), orig_dsize(0),
    payload_size(0), urg_offset(0), buffered(false), data(nullptr), payload(nullptr)
{
}

TcpSegmentNode::~TcpSegmentNode()
{
    // TODO Auto-generated destructor stub
}

//-------------------------------------------------------------------------
// TcpSegment stuff
//-------------------------------------------------------------------------
TcpSegmentNode* TcpSegmentNode::init(TcpSegmentDescriptor& tsd)
{
    return init(tsd.get_pkt()->pkth->ts, tsd.get_pkt()->data, tsd.get_seg_len() );
}

TcpSegmentNode* TcpSegmentNode::init(TcpSegmentNode& tsn)
{
    return init(tsn.tv, tsn.payload, tsn.payload_size);
}

TcpSegmentNode* TcpSegmentNode::init(const struct timeval& tv, const uint8_t* data, unsigned dsize)
{
    TcpSegmentNode* ss = new TcpSegmentNode;
    ss->data = ( uint8_t* )snort_alloc(dsize);
    ss->payload = ss->data;
    ss->tv = tv;
    memcpy(ss->payload, data, dsize);
    ss->orig_dsize = dsize;
    ss->payload_size = ss->orig_dsize;
    tcpStats.mem_in_use += dsize;
    return ss;
}

void TcpSegmentNode::term()
{
    snort_free(data);
    tcpStats.segs_released++;
    tcpStats.mem_in_use -= orig_dsize;
    delete this;
}

bool TcpSegmentNode::is_retransmit(const uint8_t* rdata, uint16_t rsize, uint32_t rseq)
{
    // retransmit must have same payload at same place
    if ( !SEQ_EQ(seq, rseq) )
        return false;

    if ( ( ( payload_size <= rsize )and !memcmp(data, rdata, payload_size) )
        or ( ( payload_size > rsize )and !memcmp(data, rdata, rsize) ) )
        return true;

    return false;
}

