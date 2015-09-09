//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment_descriptor.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#include "tcp_segment_descriptor.h"

TcpSegmentDescriptor::TcpSegmentDescriptor( Flow* flow, Packet* pkt ) :
	flow( flow ), pkt( pkt )
{
    direction = flow->ssn_state.direction;

    tcph = pkt->ptrs.tcph;
    data_len = pkt->dsize;

    src_port = ntohs(tcph->th_sport);
    dst_port = ntohs(pkt->ptrs.tcph->th_dport);
    seq = ntohl(pkt->ptrs.tcph->th_seq);
    ack = ntohl(pkt->ptrs.tcph->th_ack);
    win = ntohs(pkt->ptrs.tcph->th_win);
    end_seq = seq + (uint32_t) pkt->dsize;
    ts = 0;
}

TcpSegmentDescriptor::~TcpSegmentDescriptor()
{
    // TODO Auto-generated destructor stub
}

