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

// tcp_syn_sent_state.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Aug 5, 2015

#include <iostream>
using namespace std;

#include "tcp_syn_recv_state.h"

TcpSynRecvState::TcpSynRecvState()
{
    // TODO Auto-generated constructor stub

}

TcpSynRecvState::~TcpSynRecvState()
{
    // TODO Auto-generated destructor stub
}

void TcpSynRecvState::syn_sent( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::syn_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::syn_ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::syn_ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::data_seg_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::data_seg_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::fin_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::fin_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::rst_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpSynRecvState::rst_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

