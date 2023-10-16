//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_mid_stream_sent.h author Ron Dempster <rdempste@cisco.com>
// Created on: Dec 7, 2022

#ifndef TCP_STATE_MID_STREAM_SENT_H
#define TCP_STATE_MID_STREAM_SENT_H

#include "tcp_state_handler.h"

class TcpStateMidStreamSent : public TcpStateHandler
{
public:
    TcpStateMidStreamSent(TcpStateMachine&);

    bool syn_sent(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool syn_recv(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool syn_ack_sent(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool syn_ack_recv(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool ack_sent(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool ack_recv(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool data_seg_sent(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool data_seg_recv(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool fin_sent(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool fin_recv(TcpSegmentDescriptor&, TcpStreamTracker&) override;
    bool rst_recv(TcpSegmentDescriptor&, TcpStreamTracker&) override;

    bool do_post_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&) override;

private:
    bool check_for_window_slam(TcpSegmentDescriptor&, TcpStreamTracker&, bool& is_ack_valid);
};

#endif

