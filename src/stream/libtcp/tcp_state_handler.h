//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_handler.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jun 24, 2015

#ifndef TCP_STATE_HANDLER_H
#define TCP_STATE_HANDLER_H

#include "protocols/tcp.h"
#include "stream/libtcp/tcp_stream_tracker.h"

class TcpSegmentDescriptor;
class TcpStateMachine;

class TcpStateHandler
{
public:
    TcpStateHandler(TcpStreamTracker::TcpState, TcpStateMachine&);
    virtual ~TcpStateHandler() = default;

    virtual bool eval(TcpSegmentDescriptor&, TcpStreamTracker&);

    TcpStreamTracker::TcpState get_tcp_state() const
    {
        return tcp_state;
    }

    const TcpStateMachine* get_tsm() const
    {
        return tsm;
    }

    void set_tsm(const TcpStateMachine* tsm)
    {
        this->tsm = tsm;
    }

    virtual bool do_pre_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&);
    virtual bool do_post_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&);

protected:
    virtual bool syn_sent(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool syn_recv(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool syn_ack_sent(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool syn_ack_recv(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool ack_sent(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool ack_recv(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool data_seg_sent(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool data_seg_recv(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool fin_sent(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool fin_recv(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool rst_sent(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }
    virtual bool rst_recv(TcpSegmentDescriptor&, TcpStreamTracker&) { return true; }

    const TcpStateMachine* tsm;
    TcpStreamTracker::TcpState tcp_state;
};

#endif

