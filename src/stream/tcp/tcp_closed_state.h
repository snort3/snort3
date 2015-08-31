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

// tcp_closed_state.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifndef TCP_CLOSED_STATE_H
#define TCP_CLOSED_STATE_H

#include "stream/libtcp/tcp_state_handler.h"

class TcpClosedState: public TcpStateHandler
{
public:
    TcpClosedState();
    virtual ~TcpClosedState();

    void syn_sent(TcpSegmentDescriptor&, TcpStreamTracker&);
    void syn_recv(TcpSegmentDescriptor&, TcpStreamTracker&);
    void syn_ack_sent(TcpSegmentDescriptor&, TcpStreamTracker&);
    void syn_ack_recv(TcpSegmentDescriptor&, TcpStreamTracker&);
    void ack_sent(TcpSegmentDescriptor&, TcpStreamTracker&);
    void ack_recv(TcpSegmentDescriptor&, TcpStreamTracker&);
    void data_seg_sent(TcpSegmentDescriptor&, TcpStreamTracker&);
    void data_seg_recv(TcpSegmentDescriptor&, TcpStreamTracker&);
    void fin_sent(TcpSegmentDescriptor&, TcpStreamTracker&);
    void fin_recv(TcpSegmentDescriptor&, TcpStreamTracker&);
    void rst_sent(TcpSegmentDescriptor&, TcpStreamTracker&);
    void rst_recv(TcpSegmentDescriptor&, TcpStreamTracker&);
};

#endif
