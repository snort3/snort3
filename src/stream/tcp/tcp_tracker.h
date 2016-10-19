//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_tracker.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Dec 1, 2015

#ifndef TCP_TRACKER_H_
#define TCP_TRACKER_H_

#include "stream/libtcp/tcp_stream_tracker.h"

//-------------------------------------------------------------------------
// extra, extra - read all about it!
// -- u2 is the only output plugin that currently supports extra data
// -- extra data may be captured before or after alerts
// -- extra data may be per packet or persistent (saved on session)
//
// -- per packet extra data is logged iff we alert on the packet
//    containing the extra data - u2 drives this
// -- an extra data mask is added to Packet to indicate when per packet
//    extra data is available
//
// -- persistent extra data must be logged exactly once for each alert
//    regardless of capture/alert ordering - s5 purge_alerts drives this
// -- an extra data mask is added to the session trackers to indicate that
//    persistent extra data is available
//
// -- event id and second are added to the session alert trackers so that
//    the extra data can be correlated with events
// -- event id and second are not available when check_alerted()
//    is called; u2 calls StreamUpdateSessionAlertTcp as events are logged
//    to set these fields
//-------------------------------------------------------------------------

class TcpTracker : public TcpStreamTracker
{
public:
    TcpTracker(bool, class TcpSession*);
    virtual ~TcpTracker();

    void init_tcp_state() override;
    void print() override;
    void init_flush_policy() override;
    void set_splitter(StreamSplitter* ss) override;
    void set_splitter(const Flow* flow) override;
    void reset_splitter( void ) override;

    void init_on_syn_sent(TcpSegmentDescriptor&) override;
    void init_on_syn_recv(TcpSegmentDescriptor&) override;
    void init_on_synack_sent(TcpSegmentDescriptor& tsd) override;
    void init_on_synack_recv(TcpSegmentDescriptor& tsd) override;
    void init_on_3whs_ack_sent(TcpSegmentDescriptor& tsd) override;
    void init_on_3whs_ack_recv(TcpSegmentDescriptor& tsd) override;
    void init_on_data_seg_sent(TcpSegmentDescriptor& tsd) override;
    void init_on_data_seg_recv(TcpSegmentDescriptor& tsd) override;
    void finish_server_init(TcpSegmentDescriptor& tsd) override;
    void finish_client_init(TcpSegmentDescriptor& tsd) override;

    void update_tracker_ack_recv(TcpSegmentDescriptor& tsd) override;
    void update_tracker_ack_sent(TcpSegmentDescriptor& tsd) override;
    bool update_on_3whs_ack(TcpSegmentDescriptor& tsd) override;
    bool update_on_rst_recv(TcpSegmentDescriptor& tsd) override;
    void update_on_rst_sent() override;
    bool update_on_fin_recv(TcpSegmentDescriptor& tsd) override;
    bool update_on_fin_sent(TcpSegmentDescriptor& tsd) override;
    bool is_segment_seq_valid(TcpSegmentDescriptor& tsd) override;
    void flush_data_on_fin_recv(TcpSegmentDescriptor& tsd) override;

    void init_toolbox() override;
};

#endif

