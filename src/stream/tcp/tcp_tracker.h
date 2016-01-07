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

// tcp_tracker.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Dec 1, 2015

#ifndef TCP_TRACKER_H_
#define TCP_TRACKER_H_

#include "stream/libtcp/tcp_stream_tracker.h"
#include "stream/paf.h"
#include "tcp_defs.h"

struct StateMgr
{
    uint8_t sub_state;
    enum TcpStreamTracker::TcpStates state_queue;
    uint8_t expected_flags;
    uint32_t transition_seq;
    uint32_t stq_get_seq;
};

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

/* Only track a maximum number of alerts per session */
#define MAX_SESSION_ALERTS 8
struct StreamAlertInfo
{
    /* For storing alerts that have already been seen on the session */
    uint32_t sid;
    uint32_t gid;
    uint32_t seq;
    // if we log extra data, event_* is used to correlate with alert
    uint32_t event_id;
    uint32_t event_second;
};

class TcpNormalizer;
class TcpReassembler;

class TcpTracker : public TcpStreamTracker
{
public:
    TcpTracker(bool);
    virtual ~TcpTracker(void);
    void init_tracker(void);
    void print(void);
    void init_flush_policy(void);
    void set_splitter(StreamSplitter* ss);
    void set_splitter(const Flow* flow);

    void init_on_syn_sent(TcpSegmentDescriptor&);
    void init_on_syn_recv(TcpSegmentDescriptor&);
    void init_on_synack_sent(TcpSegmentDescriptor& tsd);
    void init_on_synack_recv(TcpSegmentDescriptor& tsd);
    void init_on_3whs_ack_sent(TcpSegmentDescriptor& tsd);
    void init_on_3whs_ack_recv(TcpSegmentDescriptor& tsd);
    void init_on_data_seg_sent(TcpSegmentDescriptor& tsd);
    void init_on_data_seg_recv(TcpSegmentDescriptor& tsd);

    StateMgr s_mgr; /* state tracking goodies */

    // this is intended to be private to paf but is included
    // directly to avoid the need for allocation; do not directly
    // manipulate within this module.
    PAF_State paf_state;    // for tracking protocol aware flushing
    FlushPolicy flush_policy;
    StreamSplitter* splitter;
    TcpNormalizer* normalizer;
    TcpReassembler* reassembler;

    uint32_t r_nxt_ack; /* next expected ack from remote side */
    uint32_t r_win_base; /* remote side window base sequence number
     * (i.e. the last ack we got) */

    uint32_t small_seg_count;

    uint8_t alert_count; /* number alerts stored (up to MAX_SESSION_ALERTS) */
    StreamAlertInfo alerts[MAX_SESSION_ALERTS]; /* history of alerts */
};

#endif

