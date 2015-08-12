//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#ifndef TCP_SESSION_H
#define TCP_SESSION_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_tcp.h"
#include "stream/paf.h"
#include "flow/session.h"

// TBD-EDM - these includes are for functions moved to a new file to group related functionality
// in specific files ... these functional groups will be further refactored as the stream tcp
// rewrite continues...
#include "tcp_reassembly.h"
// TBD-EDM

/* Only track a maximum number of alerts per session */
#define MAX_SESSION_ALERTS 8

#ifdef DEBUG
extern const char* const flush_policy_names[];
#endif

struct StateMgr
{
    uint8_t state;
    uint8_t sub_state;
    uint8_t state_queue;
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

struct TcpTracker
{
    StateMgr s_mgr; /* state tracking goodies */
    class StreamSplitter* splitter;
    FlushPolicy flush_policy;

    // this is intended to be private to paf but is included
    // directly to avoid the need for allocation; do not directly
    // manipulate within this module.
    PAF_State paf_state;    // for tracking protocol aware flushing

    StreamTcpConfig* config;
    TcpSegment *seglist; /* first queued segment */
    TcpSegment *seglist_tail; /* last queued segment */

    // FIXIT-P seglist_base_seq is the sequence number to flush from
    // and is valid even when seglist is empty.  seglist_next is
    // the segment to flush from and is set per packet.  should keep
    // up to date.
    TcpSegment* seglist_next;

    /* Local for these variables means the local part of the connection.  For
     * example, if this particular TcpTracker was tracking the client side
     * of a connection, the l_unackd value would represent the client side of
     * the connection's last unacked sequence number
     */
    uint32_t l_unackd; /* local unack'd seq number */
    uint32_t l_nxt_seq; /* local next expected sequence */
    uint32_t l_window; /* local receive window */

    uint32_t r_nxt_ack; /* next expected ack from remote side */
    uint32_t r_win_base; /* remote side window base sequence number
     * (i.e. the last ack we got) */
    uint32_t isn; /* initial sequence number */
    uint32_t ts_last; /* last timestamp (for PAWS) */
    uint32_t ts_last_pkt; /* last packet timestamp we got */

    uint32_t seglist_base_seq; /* seq of first queued segment */
    uint32_t seg_count; /* number of current queued segments */
    uint32_t seg_bytes_total; /* total bytes currently queued */
    uint32_t seg_bytes_logical; /* logical bytes queued (total - overlaps) */
    uint32_t total_bytes_queued; /* total bytes queued (life of session) */
    uint32_t total_segs_queued; /* number of segments queued (life) */
    uint32_t overlap_count; /* overlaps encountered */
    uint32_t small_seg_count;
    uint32_t flush_count; /* number of flushed queued segments */
    uint32_t xtradata_mask; /* extra data available to log */

    uint16_t os_policy;
    uint16_t reassembly_policy;

    uint16_t wscale; /* window scale setting */
    uint16_t mss; /* max segment size */

    uint8_t mac_addr[6];
    uint8_t flags; /* bitmap flags (TF_xxx) */

    uint8_t alert_count; /* number alerts stored (up to MAX_SESSION_ALERTS) */
    StreamAlertInfo alerts[MAX_SESSION_ALERTS]; /* history of alerts */
};

// FIXIT-L session tracking must be split from reassembly
// into a separate module a la ip_session.cc and ip_defrag.cc
// (of course defrag should also be cleaned up)
class TcpSession: public Session
{
public:
    TcpSession(Flow*);
    ~TcpSession();

    bool setup(Packet*) override;
    int process(Packet*) override;
    void clear() override;
    void cleanup() override;
    void restart(Packet*) override;

    void update_direction(char dir, const sfip_t*, uint16_t port) override;

    bool add_alert(Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(Packet*, uint32_t gid, uint32_t sid) override;

    int update_alert(Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
            uint32_t /*event_id*/, uint32_t /*event_second*/) override;

    void flush_client(Packet*) override;
    void flush_server(Packet*) override;
    void flush_talker(Packet*) override;
    void flush_listener(Packet*) override;

    void set_splitter(bool /*c2s*/, StreamSplitter*) override;
    StreamSplitter* get_splitter(bool /*c2s*/) override;

    void set_extra_data(Packet*, uint32_t /*flag*/) override;
    void clear_extra_data(Packet*, uint32_t /*flag*/) override;

    bool is_sequenced(uint8_t /*dir*/) override;
    bool are_packets_missing(uint8_t /*dir*/) override;

    uint8_t get_reassembly_direction() override;
    uint8_t missing_in_reassembled(uint8_t /*dir*/) override;

    void reset();
    void flush();
    void start_proxy();

public:
    TcpTracker client;
    TcpTracker server;

    static void set_memcap(class Memcap&);

    static void sinit();
    static void sterm();

    static void show(StreamTcpConfig*);

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    int32_t ingress_index; /* Index of the inbound interface. */
    int32_t egress_index; /* Index of the outbound interface. */
    int32_t ingress_group; /* Index of the inbound group. */
    int32_t egress_group; /* Index of the outbound group. */
    uint32_t daq_flags; /* Flags for the packet (DAQ_PKT_FLAG_*) */
    uint16_t address_space_id;
#endif

    uint8_t ecn;
    bool lws_init;
    bool tcp_init;
    uint32_t event_mask;

private:
    int process_dis(Packet*);
};

#endif

