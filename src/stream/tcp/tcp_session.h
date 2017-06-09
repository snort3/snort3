//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "stream/libtcp/tcp_stream_session.h"
#include "stream/libtcp/tcp_state_machine.h"
#include "stream/tcp/tcp_tracker.h"

class TcpEventLogger;

class TcpSession : public TcpStreamSession
{
public:
    TcpSession(Flow*);
    ~TcpSession();

    bool setup(Packet*) override;
    void restart(Packet* p) override;
    void precheck(Packet* p) override;
    int process(Packet*) override;

    void flush() override;
    void flush_client(Packet*) override;
    void flush_server(Packet*) override;
    void flush_talker(Packet*, bool final_flush = false) override;
    void flush_listener(Packet*, bool final_flush = false) override;

    virtual void clear_session(bool free_flow_data, bool flush_segments, bool restart, Packet* p = nullptr) override;

    void set_extra_data(Packet*, uint32_t /*flag*/) override;
    void clear_extra_data(Packet*, uint32_t /*flag*/) override;

    void update_perf_base_state(char new_state) override;
    TcpStreamTracker::TcpState get_talker_state() override;
    TcpStreamTracker::TcpState get_listener_state() override;
    void update_timestamp_tracking(TcpSegmentDescriptor&) override;
    void update_session_on_rst(TcpSegmentDescriptor&, bool) override;
    bool handle_syn_on_reset_session(TcpSegmentDescriptor&) override;
    void handle_data_on_syn(TcpSegmentDescriptor&) override;
    void update_ignored_session(TcpSegmentDescriptor&) override;
    void update_paws_timestamps(TcpSegmentDescriptor&) override;
    void check_for_repeated_syn(TcpSegmentDescriptor&) override;
    void check_for_session_hijack(TcpSegmentDescriptor&) override;
    bool check_for_window_slam(TcpSegmentDescriptor& tsd) override;
    void mark_packet_for_drop(TcpSegmentDescriptor&) override;
    void handle_data_segment(TcpSegmentDescriptor&) override;

    bool validate_packet_established_session(TcpSegmentDescriptor&) override;

private:
    void set_os_policy() override;
    bool flow_exceeds_config_thresholds(TcpSegmentDescriptor&);
    void check_fin_transition_status(TcpSegmentDescriptor&);
    void process_tcp_stream(TcpSegmentDescriptor&);
    int process_tcp_data(TcpSegmentDescriptor&);
    void swap_trackers();
    void NewTcpSessionOnSyn(TcpSegmentDescriptor&);
    void NewTcpSessionOnSynAck(TcpSegmentDescriptor&);
    int process_dis(Packet*);
    void update_on_3whs_complete(TcpSegmentDescriptor&);
    bool is_flow_handling_packets(Packet*);
    void cleanup_session_if_expired(Packet*);
    bool do_packet_analysis_pre_checks(Packet*, TcpSegmentDescriptor&);
    void do_packet_analysis_post_checks(Packet*);
    void flush_tracker(TcpStreamTracker*, Packet*, uint32_t dir, bool final_flush);

    TcpStateMachine* tsm;
};

#endif

