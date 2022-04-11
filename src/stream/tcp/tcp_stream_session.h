//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_session.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Feb 18, 2016

#ifndef TCP_STREAM_SESSION_H
#define TCP_STREAM_SESSION_H

#include "detection/detection_engine.h"
#include "flow/session.h"
#include "protocols/ipv6.h"

#include "tcp_stream_config.h"
#include "tcp_stream_tracker.h"

// FIXIT-L session tracking could be split from reassembly
// into a separate module a la ip_session.cc and ip_defrag.cc
// (of course defrag should also be cleaned up)
class TcpStreamSession : public Session
{
public:
    ~TcpStreamSession() override;

    void clear() override;
    void cleanup(snort::Packet* = nullptr) override;

    void set_splitter(bool, snort::StreamSplitter*) override;
    snort::StreamSplitter* get_splitter(bool) override;

    bool is_sequenced(uint8_t dir) override;
    bool are_packets_missing(uint8_t dir) override;

    void disable_reassembly(snort::Flow*) override;
    uint8_t get_reassembly_direction() override;
    uint8_t missing_in_reassembled(uint8_t dir) override;
    bool are_client_segments_queued() override;

    bool add_alert(snort::Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(snort::Packet*, uint32_t gid, uint32_t sid) override;
    int update_alert(snort::Packet*, uint32_t gid, uint32_t sid,
        uint32_t event_id, uint32_t event_second) override;

    bool set_packet_action_to_hold(snort::Packet*) override;

    uint16_t get_mss(bool to_server) const;
    uint8_t get_tcp_options_len(bool to_server) const;

    void reset();
    void start_proxy();

    void set_packet_header_foo(const TcpSegmentDescriptor&);
    void get_packet_header_foo(DAQ_PktHdr_t*, uint32_t dir);
    bool can_set_no_ack();
    bool set_no_ack(bool);
    bool no_ack_mode_enabled() { return no_ack; }
    virtual void update_perf_base_state(char) = 0;
    virtual void clear_session(
        bool free_flow_data, bool flush_segments, bool restart, snort::Packet* p = nullptr) = 0;
    virtual TcpStreamTracker::TcpState get_talker_state(TcpSegmentDescriptor&) = 0;
    virtual TcpStreamTracker::TcpState get_listener_state(TcpSegmentDescriptor&) = 0;
    TcpStreamTracker::TcpState get_peer_state(TcpStreamTracker* me)
    { return me == &client ? server.get_tcp_state() : client.get_tcp_state(); }

    virtual void init_new_tcp_session(TcpSegmentDescriptor&);
    virtual void update_timestamp_tracking(TcpSegmentDescriptor&) = 0;
    virtual void update_session_on_syn_ack();
    virtual void update_session_on_ack();
    virtual void update_session_on_server_packet(TcpSegmentDescriptor&);
    virtual void update_session_on_client_packet(TcpSegmentDescriptor&);
    virtual void update_session_on_rst(TcpSegmentDescriptor&, bool) = 0;
    virtual bool handle_syn_on_reset_session(TcpSegmentDescriptor&) = 0;
    virtual void handle_data_on_syn(TcpSegmentDescriptor&) = 0;
    virtual void update_ignored_session(TcpSegmentDescriptor&) = 0;
    void generate_no_3whs_event()
    {
        if ( generate_3whs_alert && flow->two_way_traffic())
        {
            tel.set_tcp_event(EVENT_NO_3WHS);
            generate_3whs_alert = false;
        }
    }

    void set_pkt_action_flag(uint32_t flag)
    { pkt_action_mask |= flag; }

    virtual void update_paws_timestamps(TcpSegmentDescriptor&) = 0;
    virtual void check_for_repeated_syn(TcpSegmentDescriptor&) = 0;
    virtual void check_for_session_hijack(TcpSegmentDescriptor&) = 0;
    virtual bool check_for_window_slam(TcpSegmentDescriptor&) = 0;
    virtual void mark_packet_for_drop(TcpSegmentDescriptor&) = 0;
    virtual void handle_data_segment(TcpSegmentDescriptor&) = 0;
    virtual bool validate_packet_established_session(TcpSegmentDescriptor&) = 0;

    TcpStreamTracker client;
    TcpStreamTracker server;
    bool lws_init = false;
    bool tcp_init = false;
    uint32_t pkt_action_mask = ACTION_NOTHING;
    uint8_t ecn = 0;
    int32_t ingress_index = DAQ_PKTHDR_UNKNOWN;
    int16_t ingress_group = DAQ_PKTHDR_UNKNOWN;
    int32_t egress_index = DAQ_PKTHDR_UNKNOWN;
    int16_t egress_group = DAQ_PKTHDR_UNKNOWN;
    uint32_t daq_flags = 0;
    uint16_t address_space_id = 0;
    bool generate_3whs_alert = true;
    TcpStreamConfig* tcp_config = nullptr;
    TcpEventLogger tel;
    bool cleaning = false;
    uint8_t held_packet_dir = SSN_DIR_NONE;

private:
    bool no_ack = false;

protected:
    TcpStreamSession(snort::Flow*);
    virtual void set_os_policy() = 0;
};

#endif

