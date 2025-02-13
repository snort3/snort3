//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow.h"
#include "flow/session.h"
#include "protocols/packet.h"
#include "stream/stream.h"

#include "tcp_event_logger.h"
#include "tcp_state_machine.h"
#include "tcp_stream_config.h"
#include "tcp_stream_tracker.h"

namespace snort
{
class Flow;
struct Packet;
}

class TcpSegmentDescriptor;

class TcpSession : public Session
{
public:
    TcpSession(snort::Flow*);
    ~TcpSession() override;

    static void sinit();
    static void sterm();

    bool setup(snort::Packet*) override;
    void restart(snort::Packet* p) override;
    bool precheck(snort::Packet* p) override;
    int process(snort::Packet*) override;

    void clear() override;
    void cleanup(snort::Packet* = nullptr) override;

    void set_splitter(bool, snort::StreamSplitter*) override;
    snort::StreamSplitter* get_splitter(bool) override;

    void disable_reassembly(snort::Flow*) override;
    uint8_t missing_in_reassembled(uint8_t dir) const override;
    bool are_client_segments_queued() const override;
    bool is_sequenced(uint8_t dir) const override;
    bool are_packets_missing(uint8_t dir) const override;
    bool set_packet_action_to_hold(snort::Packet*) override;

    bool add_alert(snort::Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(snort::Packet*, uint32_t gid, uint32_t sid) override;
    int update_alert(snort::Packet*, uint32_t gid, uint32_t sid,
        uint32_t event_id, uint32_t event_second) override;
    void set_extra_data(snort::Packet*, uint32_t /*flag*/) override;

    void flush() override;
    void flush_client(snort::Packet*) override;
    void flush_server(snort::Packet*) override;
    void flush_talker(snort::Packet*, bool final_flush = false) override;
    void flush_listener(snort::Packet*, bool final_flush = false) override;
    // cppcheck-suppress virtualCallInConstructor

    void reset();
    void start_proxy();
    void clear_session(bool free_flow_data, bool flush_segments, bool restart, snort::Packet* p = nullptr);
    TcpStreamTracker::TcpState get_talker_state(const TcpSegmentDescriptor& tsd);
    TcpStreamTracker::TcpState get_listener_state(const TcpSegmentDescriptor& tsd);
    TcpStreamTracker::TcpState get_peer_state(const TcpStreamTracker& me)
    { return me.client_tracker ? server.get_tcp_state() : client.get_tcp_state(); }

    void init_new_tcp_session(TcpSegmentDescriptor&);
    void update_perf_base_state(char new_state);
    void update_timestamp_tracking(TcpSegmentDescriptor&);
    void update_paws_timestamps(TcpSegmentDescriptor&);
    void update_session_on_rst(const TcpSegmentDescriptor&, bool);
    bool handle_syn_on_reset_session(TcpSegmentDescriptor&);
    void handle_data_on_syn(TcpSegmentDescriptor&);
    void update_ignored_session(TcpSegmentDescriptor&);

    uint16_t get_mss(bool to_server) const;
    uint8_t get_tcp_options_len(bool to_server) const;

    void get_packet_header_foo(DAQ_PktHdr_t*, const DAQ_PktHdr_t* orig, uint32_t dir);
    bool can_set_no_ack();
    bool set_no_ack(bool);
    inline bool no_ack_mode_enabled() { return no_ack; }

    void set_pkt_action_flag(uint32_t flag)
    { pkt_action_mask |= flag; }

    void set_established(const TcpSegmentDescriptor&);
    void set_pseudo_established(snort::Packet*);
    void check_for_pseudo_established(snort::Packet*);
    bool check_for_one_sided_session(snort::Packet*);

    void check_for_repeated_syn(TcpSegmentDescriptor&);
    void check_for_session_hijack(TcpSegmentDescriptor&);
    bool check_for_window_slam(TcpSegmentDescriptor& tsd);
    void mark_packet_for_drop(TcpSegmentDescriptor&);
    void handle_data_segment(TcpSegmentDescriptor&, bool flush = true);
    bool validate_packet_established_session(TcpSegmentDescriptor&);

    TcpStreamTracker client;
    TcpStreamTracker server;
    TcpStreamConfig* tcp_config = nullptr;
    TcpEventLogger tel;
    bool tcp_init = false;
    uint32_t pkt_action_mask = ACTION_NOTHING;
    uint32_t initiator_watermark = 0;
    int32_t ingress_index = DAQ_PKTHDR_UNKNOWN;
    int32_t egress_index = DAQ_PKTHDR_UNKNOWN;
    int16_t ingress_group = DAQ_PKTHDR_UNKNOWN;
    int16_t egress_group = DAQ_PKTHDR_UNKNOWN;
    uint32_t daq_flags = 0;
    uint32_t address_space_id = 0;
    bool cleaning = false;
    uint8_t held_packet_dir = SSN_DIR_NONE;
    uint8_t ecn = 0;

private:
    int process_tcp_packet(TcpSegmentDescriptor&, const snort::Packet*);
    void set_os_policy();
    void swap_trackers();
    void init_session_on_syn(TcpSegmentDescriptor&);
    void init_session_on_synack(TcpSegmentDescriptor&);
    void update_on_3whs_complete(TcpSegmentDescriptor&);
    bool ignore_this_packet(snort::Packet*);
    bool cleanup_session_if_expired(snort::Packet*);
    void init_tcp_packet_analysis(TcpSegmentDescriptor&);
    void check_events_and_actions(const TcpSegmentDescriptor& tsd);
    void flush_tracker(TcpStreamTracker&, snort::Packet*, uint32_t dir, bool final_flush);
    bool check_reassembly_queue_thresholds(TcpSegmentDescriptor&, TcpStreamTracker*);
    bool filter_packet_for_reassembly(TcpSegmentDescriptor&, TcpStreamTracker*);
    void check_small_segment_threshold(const TcpSegmentDescriptor&, TcpStreamTracker*);
    void check_flow_missed_3whs();

    void set_packet_header_foo(const TcpSegmentDescriptor&);
    void update_session_on_server_packet(TcpSegmentDescriptor&);
    void update_session_on_client_packet(TcpSegmentDescriptor&);

    TcpStateMachine* tsm;
    bool splitter_init = false;
    bool no_ack = false;
};

#endif

