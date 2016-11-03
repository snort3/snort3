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

// tcp_stream_session.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Feb 18, 2016

#ifndef TCP_STREAM_SESSION_H_
#define TCP_STREAM_SESSION_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "flow/session.h"
#include "stream/libtcp/tcp_stream_tracker.h"
#include "stream/tcp/tcp_stream_config.h"

#ifdef DEBUG_MSGS
extern const char* const flush_policy_names[];
#endif

// FIXIT-L session tracking must be split from reassembly
// into a separate module a la ip_session.cc and ip_defrag.cc
// (of course defrag should also be cleaned up)
class TcpStreamSession : public Session
{
public:
    TcpStreamSession(Flow*);
    virtual ~TcpStreamSession();

    bool setup(Packet*) override;
    void clear() override;
    void cleanup(Packet* = nullptr) override;
    void set_splitter(bool, StreamSplitter*) override;
    StreamSplitter* get_splitter(bool) override;
    bool is_sequenced(uint8_t /*dir*/) override;
    bool are_packets_missing(uint8_t /*dir*/) override;
    uint8_t get_reassembly_direction() override;
    uint8_t missing_in_reassembled(uint8_t /*dir*/) override;
    void update_direction(char dir, const SfIp*, uint16_t port) override;
    bool add_alert(Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(Packet*, uint32_t gid, uint32_t sid) override;
    int update_alert(Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
        uint32_t /*event_id*/, uint32_t /*event_second*/) override;

    static void sinit();
    static void sterm();

    void reset();
    void start_proxy();
    void print();

    void SetPacketHeaderFoo(const Packet* p);
    void GetPacketHeaderFoo(DAQ_PktHdr_t* pkth, uint32_t dir);
    void SwapPacketHeaderFoo();

    virtual void update_perf_base_state(char) { }
    virtual void clear_session(
        bool free_flow_data, bool flush_segments, bool restart, Packet* p = nullptr) = 0;

    // FIXIT-L these 2 function names convey no meaning afaict... figure out
    // why are they called and name appropriately...
    virtual void retransmit_process(Packet* p)
    {
        // Data has already been analyzed so don't bother looking at it again.
        DetectionEngine::disable_content(p);
    }

    virtual void retransmit_handle(Packet* p)
    {
        flow->call_handlers(p, false);
    }

    virtual void eof_handle(Packet* p)
    {
        flow->call_handlers(p, true);
    }

    virtual void flush() { }

    virtual TcpStreamTracker::TcpState get_talker_state()
    { return TcpStreamTracker::TCP_MAX_STATES; }

    virtual TcpStreamTracker::TcpState get_listener_state()
    { return TcpStreamTracker::TCP_MAX_STATES; }

    virtual void init_new_tcp_session(TcpSegmentDescriptor&);
    virtual void update_timestamp_tracking(TcpSegmentDescriptor&) { }
    virtual void update_session_on_syn_ack();
    virtual void update_session_on_ack();
    virtual void update_session_on_server_packet(TcpSegmentDescriptor&);
    virtual void update_session_on_client_packet(TcpSegmentDescriptor&);
    virtual void update_session_on_rst(TcpSegmentDescriptor&, bool) { }
    virtual bool handle_syn_on_reset_session(TcpSegmentDescriptor&) { return true; }
    virtual void handle_data_on_syn(TcpSegmentDescriptor&) { }
    virtual void update_ignored_session(TcpSegmentDescriptor&) { }

    void generate_no_3whs_event()
    {
        if ( !no_3whs )
        {
            tel.set_tcp_event(EVENT_NO_3WHS);
            no_3whs = true;
        }
    }

    void set_pkt_action_flag(uint32_t flag)
    { pkt_action_mask |= flag; }

    virtual void update_paws_timestamps(TcpSegmentDescriptor&) { }
    virtual void check_for_repeated_syn(TcpSegmentDescriptor&) { }
    virtual void check_for_session_hijack(TcpSegmentDescriptor&) { }
    virtual bool check_for_window_slam(TcpSegmentDescriptor&) { return true; }
    virtual void mark_packet_for_drop(TcpSegmentDescriptor&) { }
    virtual void handle_data_segment(TcpSegmentDescriptor&) { }
    virtual bool validate_packet_established_session(TcpSegmentDescriptor&) { return true; }

    TcpStreamTracker* client = nullptr;
    TcpStreamTracker* server = nullptr;
    bool lws_init = false;
    bool tcp_init = false;
    uint32_t pkt_action_mask = ACTION_NOTHING;
    uint8_t ecn = 0;
    int32_t ingress_index = 0;
    int32_t ingress_group = 0;
    int32_t egress_index = 0;
    int32_t egress_group = 0;
    uint32_t daq_flags = 0;
    uint16_t address_space_id = 0;
    bool no_3whs = false;
    TcpStreamConfig* config = nullptr;
    TcpEventLogger tel;

protected:
    virtual void set_os_policy() = 0;

    TcpStreamTracker* talker = nullptr;
    TcpStreamTracker* listener = nullptr;
};

#endif

