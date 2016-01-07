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

#include "perf_monitor/perf_base.h"
#include "detection/detect.h"
#include "flow/session.h"

#include "stream/libtcp/tcp_state_machine.h"
#include "stream_tcp.h"
#include "tcp_defs.h"
#include "tcp_stream_config.h"
#include "tcp_tracker.h"

#ifdef DEBUG
extern const char* const flush_policy_names[];
#endif

class TcpEventLogger;

// FIXIT-L session tracking must be split from reassembly
// into a separate module a la ip_session.cc and ip_defrag.cc
// (of course defrag should also be cleaned up)
class TcpSession : public Session
{
public:
    TcpSession(Flow*);
    ~TcpSession();

    bool setup(Packet*) override;
    int process(Packet*) override;
    void clear(void) override;
    void cleanup(void) override;
    void restart(Packet*) override;
    void print(void);

    void set_splitter(bool, StreamSplitter*) override;
    StreamSplitter* get_splitter(bool) override;
    void init_new_tcp_session(TcpSegmentDescriptor& tsd);
    void update_session_state(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd);

    void update_direction(char dir, const sfip_t*, uint16_t port) override;

    bool add_alert(Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(Packet*, uint32_t gid, uint32_t sid) override;
    int update_alert(Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
        uint32_t /*event_id*/, uint32_t /*event_second*/) override;

    void flush_client(Packet*) override;
    void flush_server(Packet*) override;
    void flush_talker(Packet*) override;
    void flush_listener(Packet*) override;

    void set_extra_data(Packet*, uint32_t /*flag*/) override;
    void clear_extra_data(Packet*, uint32_t /*flag*/) override;
    bool is_sequenced(uint8_t /*dir*/) override;
    bool are_packets_missing(uint8_t /*dir*/) override;
    uint8_t get_reassembly_direction(void) override;
    uint8_t missing_in_reassembled(uint8_t /*dir*/) override;

    void update_perf_base_state(SFBASE* sf_base, char newState);

    void SetPacketHeaderFoo(const Packet* p);
    void GetPacketHeaderFoo(DAQ_PktHdr_t* pkth, uint32_t dir);
    void SwapPacketHeaderFoo(void);

    // FIXIT - these 2 function names convey no meaning afaict... figure out
    // why are they called and name appropriately...
    void retransmit_process(Packet* p)
    {
        // Data has already been analyzed so don't bother looking at it again.
        DisableDetect(p);
    }

    void retransmit_handle(Packet* p)
    {
        flow->call_handlers(p, false);
    }

    void reset(void);
    void flush(void);
    void start_proxy(void);
    static void set_memcap(class Memcap&);
    static void sinit(void);
    static void sterm(void);
    void update_session_on_server_packet(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd);
    void update_session_on_client_packet(TcpSegmentDescriptor& tsd);
    bool handle_syn_on_reset_session(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd);
    void update_ignored_session(TcpSegmentDescriptor& tsd);

    TcpEventLogger* tel;
    TcpStreamConfig* config;
    TcpTracker* client;
    TcpTracker* server;
    uint8_t ecn;
    bool lws_init;
    bool tcp_init;

    int32_t ingress_index; /* Index of the inbound interface. */
    int32_t ingress_group; /* Index of the inbound group. */
    int32_t egress_index; /* Index of the outbound interface. */
    int32_t egress_group; /* Index of the outbound group. */
    uint32_t daq_flags; /* Flags for the packet (DAQ_PKT_FLAG_*) */
    uint16_t address_space_id;

    uint32_t pkt_action_mask;
    bool require_3whs;
    bool no_3whs;

    // FIXIT - deprecate this once tcp state machine is fully implemented
    bool new_ssn;

private:
    void EndOfFileHandle(Packet* p);
    bool flow_exceeds_config_thresholds(TcpTracker* rcv, TcpSegmentDescriptor& tsd);
    void process_tcp_stream(TcpTracker* rcv, TcpSegmentDescriptor& tsd);
    int process_tcp_data(TcpTracker* listener, TcpSegmentDescriptor& tsd);
    void process_tcp_packet(TcpSegmentDescriptor&);
    void FinishServerInit(TcpSegmentDescriptor& tsd);
    void swap_trackers(void);

    void NewTcpSessionOnSyn(TcpSegmentDescriptor&);
    void NewTcpSessionOnSynAck(TcpSegmentDescriptor&);
    void set_os_policy(void);

    void cleanup_session(int freeApplicationData, Packet* p = nullptr);
    void clear_session(int freeApplicationData);

    int process_dis(Packet*);
    void handle_data_on_syn(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd);

    TcpTracker* talker;
    TcpTracker* listener;
    TcpStateMachine tsm;
};

#endif

