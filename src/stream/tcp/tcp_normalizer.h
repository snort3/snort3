//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// tcp_normalizer.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_NORMALIZER_H
#define TCP_NORMALIZER_H

#include "tcp_defs.h"

#include "main/thread.h"
#include "normalize/normalize.h"
#include "normalize/norm_stats.h"
#include "protocols/tcp_options.h"

class TcpStreamSession;
class TcpStreamTracker;
class TcpSegmentDescriptor;

struct TcpNormalizerState
{
    TcpStreamSession* session = nullptr;
    TcpStreamTracker* tracker = nullptr;
    TcpStreamTracker* peer_tracker = nullptr;

    StreamPolicy os_policy = StreamPolicy::OS_DEFAULT;

    int32_t paws_ts_fudge = 0;
    int tcp_ts_flags = 0;
    uint32_t zwp_seq = 0;

    int8_t trim_syn = 0;
    int8_t trim_rst = 0;
    int8_t trim_win = 0;
    int8_t trim_mss = 0;
    int8_t strip_ecn = 0;
    int8_t tcp_block = 0;
    int8_t opt_block = 0;

    bool tcp_ips_enabled = false;
    bool paws_drop_zero_ts = false;
};

class TcpNormalizer
{
public:
    using State = TcpNormalizerState;

    virtual ~TcpNormalizer() = default;

    virtual void init(State&) { }
    virtual void session_blocker(State&, TcpSegmentDescriptor&);
    virtual bool packet_dropper(State&, TcpSegmentDescriptor&, NormFlags);
    virtual bool trim_syn_payload(State&, TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void trim_rst_payload(State&, TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void trim_win_payload(State&, TcpSegmentDescriptor&, uint32_t max = 0,
        bool force = false);
    virtual void trim_mss_payload(State&, TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void ecn_tracker(State&, const snort::tcp::TCPHdr*, bool req3way);
    virtual void ecn_stripper(State&, TcpSegmentDescriptor&);
    virtual uint32_t get_zwp_seq(State&);
    virtual uint32_t get_stream_window(State&, TcpSegmentDescriptor&);
    virtual uint32_t get_tcp_timestamp(State&, TcpSegmentDescriptor&, bool strip);
    virtual int handle_paws(State&, TcpSegmentDescriptor&);
    virtual bool validate_rst(State&, TcpSegmentDescriptor&);
    virtual int handle_repeated_syn(State&, TcpSegmentDescriptor&) = 0;
    virtual uint16_t set_urg_offset(State&, const snort::tcp::TCPHdr* tcph, uint16_t dsize);
    virtual void set_zwp_seq(State&, uint32_t seq);

    static void reset_stats();

protected:
    TcpNormalizer() = default;

    virtual bool trim_payload(State&, TcpSegmentDescriptor&, uint32_t, NormMode, PegCounts,
        bool force = false);
    virtual bool strip_tcp_timestamp(
        State&, TcpSegmentDescriptor&, const snort::tcp::TcpOption*, NormMode);
    virtual bool validate_rst_seq_geq(State&, TcpSegmentDescriptor&);
    virtual bool validate_rst_end_seq_geq(State&, TcpSegmentDescriptor&);
    virtual bool validate_rst_seq_eq(State&, TcpSegmentDescriptor&);

    virtual int validate_paws_timestamp(State&, TcpSegmentDescriptor&);
    virtual bool is_paws_ts_checked_required(State&, TcpSegmentDescriptor&);
    virtual int validate_paws(State&, TcpSegmentDescriptor&);
    virtual int handle_paws_no_timestamps(State&, TcpSegmentDescriptor&);
};

#endif

