//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// tcp_normalizers.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 22, 2015

#ifndef TCP_NORMALIZERS_H
#define TCP_NORMALIZERS_H

#include "stream/tcp/tcp_normalizer.h"

class TcpStreamSession;
class TcpStreamSession;

class TcpNormalizerFactory
{
public:
    static TcpNormalizer* create(StreamPolicy);
};

class TcpNormalizerPolicy
{
public:
    TcpNormalizerPolicy() = default;
    ~TcpNormalizerPolicy() = default;

    void init(StreamPolicy os, TcpStreamSession* ssn, TcpStreamTracker* trk, TcpStreamTracker* peer);
    void reset()
    { init(StreamPolicy::OS_INVALID, nullptr, nullptr, nullptr); }

    bool packet_dropper(TcpSegmentDescriptor& tsd, NormFlags nflags)
    { return norm->packet_dropper(tns, tsd, nflags); }

    void trim_syn_payload(TcpSegmentDescriptor& tsd, uint32_t max = 0)
    { norm->trim_syn_payload(tns, tsd, max); }

    void trim_rst_payload(TcpSegmentDescriptor& tsd, uint32_t max = 0)
    { norm->trim_rst_payload(tns, tsd, max); }

    void trim_win_payload(TcpSegmentDescriptor& tsd, uint32_t max = 0)
    { norm->trim_win_payload(tns, tsd, max); }

    void trim_mss_payload(TcpSegmentDescriptor& tsd, uint32_t max = 0)
    { norm->trim_mss_payload(tns, tsd, max); }

    void ecn_tracker(const snort::tcp::TCPHdr* tcph, bool req3way)
    { norm->ecn_tracker(tns, tcph, req3way); }

    void ecn_stripper(snort::Packet* p)
    { norm->ecn_stripper(tns, p); }

    uint32_t get_stream_window(TcpSegmentDescriptor& tsd)
    { return norm->get_stream_window(tns, tsd); }

    uint32_t get_tcp_timestamp(TcpSegmentDescriptor& tsd, bool strip)
    { return norm->get_tcp_timestamp(tns, tsd, strip); }

    int handle_paws(TcpSegmentDescriptor& tsd)
    { return norm->handle_paws(tns, tsd); }

    bool validate_rst(TcpSegmentDescriptor& tsd)
    { return norm->validate_rst(tns, tsd); }

    int handle_repeated_syn(TcpSegmentDescriptor& tsd)
    { return norm->handle_repeated_syn(tns, tsd); }

    uint16_t set_urg_offset(const snort::tcp::TCPHdr* tcph, uint16_t dsize)
    { return norm->set_urg_offset(tns, tcph, dsize); }

    StreamPolicy get_os_policy() const
    { return tns.os_policy; }

    bool is_paws_drop_zero_ts() const
    { return tns.paws_drop_zero_ts; }

    int32_t get_paws_ts_fudge() const
    { return tns.paws_ts_fudge; }

    int8_t get_opt_block() const
    { return tns.opt_block; }

    int8_t get_strip_ecn() const
    { return tns.strip_ecn; }

    int8_t get_tcp_block() const
    { return tns.tcp_block; }

    int8_t get_trim_rst() const
    { return tns.trim_rst; }

    int8_t get_trim_syn() const
    { return tns.trim_syn; }

    int8_t get_trim_mss() const
    { return tns.trim_mss; }

    int8_t get_trim_win() const
    { return tns.trim_win; }

    bool is_tcp_ips_enabled() const
    { return tns.tcp_ips_enabled; }

    bool handling_timestamps() const
    { return tns.tcp_ts_flags != TF_NONE; }

    uint32_t get_timestamp_flags()
    { return tns.tcp_ts_flags; }

private:
    TcpNormalizer* norm = nullptr;
    TcpNormalizerState tns;
};

#endif

