//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

// tcp_normalizer.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_NORMALIZER_H
#define TCP_NORMALIZER_H

#include "normalize/normalize.h"
#include "protocols/tcp_options.h"
#include "stream/tcp/tcp_session.h"

enum TcpPegCounts
{
    PC_TCP_TRIM_SYN,
    PC_TCP_TRIM_RST,
    PC_TCP_TRIM_WIN,
    PC_TCP_TRIM_MSS,
    PC_TCP_ECN_SSN,
    PC_TCP_TS_NOP,
    PC_TCP_IPS_DATA,
    PC_TCP_BLOCK,
    PC_TCP_MAX
};

extern THREAD_LOCAL PegCount tcp_norm_stats[PC_TCP_MAX][NORM_MODE_MAX];

class TcpNormalizer
{
public:

    virtual ~TcpNormalizer( ) { }

    virtual bool packet_dropper (TcpSegmentDescriptor&, NormFlags);
    virtual void trim_syn_payload(TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void trim_rst_payload(TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void trim_win_payload(TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void trim_mss_payload(TcpSegmentDescriptor&, uint32_t max = 0);
    virtual void ecn_tracker(const tcp::TCPHdr*, bool req3way);
    virtual void ecn_stripper(Packet*);
    virtual uint32_t get_stream_window(TcpSegmentDescriptor&);
    virtual uint32_t get_tcp_timestamp(TcpSegmentDescriptor&, bool strip);
    virtual int handle_paws(TcpSegmentDescriptor&);
    virtual bool validate_rst(TcpSegmentDescriptor&);
    virtual int handle_repeated_syn(TcpSegmentDescriptor&) = 0;
    virtual uint16_t set_urg_offset(const tcp::TCPHdr* tcph, uint16_t dsize);

    static const PegInfo* get_normalization_pegs();
    static NormPegs get_normalization_counts(unsigned&);

    void set_peer_tracker(TcpStreamTracker* peer_tracker)
    {
        this->peer_tracker = peer_tracker;
    }

    StreamPolicy get_os_policy() const
    {
        return os_policy;
    }

    bool is_paws_drop_zero_ts() const
    {
        return paws_drop_zero_ts;
    }

    int32_t get_paws_ts_fudge() const
    {
        return paws_ts_fudge;
    }

    NormMode get_opt_block() const
    {
        return opt_block;
    }

    NormMode get_strip_ecn() const
    {
        return strip_ecn;
    }

    NormMode get_tcp_block() const
    {
        return tcp_block;
    }

    NormMode get_trim_rst() const
    {
        return trim_rst;
    }

    NormMode get_trim_syn() const
    {
        return trim_syn;
    }

    NormMode get_trim_mss() const
    {
        return trim_mss;
    }

    NormMode get_trim_win() const
    {
        return trim_win;
    }

    bool is_tcp_ips_enabled() const
    {
        return tcp_ips_enabled;
    }

    bool handling_timestamps() const
    {
        return tcp_ts_flags != TF_NONE;
    }

    uint32_t get_timestamp_flags()
    {
        return tcp_ts_flags;
    }

protected:
    TcpNormalizer(StreamPolicy, TcpSession*, TcpStreamTracker*);
    virtual void trim_payload(TcpSegmentDescriptor&, uint32_t, NormMode, TcpPegCounts);
    virtual bool strip_tcp_timestamp(TcpSegmentDescriptor&, const tcp::TcpOption*, NormMode);
    virtual bool validate_rst_seq_geq(TcpSegmentDescriptor&);
    virtual bool validate_rst_end_seq_geq(TcpSegmentDescriptor&);
    virtual bool validate_rst_seq_eq(TcpSegmentDescriptor&);

    virtual int validate_paws_timestamp(TcpSegmentDescriptor&);
    virtual bool is_paws_ts_checked_required(TcpSegmentDescriptor&);
    virtual int validate_paws(TcpSegmentDescriptor&);
    virtual int handle_paws_no_timestamps(TcpSegmentDescriptor&);

    StreamPolicy os_policy;
    TcpSession* session = nullptr;
    TcpStreamTracker* tracker = nullptr;
    TcpStreamTracker* peer_tracker = nullptr;
    bool tcp_ips_enabled;
    NormMode trim_syn;
    NormMode trim_rst;
    NormMode trim_win;
    NormMode trim_mss;
    NormMode strip_ecn;
    NormMode tcp_block;
    NormMode opt_block;
    int32_t paws_ts_fudge = 0;
    bool paws_drop_zero_ts = true;
    int tcp_ts_flags = 0;
};

#endif

