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

// tcp_normalization.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_normalizer.h"

#include "stream/libtcp/tcp_stream_session.h"
#include "stream/libtcp/tcp_stream_tracker.h"

#include "packet_io/active.h"

using namespace snort;

THREAD_LOCAL PegCount tcp_norm_stats[PC_TCP_MAX][NORM_MODE_MAX];

static const PegInfo pegName[] =
{
    { CountType::SUM, "tcp_trim_syn", "tcp segments trimmed on SYN" },
    { CountType::SUM, "tcp_trim_rst", "RST packets with data trimmed" },
    { CountType::SUM, "tcp_trim_win", "data trimmed to window" },
    { CountType::SUM, "tcp_trim_mss", "data trimmed to MSS" },
    { CountType::SUM, "tcp_ecn_session", "ECN bits cleared" },
    { CountType::SUM, "tcp_ts_nop", "timestamp options cleared" },
    { CountType::SUM, "tcp_ips_data", "normalized segments" },
    { CountType::SUM, "tcp_block", "blocked segments" },
    { CountType::END, nullptr, nullptr }
};

const PegInfo* TcpNormalizer::get_normalization_pegs()
{
    return pegName;
}

NormPegs TcpNormalizer::get_normalization_counts(unsigned& c)
{
    c = PC_TCP_MAX;
    return tcp_norm_stats;
}

void TcpNormalizer::trim_payload(
    TcpNormalizerState&,
    TcpSegmentDescriptor& tsd, uint32_t max, NormMode mode, TcpPegCounts peg)
{
    if (mode == NORM_MODE_ON)
    {
        uint16_t fat = tsd.get_seg_len() - max;
        tsd.set_seg_len(max);
        tsd.get_pkt()->packet_flags |= PKT_RESIZED;
        tsd.set_end_seq(tsd.get_end_seq() - fat);
    }

    tcp_norm_stats[peg][mode]++;
}

bool TcpNormalizer::strip_tcp_timestamp(
    TcpNormalizerState&,
    TcpSegmentDescriptor& tsd, const tcp::TcpOption* opt, NormMode mode)
{
    tcp_norm_stats[PC_TCP_TS_NOP][mode]++;

    if (mode == NORM_MODE_ON)
    {
        // set raw option bytes to nops
        memset((void*)opt, (uint32_t)tcp::TcpOptCode::NOP, tcp::TCPOLEN_TIMESTAMP);
        tsd.get_pkt()->packet_flags |= PKT_MODIFIED;
        return true;
    }

    return false;
}

bool TcpNormalizer::packet_dropper(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, NormFlags f)
{
    const int8_t mode = (f == NORM_TCP_BLOCK) ? tns.tcp_block : tns.opt_block;

    tcp_norm_stats[PC_TCP_BLOCK][mode]++;

    if (mode == NORM_MODE_ON)
    {
        Active::drop_packet(tsd.get_pkt());
        return true;
    }

    return false;
}

void TcpNormalizer::trim_syn_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tns, tsd, max, (NormMode)tns.trim_syn, PC_TCP_TRIM_SYN);
}

void TcpNormalizer::trim_rst_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tns, tsd, max, (NormMode)tns.trim_rst, PC_TCP_TRIM_RST);
}

void TcpNormalizer::trim_win_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tns, tsd, max, (NormMode)tns.trim_win, PC_TCP_TRIM_WIN);
}

void TcpNormalizer::trim_mss_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tns, tsd, max, (NormMode)tns.trim_mss, PC_TCP_TRIM_MSS);
}

void TcpNormalizer::ecn_tracker(
    TcpNormalizerState& tns, const tcp::TCPHdr* tcph, bool req3way)
{
    if ( tcph->is_syn_ack() )
    {
        if ( !req3way || tns.session->ecn )
            tns.session->ecn = ((tcph->th_flags & (TH_ECE | TH_CWR)) == TH_ECE);
    }
    else if ( tcph->is_syn() )
        tns.session->ecn = tcph->are_flags_set(TH_ECE | TH_CWR);
}

void TcpNormalizer::ecn_stripper(
    TcpNormalizerState& tns, Packet* p)
{
    if (!tns.session->ecn && (p->ptrs.tcph->th_flags & (TH_ECE | TH_CWR)))
    {
        if (tns.strip_ecn == NORM_MODE_ON)
        {
            (const_cast<tcp::TCPHdr*>(p->ptrs.tcph))->th_flags &= ~(TH_ECE | TH_CWR);
            p->packet_flags |= PKT_MODIFIED;
        }

        tcp_norm_stats[PC_TCP_ECN_SSN][tns.strip_ecn]++;
    }
}

// don't use the window if we may have missed scaling
// one way zero window is uninitialized
// two way zero window is actually closed (regardless of scaling)
uint32_t TcpNormalizer::get_stream_window(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    int32_t window;

    if ( tns.tracker->get_snd_wnd() )
    {
        if ( !(tns.session->flow->session_state & STREAM_STATE_MIDSTREAM ) )
            return tns.tracker->get_snd_wnd();
    }
    else if ( tns.session->flow->two_way_traffic() )
        return tns.tracker->get_snd_wnd();

    // ensure the data is in the window
    window = tsd.get_end_seq() - tns.tracker->r_win_base;
    if ( window < 0 )
        window = 0;

    return (uint32_t)window;
}

uint32_t TcpNormalizer::get_tcp_timestamp(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, bool strip)
{
    tcp::TcpOptIterator iter(tsd.get_tcph(), tsd.get_pkt() );

    // using const because non-const is not supported
    for ( const tcp::TcpOption& opt : iter )
    {
        if ( opt.code == tcp::TcpOptCode::TIMESTAMP )
        {
            bool stripped = false;

            if (strip)
                stripped = strip_tcp_timestamp(tns, tsd, &opt, (NormMode)tns.opt_block);

            if (!stripped)
            {
                tsd.set_ts(extract_32bits(opt.data) );
                return TF_TSTAMP;
            }
        }
    }
    tsd.set_ts(0);

    return TF_NONE;
}

bool TcpNormalizer::validate_rst_seq_geq(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    // FIXIT-H check for rcv_nxt == 0 is hack for uninitialized rcv_nxt, fix this
    if ( ( tns.tracker->rcv_nxt == 0 ) || SEQ_GEQ(tsd.get_seg_seq(), tns.tracker->rcv_nxt) )
        return true;

    return false;
}

bool TcpNormalizer::validate_rst_end_seq_geq(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    // FIXIT-H check for r_win_base == 0 is hack for uninitialized r_win_base, fix this
    if ( tns.tracker->r_win_base == 0 )
        return true;

    if ( SEQ_GEQ(tsd.get_end_seq(), tns.tracker->r_win_base))
    {
        // reset must be admitted when window closed
        if (SEQ_LEQ(tsd.get_seg_seq(), tns.tracker->r_win_base + get_stream_window(tns, tsd)))
            return true;
    }

    return false;
}

bool TcpNormalizer::validate_rst_seq_eq(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    uint32_t expected_seq = tns.tracker->rcv_nxt + tns.tracker->get_fin_seq_adjust();

    // FIXIT-H check for rcv_nxt == 0 is hack for uninitialized rcv_nxt, fix this
    if ( ( tns.tracker->rcv_nxt == 0 ) || SEQ_EQ(tsd.get_seg_seq(), expected_seq) )
        return true;

    return false;
}

// per rfc 793 a rst is valid if the seq number is in window
// for all states but syn-sent (handled above).  however, we
// validate here based on how various implementations actually
// handle a rst.
bool TcpNormalizer::validate_rst(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return validate_rst_seq_eq(tns, tsd);
}

int TcpNormalizer::validate_paws_timestamp(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    if ( ( (int)( ( tsd.get_ts() - tns.peer_tracker->get_ts_last() ) + tns.paws_ts_fudge ) ) < 0 )
    {
        /* bail, we've got a packet outside the PAWS window! */
        //inc_tcp_discards();
        tns.session->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
        packet_dropper(tns, tsd, NORM_TCP_OPT);
        return ACTION_BAD_PKT;
    }
    else if ( ( tns.peer_tracker->get_ts_last() != 0 )
        && ( ( uint32_t )tsd.get_pkt()->pkth->ts.tv_sec > tns.peer_tracker->get_ts_last_packet() +
        PAWS_24DAYS ) )
    {
        /* this packet is from way too far into the future */
        //inc_tcp_discards();
        tns.session->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
        packet_dropper(tns, tsd, NORM_TCP_OPT);
        return ACTION_BAD_PKT;
    }
    else
        return ACTION_NOTHING;
}

bool TcpNormalizer::is_paws_ts_checked_required(
    TcpNormalizerState&, TcpSegmentDescriptor&)
{
    return true;
}

int TcpNormalizer::validate_paws(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    tns.tcp_ts_flags = get_tcp_timestamp(tns, tsd, false);
    if ( tns.tcp_ts_flags )
    {
        bool check_ts = is_paws_ts_checked_required(tns, tsd);

        if ( check_ts )
            return validate_paws_timestamp(tns, tsd);
        else
            return ACTION_NOTHING;
    }
    else
    {
        // we've got a packet with no timestamp, but 3whs indicated talker was doing
        //  timestamps.  This breaks protocol, however, some servers still ack the packet
        //   with the missing timestamp.  Log an alert, but continue to process the packet
        tns.session->tel.set_tcp_event(EVENT_NO_TIMESTAMP);

        /* Ignore the timestamp for this first packet, next one will checked. */
        if ( tns.session->config->policy == StreamPolicy::OS_SOLARIS )
            tns.tracker->clear_tf_flags(TF_TSTAMP);

        packet_dropper(tns, tsd, NORM_TCP_OPT);
        return ACTION_NOTHING;
    }
}

int TcpNormalizer::handle_paws_no_timestamps(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    tns.tcp_ts_flags = get_tcp_timestamp(tns, tsd, true);
    if (tns.tcp_ts_flags)
    {
        if (!(tns.peer_tracker->get_tf_flags() & TF_TSTAMP))
        {
            // SYN skipped, may have missed talker's timestamp , so set it now.
            if (tsd.get_ts() == 0)
                tns.peer_tracker->set_tf_flags(TF_TSTAMP | TF_TSTAMP_ZERO);
            else
                tns.peer_tracker->set_tf_flags(TF_TSTAMP);
        }

        // Only valid to test this if listener is using timestamps. Otherwise, timestamp
        // in this packet is not used, regardless of its value.
        if ( ( tns.paws_drop_zero_ts && ( tsd.get_ts() == 0 ) ) &&
            ( tns.tracker->get_tf_flags() & TF_TSTAMP ) )
        {
            tns.session->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
            return ACTION_BAD_PKT;
        }
    }

    return ACTION_NOTHING;
}

int TcpNormalizer::handle_paws(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    if ( tsd.get_tcph()->is_rst() )
        return ACTION_NOTHING;

#if 0
    if ( tsd.get_tcph()->is_ack() && Normalize_IsEnabled(NORM_TCP_OPT) )
    {
        // FIXIT-L validate tsecr here (check that it was previously sent)
        // checking for the most recent ts is easy enough must check if
        // ts are up to date in retransmitted packets
    }
#endif

    if ((tns.peer_tracker->get_tf_flags() & TF_TSTAMP) &&
        (tns.tracker->get_tf_flags() & TF_TSTAMP))
    {
        return validate_paws(tns, tsd);
    }
    else if (tsd.get_tcph()->is_syn_only())
    {
        tns.tcp_ts_flags = get_tcp_timestamp(tns, tsd, false);
        if (tns.tcp_ts_flags)
            tns.peer_tracker->set_tf_flags(TF_TSTAMP);

        return ACTION_NOTHING;
    }
    else
    {
        return handle_paws_no_timestamps(tns, tsd);
    }
}

uint16_t TcpNormalizer::set_urg_offset(
    TcpNormalizerState&, const tcp::TCPHdr* tcph, uint16_t dsize)
{
    uint16_t urg_offset = 0;

    if (tcph->are_flags_set(TH_URG) )
    {
        urg_offset = tcph->urp();

        // discard data from urgent pointer If urg pointer is beyond this packet,
        // it's treated as a 0
        if (urg_offset > dsize)
            urg_offset = 0;
    }

    return urg_offset;
}

