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

// tcp_normalization.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_normalizer.h"

#include "main/snort_debug.h"
#include "packet_io/active.h"

THREAD_LOCAL PegCount tcp_norm_stats[PC_TCP_MAX][NORM_MODE_MAX];

static const PegInfo pegName[] =
{
    { "tcp_trim_syn", "tcp segments trimmed on SYN" },
    { "tcp_trim_rst", "RST packets with data trimmed" },
    { "tcp_trim_win", "data trimmed to window" },
    { "tcp_trim_mss", "data trimmed to MSS" },
    { "tcp_ecn_session", "ECN bits cleared" },
    { "tcp_ts_nop", "timestamp options cleared" },
    { "tcp_ips_data", "normalized segments" },
    { "tcp_block", "blocked segments" },
    { nullptr, nullptr }
};

#if 0
static inline int SetupOK(const TcpStreamTracker* st)
{
    return ((st->s_mgr.sub_state & SUB_SETUP_OK) == SUB_SETUP_OK);
}

int strip = ( SetupOK(peer_tracker) && SetupOK(tracker) );
DebugMessage(DEBUG_STREAM_STATE, "listener not doing timestamps...\n");
#endif

TcpNormalizer::TcpNormalizer(StreamPolicy os_policy, TcpSession* session,
    TcpStreamTracker* tracker) :
    os_policy(os_policy), session(session), tracker(tracker)
{
    tcp_ips_enabled = Normalize_IsEnabled(NORM_TCP_IPS);
    trim_syn = Normalize_GetMode(NORM_TCP_TRIM_SYN);
    trim_rst = Normalize_GetMode(NORM_TCP_TRIM_RST);
    trim_win = Normalize_GetMode(NORM_TCP_TRIM_WIN);
    trim_mss = Normalize_GetMode(NORM_TCP_TRIM_MSS);
    strip_ecn = Normalize_GetMode(NORM_TCP_ECN_STR);
    tcp_block = Normalize_GetMode(NORM_TCP_BLOCK);
    opt_block = Normalize_GetMode(NORM_TCP_OPT);
}

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
    TcpSegmentDescriptor& tsd, uint32_t max, NormMode mode, TcpPegCounts peg)
{
    if (mode == NORM_MODE_ON)
    {
        uint16_t fat = tsd.get_seg_len() - max;
        tsd.set_seg_len(max);
        tsd.get_pkt()->packet_flags |= (PKT_MODIFIED | PKT_RESIZED);
        tsd.set_end_seq(tsd.get_end_seq() - fat);
    }

    tcp_norm_stats[peg][mode]++;
}

bool TcpNormalizer::strip_tcp_timestamp(
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

bool TcpNormalizer::packet_dropper(TcpSegmentDescriptor& tsd, NormFlags f)
{
    const NormMode mode = (f == NORM_TCP_BLOCK) ? tcp_block : opt_block;

    tcp_norm_stats[PC_TCP_BLOCK][mode]++;

    if (mode == NORM_MODE_ON)
    {
        Active::drop_packet(tsd.get_pkt());
        return true;
    }

    return false;
}

void TcpNormalizer::trim_syn_payload(TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tsd, max, trim_syn, PC_TCP_TRIM_SYN);
}

void TcpNormalizer::trim_rst_payload(TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tsd, max, trim_rst, PC_TCP_TRIM_RST);
}

void TcpNormalizer::trim_win_payload(TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tsd, max, trim_win, PC_TCP_TRIM_WIN);
}

void TcpNormalizer::trim_mss_payload(TcpSegmentDescriptor& tsd, uint32_t max)
{
    if (tsd.get_seg_len() > max)
        trim_payload(tsd, max, trim_mss, PC_TCP_TRIM_MSS);
}

void TcpNormalizer::ecn_tracker(const tcp::TCPHdr* tcph, bool req3way)
{
    if ( tcph->is_syn_ack() )
    {
        if ( !req3way || session->ecn )
            session->ecn = ((tcph->th_flags & (TH_ECE | TH_CWR)) == TH_ECE);
    }
    else if ( tcph->is_syn() )
        session->ecn = tcph->are_flags_set(TH_ECE | TH_CWR);
}

void TcpNormalizer::ecn_stripper(Packet* p)
{
    if (!session->ecn && (p->ptrs.tcph->th_flags & (TH_ECE | TH_CWR)))
    {
        if (strip_ecn == NORM_MODE_ON)
        {
            ((tcp::TCPHdr*)p->ptrs.tcph)->th_flags &= ~(TH_ECE | TH_CWR);
            p->packet_flags |= PKT_MODIFIED;
        }

        tcp_norm_stats[PC_TCP_ECN_SSN][strip_ecn]++;
    }
}

// don't use the window if we may have missed scaling
// one way zero window is uninitialized
// two way zero window is actually closed (regardless of scaling)
uint32_t TcpNormalizer::get_stream_window(TcpSegmentDescriptor& tsd)
{
    int32_t window;

    if ( tracker->get_snd_wnd() )
    {
        if ( !(session->flow->session_state & STREAM_STATE_MIDSTREAM ) )
            return tracker->get_snd_wnd();
    }
    else if ( session->flow->two_way_traffic() )
        return tracker->get_snd_wnd();

    // ensure the data is in the window
    window = tsd.get_end_seq() - tracker->r_win_base;
    if ( window < 0 )
        window = 0;

    return (uint32_t)window;
}

uint32_t TcpNormalizer::get_tcp_timestamp(TcpSegmentDescriptor& tsd, bool strip)
{
    DebugMessage(DEBUG_STREAM_STATE, "Getting timestamp...\n");

    tcp::TcpOptIterator iter(tsd.get_tcph(), tsd.get_pkt() );

    // using const because non-const is not supported
    for ( const tcp::TcpOption& opt : iter )
    {
        if ( opt.code == tcp::TcpOptCode::TIMESTAMP )
        {
            bool stripped = false;

            if (strip)
                stripped = strip_tcp_timestamp(tsd, &opt, opt_block);

            if (!stripped)
            {
                tsd.set_ts(extract_32bits(opt.data) );
                DebugFormat(DEBUG_STREAM_STATE, "Found timestamp %u\n", tsd.get_ts());
                return TF_TSTAMP;
            }
        }
    }
    tsd.set_ts(0);

    DebugMessage(DEBUG_STREAM_STATE, "No timestamp...\n");

    return TF_NONE;
}

bool TcpNormalizer::validate_rst_seq_geq(TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
        tsd.get_end_seq(), tracker->r_win_base, tsd.get_seg_seq(), tracker->r_nxt_ack +
        get_stream_window(tsd));

    // FIXIT-H check for r_win_base == 0 is hack for uninitialized r_win_base, fix this
    if ( ( tracker->r_nxt_ack == 0 ) || SEQ_GEQ(tsd.get_seg_seq(), tracker->r_nxt_ack) )
    {
        DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (>= next seq)!\n");
        return true;
    }

    DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (>= next seq)!\n");
    return false;
}

bool TcpNormalizer::validate_rst_end_seq_geq(TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
        tsd.get_end_seq(), tracker->r_win_base, tsd.get_seg_seq(), tracker->r_nxt_ack +
        get_stream_window(tsd));

    // FIXIT-H check for r_win_base == 0 is hack for uninitialized r_win_base, fix this
    if ( tracker->r_win_base == 0 )
        return true;

    if ( SEQ_GEQ(tsd.get_end_seq(), tracker->r_win_base))
    {
        // reset must be admitted when window closed
        if (SEQ_LEQ(tsd.get_seg_seq(), tracker->r_win_base + get_stream_window(tsd)))
        {
            DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (within window)!\n");
            return true;
        }
    }

    DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (within window)!\n");
    return false;
}

bool TcpNormalizer::validate_rst_seq_eq(TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
        tsd.get_end_seq(), tracker->r_win_base, tsd.get_seg_seq(), tracker->r_nxt_ack +
        get_stream_window(tsd));

    // FIXIT-H check for r_nxt_ack == 0 is hack for uninitialized r_nxt_ack, fix this
    if ( ( tracker->r_nxt_ack == 0 ) || SEQ_EQ(tsd.get_seg_seq(), tracker->r_nxt_ack) )
    {
        DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (next seq)!\n");
        return true;
    }

    DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (next seq)!\n");
    return false;
}

// per rfc 793 a rst is valid if the seq number is in window
// for all states but syn-sent (handled above).  however, we
// validate here based on how various implementations actually
// handle a rst.
bool TcpNormalizer::validate_rst(TcpSegmentDescriptor& tsd)
{
    return validate_rst_seq_eq(tsd);
}

int TcpNormalizer::validate_paws_timestamp(TcpSegmentDescriptor& tsd)
{
    if ( ( (int)( ( tsd.get_ts() - peer_tracker->get_ts_last() ) + paws_ts_fudge ) ) < 0 )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Packet outside PAWS window, dropping\n");
        /* bail, we've got a packet outside the PAWS window! */
        //inc_tcp_discards();
        ( ( TcpSession* )tsd.get_flow()->session )->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
        packet_dropper(tsd, NORM_TCP_OPT);
        return ACTION_BAD_PKT;
    }
    else if ( ( peer_tracker->get_ts_last() != 0 )
        && ( ( uint32_t )tsd.get_pkt()->pkth->ts.tv_sec > peer_tracker->get_ts_last_packet() +
        PAWS_24DAYS ) )
    {
        /* this packet is from way too far into the future */
        DebugFormat(DEBUG_STREAM_STATE,
            "packet PAWS timestamp way too far ahead of last packet %ld %u...\n",
            tsd.get_pkt()->pkth->ts.tv_sec, peer_tracker->get_ts_last_packet() );
        //inc_tcp_discards();
        ( ( TcpSession* )tsd.get_flow()->session )->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
        packet_dropper(tsd, NORM_TCP_OPT);
        return ACTION_BAD_PKT;
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "packet PAWS ok...\n");
        return ACTION_NOTHING;
    }
}

bool TcpNormalizer::is_paws_ts_checked_required(TcpSegmentDescriptor&)
{
    return true;
}

int TcpNormalizer::validate_paws(TcpSegmentDescriptor& tsd)
{
    tcp_ts_flags = get_tcp_timestamp(tsd, false);
    if ( tcp_ts_flags )
    {
        bool check_ts = is_paws_ts_checked_required(tsd);

        if ( check_ts )
            return validate_paws_timestamp(tsd);
        else
            return ACTION_NOTHING;
    }
    else
    {
        // we've got a packet with no timestamp, but 3whs indicated talker was doing
        //  timestamps.  This breaks protocol, however, some servers still ack the packet
        //   with the missing timestamp.  Log an alert, but continue to process the packet
        DebugMessage(DEBUG_STREAM_STATE,
            "packet no timestamp, had one earlier from this side...ok for now...\n");
        ( ( TcpSession* )tsd.get_flow()->session )->tel.set_tcp_event(EVENT_NO_TIMESTAMP);

        /* Ignore the timestamp for this first packet, next one will checked. */
        if ( session->config->policy == StreamPolicy::OS_SOLARIS )
            tracker->clear_tf_flags(TF_TSTAMP);

        packet_dropper(tsd, NORM_TCP_OPT);
        return ACTION_NOTHING;
    }
}

int TcpNormalizer::handle_paws_no_timestamps(TcpSegmentDescriptor& tsd)
{
    tcp_ts_flags = get_tcp_timestamp(tsd, true);
    if (tcp_ts_flags)
    {
        if (!(peer_tracker->get_tf_flags() & TF_TSTAMP))
        {
            // SYN skipped, may have missed talker's timestamp , so set it now.
            if (tsd.get_ts() == 0)
                peer_tracker->set_tf_flags(TF_TSTAMP | TF_TSTAMP_ZERO);
            else
                peer_tracker->set_tf_flags(TF_TSTAMP);
        }

        // Only valid to test this if listener is using timestamps. Otherwise, timestamp
        // in this packet is not used, regardless of its value.
        if ( ( paws_drop_zero_ts && ( tsd.get_ts() == 0 ) ) && ( tracker->get_tf_flags() &
            TF_TSTAMP ) )
        {
            DebugMessage(DEBUG_STREAM_STATE, "Packet with 0 timestamp, dropping\n");
            ( ( TcpSession* )tsd.get_flow()->session )->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
            return ACTION_BAD_PKT;
        }
    }

    return ACTION_NOTHING;
}

int TcpNormalizer::handle_paws(TcpSegmentDescriptor& tsd)
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

    if ((peer_tracker->get_tf_flags() & TF_TSTAMP) && (tracker->get_tf_flags() & TF_TSTAMP))
    {
        DebugMessage(DEBUG_STREAM_STATE, "Checking timestamps for PAWS\n");
        return validate_paws(tsd);
    }
    else if (tsd.get_tcph()->is_syn_only())
    {
        tcp_ts_flags = get_tcp_timestamp(tsd, false);
        if (tcp_ts_flags)
            peer_tracker->set_tf_flags(TF_TSTAMP);

        return ACTION_NOTHING;
    }
    else
    {
        return handle_paws_no_timestamps(tsd);
    }
}

uint16_t TcpNormalizer::set_urg_offset(const tcp::TCPHdr* tcph, uint16_t dsize)
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

