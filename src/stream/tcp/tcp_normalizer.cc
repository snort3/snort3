//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_normalization.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_normalizer.h"

#include "detection/detection_engine.h"
#include "packet_io/packet_tracer.h"
#include "stream/stream.h"
#include "trace/trace.h"
#include "trace/trace_api.h"

#include "tcp_session.h"
#include "tcp_stream_tracker.h"

using namespace snort;

TcpNormalizer::NormStatus TcpNormalizer::apply_normalizations(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t seq, bool stream_is_inorder)
{
    // drop packet if sequence num is invalid
    if ( !tns.tracker->is_segment_seq_valid(tsd) )
    {
        if ( is_keep_alive_probe(tns, tsd) )
            return NORM_BAD_SEQ;

        bool inline_mode = tsd.is_nap_policy_inline();
        tcpStats.invalid_seq_num++;
        log_drop_reason(tns, tsd, inline_mode, "stream", "Normalizer: Sequence number is invalid\n");
        trim_win_payload(tns, tsd, 0, inline_mode);
        return NORM_BAD_SEQ;
    }

    // trim to fit in listener's window and mss
    log_drop_reason(tns, tsd, false, "stream", "Normalizer: Trimming payload to fit window size\n");
    trim_win_payload(tns, tsd,
        (tns.tracker->r_win_base + tns.tracker->get_snd_wnd() - tns.tracker->rcv_nxt));

    if ( tns.tracker->get_mss() )
        trim_mss_payload(tns, tsd, tns.tracker->get_mss());

    ecn_stripper(tns, tsd);

    if ( stream_is_inorder )
    {
        bool inline_mode = tsd.is_nap_policy_inline();

        if ( get_stream_window(tns, tsd) == 0 )
        {
            if ( !data_inside_window(tns, tsd) )
            {
                log_drop_reason(tns, tsd, inline_mode, "stream", "Normalizer: Data is outside the TCP Window\n");
                trim_win_payload(tns, tsd, 0, inline_mode);
                return NORM_TRIMMED;
            }

            if ( tns.tracker->get_iss() )
            {
                tcpStats.zero_win_probes++;
                set_zwp_seq(tns, seq);
                log_drop_reason(tns, tsd, inline_mode, "stream", 
                    "Normalizer: Maximum Zero Window Probe length supported at a time is 1 byte\n");
                trim_win_payload(tns, tsd, MAX_ZERO_WIN_PROBE_LEN, inline_mode);
            }
        }
    }
    else if ( get_stream_window(tns, tsd) == 0 )
    {
        bool inline_mode = tsd.is_nap_policy_inline();

        if ( SEQ_EQ(seq, get_zwp_seq(tns)) )
        {
            tcpStats.zero_win_probes++;
            trim_win_payload(tns, tsd, MAX_ZERO_WIN_PROBE_LEN, inline_mode);
            log_drop_reason(tns, tsd, inline_mode, "stream", "Normalizer: Maximum Zero Window Probe length supported at a time is 1 byte\n");
            return NORM_TRIMMED;
        }

        log_drop_reason(tns, tsd, inline_mode, "stream", "Normalizer: Received data during a Zero Window that is not a Zero Window Probe\n");
        trim_win_payload(tns, tsd, 0, inline_mode);
        return NORM_TRIMMED;
    }

    return NORM_OK;
}

bool TcpNormalizer::trim_payload(TcpNormalizerState&, TcpSegmentDescriptor& tsd, uint32_t max,
    NormMode mode, PegCounts peg, bool force)
{
    if ( force )
        mode = NORM_MODE_ON;

    norm_stats[peg][mode]++;

    if ( mode == NORM_MODE_ON )
    {
        uint16_t fat = tsd.get_len() - max;
        tsd.set_len(max);
        tsd.set_packet_flags(PKT_RESIZED);
        tsd.set_end_seq(tsd.get_end_seq() - fat);
        return true;
    }
    return false;
}

bool TcpNormalizer::strip_tcp_timestamp(
    TcpNormalizerState&, TcpSegmentDescriptor& tsd, const tcp::TcpOption* opt, NormMode mode)
{
    norm_stats[PC_TCP_TS_NOP][mode]++;

    if (mode == NORM_MODE_ON)
    {
        // set raw option bytes to nops
        memset((void*)opt, (uint32_t)tcp::TcpOptCode::NOP, tcp::TCPOLEN_TIMESTAMP);
        tsd.set_packet_flags(PKT_MODIFIED);
        return true;
    }

    return false;
}

void TcpNormalizer::session_blocker(
    TcpNormalizerState&, TcpSegmentDescriptor& tsd)
{
    Packet *p = tsd.get_pkt();
    DetectionEngine::disable_all(p);
    p->active->block_session(p, true);
    p->active->set_drop_reason("stream");
    if (PacketTracer::is_active())
        {
            PacketTracer::log("Normalizer: TCP Zero Window Probe byte data mismatch\n");
        }
}

bool TcpNormalizer::packet_dropper(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, NormFlags f)
{
    if ( tsd.is_meta_ack_packet() )
        return false;

    const int8_t mode = (f == NORM_TCP_BLOCK) ? tns.tcp_block : tns.opt_block;

    norm_stats[PC_TCP_BLOCK][mode]++;

    if (mode == NORM_MODE_ON)
    {
        tsd.drop_packet();
        tcpStats.discards++;
        return true;
    }

    tcpStats.discards_skipped++;
    return false;
}

bool TcpNormalizer::trim_syn_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    uint32_t len = tsd.get_len();
    
    if (len > max)
    {
        if ( PacketTracer::is_active() && (NormMode)tns.trim_syn == NORM_MODE_ON )
            PacketTracer::log("Normalizer: Trimming payload of SYN packet with length (%u) to a maximum value of %u\n", len, max);

        return trim_payload(tns, tsd, max, (NormMode)tns.trim_syn, PC_TCP_TRIM_SYN);
    }
    return false;
}

void TcpNormalizer::trim_rst_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    uint32_t len = tsd.get_len();

    if (len > max)
    {
        if ( PacketTracer::is_active() && (NormMode)tns.trim_rst == NORM_MODE_ON )
            PacketTracer::log("Normalizer: Trimming payload of RST packet with length (%u) to a maximum value of %u\n", len, max);

        trim_payload(tns, tsd, max, (NormMode)tns.trim_rst, PC_TCP_TRIM_RST);
    }
}

void TcpNormalizer::trim_win_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max, bool force)
{
    uint32_t len = tsd.get_len();

    if (len > max)
    {
        if ( PacketTracer::is_active() && (force || (NormMode)tns.trim_win == NORM_MODE_ON) )
            PacketTracer::log("Normalizer: Trimming payload with length (%u) to a maximum value of %u\n", len, max);

        trim_payload(tns, tsd, max, (NormMode)tns.trim_win, PC_TCP_TRIM_WIN, force);
    }
}

void TcpNormalizer::trim_mss_payload(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, uint32_t max)
{
    uint32_t len = tsd.get_len();

    if (len > max)
    {
        if ( PacketTracer::is_active() && (NormMode)tns.trim_mss == NORM_MODE_ON )
            PacketTracer::log("Normalizer: Trimming payload with length (%u) to fit MSS size (%u)\n", len, max);

        trim_payload(tns, tsd, max, (NormMode)tns.trim_mss, PC_TCP_TRIM_MSS);
    }
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
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    const tcp::TCPHdr* tcph = tsd.get_tcph();
    if (!tns.session->ecn && (tcph->th_flags & (TH_ECE | TH_CWR)))
    {
        if (tns.strip_ecn == NORM_MODE_ON)
        {
            (const_cast<tcp::TCPHdr*>(tcph))->th_flags &= ~(TH_ECE | TH_CWR);
            tsd.set_packet_flags(PKT_MODIFIED);
        }

        norm_stats[PC_TCP_ECN_SSN][tns.strip_ecn]++;
    }
}

uint32_t TcpNormalizer::get_zwp_seq(
    TcpNormalizerState& tns)
{
    return tns.zwp_seq;
}

// don't use the window if we may have missed scaling
// one way zero window is uninitialized
// two way zero window is actually closed (regardless of scaling)
uint32_t TcpNormalizer::get_stream_window(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    if ( tns.tracker->get_snd_wnd() )
    {
        if ( !(tns.session->flow->session_state & STREAM_STATE_MIDSTREAM ) )
            return tns.tracker->get_snd_wnd();
    }
    else if ( tns.session->flow->two_way_traffic() )
        return tns.tracker->get_snd_wnd();

    // ensure the data is in the window
    return data_inside_window(tns, tsd);
}

uint32_t TcpNormalizer::data_inside_window(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    int32_t window = tsd.get_end_seq() - tns.tracker->r_win_base;
    if ( window < 0 )
        return 0;

    return (uint32_t) window;
}

uint32_t TcpNormalizer::get_tcp_timestamp(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd, bool strip)
{
    if ( tsd.is_meta_ack_packet() )
        return TF_NONE;

    if ( tsd.get_pkt()->ptrs.decode_flags & DECODE_TCP_TS )
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
                    tsd.set_timestamp(extract_32bits(opt.data) );
                    return TF_TSTAMP;
                }
            }
        }
    }
    tsd.set_timestamp(0);
    return TF_NONE;
}

bool TcpNormalizer::validate_rst_seq_geq(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    // FIXIT-M check for rcv_nxt == 0 is hack for uninitialized rcv_nxt
    if ( ( tns.tracker->rcv_nxt == 0 ) || SEQ_GEQ(tsd.get_seq(), tns.tracker->rcv_nxt) )
        return true;

    return false;
}

bool TcpNormalizer::validate_rst_end_seq_geq(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    // FIXIT-M check for r_win_base == 0 is hack for uninitialized r_win_base
    if ( tns.tracker->r_win_base == 0 )
        return true;

    if ( SEQ_GEQ(tsd.get_end_seq(), tns.tracker->r_win_base))
    {
        // reset must be admitted when window closed
        if (SEQ_LEQ(tsd.get_seq(), tns.tracker->r_win_base + get_stream_window(tns, tsd)))
            return true;
    }

    return false;
}

bool TcpNormalizer::validate_rst_seq_eq(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    uint32_t expected_seq = tns.tracker->r_win_base + tns.tracker->get_fin_seq_adjust();

    if ( SEQ_EQ(tsd.get_seq(), expected_seq) )
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
    const uint32_t peer_ts_last = tns.peer_tracker->get_ts_last();
    if ( peer_ts_last && ( ( (int)( ( tsd.get_timestamp() - peer_ts_last ) + tns.paws_ts_fudge ) ) < 0 ) )
    {
        if ( tsd.get_pkt()->is_retry() )
        {
            //  Retry packets can legitimately have old timestamps
            //  in TCP options (if a re-transmit comes in before
            //  the retry) so don't consider it an error.
            tsd.set_timestamp(tns.peer_tracker->get_ts_last());
            return ACTION_NOTHING;
        }
        else
        {
            /* bail, we've got a packet outside the PAWS window! */
            tns.session->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
            packet_dropper(tns, tsd, NORM_TCP_OPT);
            return ACTION_BAD_PKT;
        }
    }
    else if ( ( tns.peer_tracker->get_ts_last() != 0 )
        && ( ( uint32_t )tsd.get_packet_timestamp() > tns.peer_tracker->get_ts_last_packet() +
        PAWS_24DAYS ) )
    {
        /* this packet is from way too far into the future */
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
        if ( tns.session->tcp_config->policy == StreamPolicy::OS_SOLARIS )
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
            if (tsd.get_timestamp() == 0)
                tns.peer_tracker->set_tf_flags(TF_TSTAMP | TF_TSTAMP_ZERO);
            else
                tns.peer_tracker->set_tf_flags(TF_TSTAMP);
        }

        // Only valid to test this if listener is using timestamps. Otherwise, timestamp
        // in this packet is not used, regardless of its value.
        if ( ( tns.paws_drop_zero_ts && ( tsd.get_timestamp() == 0 ) ) &&
            ( tns.tracker->get_tf_flags() & TF_TSTAMP ) )
        {
            tns.session->tel.set_tcp_event(EVENT_BAD_TIMESTAMP);
            packet_dropper(tns, tsd, NORM_TCP_BLOCK);
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

void TcpNormalizer::set_zwp_seq(
    TcpNormalizerState& tns, uint32_t seq)
{
    tns.zwp_seq = seq;
}

void TcpNormalizer::log_drop_reason(TcpNormalizerState& tns, const TcpSegmentDescriptor& tsd, bool force, const char *issuer, const std::string& log)
{
    if ( force || (NormMode)tns.trim_win == NORM_MODE_ON )
    {
        tsd.get_pkt()->active->set_drop_reason(issuer);
        if (PacketTracer::is_active())
            PacketTracer::log("%s", log.c_str());
        if (stream_tcp_trace_enabled)
            trace_logf(TRACE_WARNING_LEVEL, stream_tcp_trace, DEFAULT_TRACE_OPTION_ID, tsd.get_pkt(), "%s", log.c_str());
    }
}

bool TcpNormalizer::is_keep_alive_probe(TcpNormalizerState& tns, const TcpSegmentDescriptor& tsd)
{
    if ( (tns.tracker->r_win_base - tsd.get_seq()) == MAX_KEEP_ALIVE_PROBE_LEN
        and tsd.get_len() <= MAX_KEEP_ALIVE_PROBE_LEN and 
        !(tsd.get_tcph()->th_flags & (TH_SYN|TH_FIN|TH_RST)) )
    {
        tcpStats.keep_alive_probes++;
        return true;
    }

    return false;
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

void TcpNormalizer::reset_stats()
{
    for (int i = TCP_PEGS_START; i < PC_MAX; i++)
        for (int j = 0; j < NORM_MODE_MAX; j++)
            norm_stats[i][j] = 0;
}
