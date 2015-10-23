//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "packet_io/active.h"

#include "tcp_normalizer.h"
#include "tcp_events.h"

THREAD_LOCAL PegCount normStats[PC_MAX][NORM_MODE_MAX];

static const PegInfo pegName[] =
{
    { "tcp trim syn", "tcp segments trimmed on SYN" },
    { "tcp trim rst", "RST packets with data trimmed" },
    { "tcp trim win", "data trimed to window" },
    { "tcp trim mss", "data trimmed to MSS" },
    { "tcp ecn session", "ECN bits cleared" },
    { "tcp ts nop", "timestamp options cleared" },
    { "tcp ips data", "normalized segments" },
    { "tcp block", "blocked segments" },
    { nullptr, nullptr }
};

static inline int SetupOK(const TcpTracker* st)
{
    return ((st->s_mgr.sub_state & SUB_SETUP_OK) == SUB_SETUP_OK);
}

TcpNormalizer::TcpNormalizer( StreamPolicy os_policy, TcpSession* session, TcpTracker* tracker ) :
              os_policy( os_policy ), session( session ), tracker( tracker ),
              peer_tracker( nullptr )
{
    tcp_ips_enabled = Normalize_IsEnabled( NORM_TCP_IPS );
    trim_syn = Normalize_GetMode( NORM_TCP_TRIM_SYN );
    trim_rst = Normalize_GetMode( NORM_TCP_TRIM_RST );
    trim_win = Normalize_GetMode( NORM_TCP_TRIM_WIN );
    trim_mss = Normalize_GetMode( NORM_TCP_TRIM_MSS );
    strip_ecn = Normalize_GetMode( NORM_TCP_ECN_STR );
    tcp_block = Normalize_GetMode( NORM_TCP_BLOCK );
    opt_block = Normalize_GetMode( NORM_TCP_OPT );

    paws_ts_fudge = 0;
    paws_drop_zero_ts = true;
}

const PegInfo* TcpNormalizer::get_normalization_pegs()
{
    return pegName;
}

NormPegs TcpNormalizer::get_normalization_counts(unsigned& c)
{
    c = PC_MAX;
    return normStats;
}

void TcpNormalizer::trim_payload(TcpDataBlock* tdb, uint32_t max, NormMode mode, PegCounts peg, PerfCounts perf)
{
    if (mode == NORM_MODE_ON)
    {
         uint16_t fat = tdb->pkt->dsize - max;
         tdb->pkt->dsize = max;
         tdb->pkt->packet_flags |= (PKT_MODIFIED | PKT_RESIZED);
         tdb->end_seq -= fat;
    }

    normStats[peg][mode]++;
    sfBase.iPegs[perf][mode]++;
}

bool TcpNormalizer::strip_tcp_timestamp(TcpDataBlock* tdb, const tcp::TcpOption* opt, NormMode mode)
{
     normStats[PC_TCP_TS_NOP][mode]++;
     sfBase.iPegs[PERF_COUNT_TCP_TS_NOP][mode]++;

     if (mode == NORM_MODE_ON)
     {
         // set raw option bytes to nops
         memset((void *) opt, (uint32_t) tcp::TcpOptCode::NOP, tcp::TCPOLEN_TIMESTAMP);
         tdb->pkt->packet_flags |= PKT_MODIFIED;
         return true;
     }

     return false;
 }
bool TcpNormalizer::packet_dropper(TcpDataBlock* tdb, NormFlags f)
{
    const NormMode mode = (f == NORM_TCP_BLOCK) ? tcp_block : opt_block;

    normStats[PC_TCP_BLOCK][mode]++;
    sfBase.iPegs[PERF_COUNT_TCP_BLOCK][mode]++;

    if (mode == NORM_MODE_ON)
    {
        Active::drop_packet(tdb->pkt);
        return true;
    }

    return false;
}

void TcpNormalizer::trim_syn_payload(TcpDataBlock* tdb, uint32_t max)
{
    if (tdb->pkt->dsize > max)
        trim_payload(tdb, max, trim_syn, PC_TCP_TRIM_SYN, PERF_COUNT_TCP_TRIM_SYN);
}

void TcpNormalizer::trim_rst_payload(TcpDataBlock* tdb, uint32_t max)
{
    if (tdb->pkt->dsize > max)
        trim_payload(tdb, max, trim_rst, PC_TCP_TRIM_RST, PERF_COUNT_TCP_TRIM_RST);
}

void TcpNormalizer::trim_win_payload(TcpDataBlock* tdb, uint32_t max)
{
    if (tdb->pkt->dsize > max)
        trim_payload(tdb, max, trim_win, PC_TCP_TRIM_WIN, PERF_COUNT_TCP_TRIM_WIN);
}

void TcpNormalizer::trim_mss_payload(TcpDataBlock* tdb, uint32_t max)
{
    if (tdb->pkt->dsize > max)
        trim_payload(tdb, max, trim_mss, PC_TCP_TRIM_MSS, PERF_COUNT_TCP_TRIM_MSS);
}

void TcpNormalizer::ecn_tracker( tcp::TCPHdr* tcph, bool req3way )
{
    if( tcph->is_syn_ack() )
    {
        if( !req3way || session->ecn )
            session->ecn = ((tcph->th_flags & (TH_ECE | TH_CWR)) == TH_ECE);
    }
    else if( tcph->is_syn() )
        session->ecn = tcph->are_flags_set(TH_ECE | TH_CWR);
}

void TcpNormalizer::ecn_stripper( Packet* p )
{
    if (!session->ecn && (p->ptrs.tcph->th_flags & (TH_ECE | TH_CWR)))
    {
        if (strip_ecn == NORM_MODE_ON)
        {
            ((tcp::TCPHdr*) p->ptrs.tcph)->th_flags &= ~(TH_ECE | TH_CWR);
            p->packet_flags |= PKT_MODIFIED;
        }

        normStats[PC_TCP_ECN_SSN][strip_ecn]++;
        sfBase.iPegs[PERF_COUNT_TCP_ECN_SSN][strip_ecn]++;
    }
}

// don't use the window if we may have missed scaling
// one way zero window is unitialized
// two way zero window is actually closed (regardless of scaling)
uint32_t TcpNormalizer::get_stream_window( TcpDataBlock* tdb )
{
    int32_t window;

    if( tracker->l_window )
    {
        if( !(session->flow->session_state & STREAM_STATE_MIDSTREAM ) )
            return tracker->l_window;
    }
    else if( session->flow->two_way_traffic() )
        return tracker->l_window;

    // ensure the data is in the window
    window = tdb->end_seq - tracker->r_win_base;
    if (window < 0)
        window = 0;

    return (uint32_t) window;
}

uint32_t TcpNormalizer::get_tcp_timestamp(TcpDataBlock* tdb, bool strip)
{
    DebugMessage(DEBUG_STREAM_STATE, "Getting timestamp...\n");

    tcp::TcpOptIterator iter(tdb->pkt->ptrs.tcph, tdb->pkt);

    // using const because non-const is not supported
    for (const tcp::TcpOption& opt : iter)
    {
        if (opt.code == tcp::TcpOptCode::TIMESTAMP)
        {
            bool stripped = false;

            if (strip)
                stripped = strip_tcp_timestamp(tdb, &opt, opt_block);

            if(!stripped)
            {
                tdb->ts = EXTRACT_32BITS(opt.data);
                DebugFormat(DEBUG_STREAM_STATE, "Found timestamp %lu\n", tdb->ts);
                return TF_TSTAMP;
            }
        }
    }
    tdb->ts = 0;

    DebugMessage(DEBUG_STREAM_STATE, "No timestamp...\n");

    return TF_NONE;
}

bool TcpNormalizer::validate_rst_seq_geq( TcpDataBlock* tdb )
{
    DebugFormat(DEBUG_STREAM_STATE, "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
            tdb->end_seq, tracker->r_win_base, tdb->seq, tracker->r_nxt_ack + get_stream_window( tdb ));

    if (SEQ_GEQ(tdb->seq, tracker->r_nxt_ack))
    {
        DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (>= next seq)!\n");
        return true;
    }

    DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (>= next seq)!\n");
    return false;
}

bool TcpNormalizer::validate_rst_end_seq_geq( TcpDataBlock* tdb )
{
    DebugFormat(DEBUG_STREAM_STATE, "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
            tdb->end_seq, tracker->r_win_base, tdb->seq, tracker->r_nxt_ack + get_stream_window( tdb ));

    if (SEQ_GEQ(tdb->end_seq, tracker->r_win_base))
     {
         // reset must be admitted when window closed
         if (SEQ_LEQ(tdb->seq, tracker->r_win_base + get_stream_window( tdb )))
         {
             DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (within window)!\n");
             return true;
         }
     }

     DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (within window)!\n");
     return false;
}

bool TcpNormalizer::validate_rst_seq_eq( TcpDataBlock* tdb )
{
    DebugFormat(DEBUG_STREAM_STATE, "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
            tdb->end_seq, tracker->r_win_base, tdb->seq, tracker->r_nxt_ack + get_stream_window( tdb ));

    if (SEQ_EQ(tdb->seq, tracker->r_nxt_ack))
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
bool TcpNormalizer::validate_rst( TcpDataBlock* tdb )
{
    return validate_rst_seq_eq( tdb );
}

int TcpNormalizer::validate_paws_timestamp( TcpDataBlock* tdb, int* eventcode )
{
    if( ( (int) ( ( tdb->ts - peer_tracker->ts_last ) + paws_ts_fudge ) ) < 0 )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Packet outside PAWS window, dropping\n");
        /* bail, we've got a packet outside the PAWS window! */
        //inc_tcp_discards();
        *eventcode |= EVENT_BAD_TIMESTAMP;
        packet_dropper(tdb, NORM_TCP_OPT);
        return ACTION_BAD_PKT;
    }
    else if( ( peer_tracker->ts_last != 0 )
            && ( ( uint32_t ) tdb->pkt->pkth->ts.tv_sec > peer_tracker->ts_last_pkt + PAWS_24DAYS ) )
    {
        /* this packet is from way too far into the future */
        DebugFormat(DEBUG_STREAM_STATE, "packet PAWS timestamp way too far ahead of last packet %d %d...\n",
                tdb->pkt->pkth->ts.tv_sec, peer_tracker->ts_last_pkt);
        //inc_tcp_discards();
        *eventcode |= EVENT_BAD_TIMESTAMP;
        packet_dropper(tdb, NORM_TCP_OPT);
        return ACTION_BAD_PKT;
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "packet PAWS ok...\n");
        return ACTION_NOTHING;
    }
}

bool TcpNormalizer::is_paws_ts_checked_required( TcpDataBlock* )
{
    return true;
}

int TcpNormalizer::validate_paws( TcpDataBlock* tdb, int* eventcode, int* got_ts )
{
    *got_ts = get_tcp_timestamp(tdb, false);
    if (*got_ts)
    {
        bool check_ts = is_paws_ts_checked_required( tdb );

        if (check_ts)
            return validate_paws_timestamp( tdb, eventcode );
        else
            return ACTION_NOTHING;
    }
    else
    {
        // we've got a packet with no timestamp, but 3whs indicated talker was doing
        //  timestamps.  This breaks protocol, however, some servers still ack the packet
        //   with the missing timestamp.  Log an alert, but continue to process the packet
        DebugMessage(DEBUG_STREAM_STATE, "packet no timestamp, had one earlier from this side...ok for now...\n");
        *eventcode |= EVENT_NO_TIMESTAMP;

        /* Ignore the timestamp for this first packet, next one will checked. */
        if (tracker->config->policy == StreamPolicy::OS_SOLARIS)
            tracker->flags &= ~TF_TSTAMP;

        packet_dropper(tdb, NORM_TCP_OPT);
        return ACTION_NOTHING;
    }
}

int TcpNormalizer::handle_paws_no_timestamps(TcpDataBlock* tdb, int* eventcode, int* got_ts)
{
    // if we are not handling timestamps, and this isn't a syn (only), and we have seen a
    // valid 3way setup, then we strip (nop) the timestamp option.  this includes the cases
    // where we disable timestamp handling.
    int strip = ( SetupOK( peer_tracker ) && SetupOK( tracker ) );
    DebugMessage(DEBUG_STREAM_STATE, "listener not doing timestamps...\n");

    *got_ts = get_tcp_timestamp(tdb, strip);
    if (*got_ts)
    {
        if (!(peer_tracker->flags & TF_TSTAMP))
        {
            // SYN skipped, may have missed talker's timestamp , so set it now.
            peer_tracker->flags |= TF_TSTAMP;
            if (tdb->ts == 0)
                peer_tracker->flags |= TF_TSTAMP_ZERO;
        }

        // Only valid to test this if listener is using timestamps. Otherwise, timestamp
        // in this packet is not used, regardless of its value.
        if ( ( paws_drop_zero_ts && ( tdb->ts == 0 ) ) && ( tracker->flags & TF_TSTAMP ) )
        {
            DebugMessage(DEBUG_STREAM_STATE, "Packet with 0 timestamp, dropping\n");
            *eventcode |= EVENT_BAD_TIMESTAMP;
            return ACTION_BAD_PKT;
        }
    }

    return ACTION_NOTHING;
}

int TcpNormalizer::handle_paws(TcpDataBlock* tdb, int* eventcode, int* got_ts)
{
    if ( tdb->pkt->ptrs.tcph->is_rst() )
        return ACTION_NOTHING;

#if 0
    if ( tdb->pkt->ptrs.tcph->is_ack() && Normalize_IsEnabled(NORM_TCP_OPT) )
    {
        // FIXIT-L validate tsecr here (check that it was previously sent)
        // checking for the most recent ts is easy enough must check if
        // ts are up to date in retransmitted packets
    }
#endif

    if ((peer_tracker->flags & TF_TSTAMP) && (tracker->flags & TF_TSTAMP))
    {
        DebugMessage(DEBUG_STREAM_STATE, "Checking timestamps for PAWS\n");
        return validate_paws( tdb, eventcode, got_ts );
    }
    else if (tdb->pkt->ptrs.tcph->is_syn_only())
    {
        *got_ts = get_tcp_timestamp(tdb, 0);
        if (*got_ts)
            peer_tracker->flags |= TF_TSTAMP;

        return ACTION_NOTHING;
    }
    else
    {
        return handle_paws_no_timestamps( tdb, eventcode, got_ts );
    }
}

uint16_t TcpNormalizer::set_urg_offset( const tcp::TCPHdr* tcph, uint16_t dsize )
{
    uint16_t urg_offset = 0;

    if(tcph->are_flags_set( TH_URG) )
    {
        urg_offset = tcph->urp();

        // discard data from urgent pointer If urg pointer is beyond this packet,
        // it's treated as a 0
        if (urg_offset > dsize)
            urg_offset = 0;
    }

    return urg_offset;
}
