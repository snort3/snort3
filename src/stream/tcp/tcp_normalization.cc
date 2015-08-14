//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "tcp_normalization.h"
#include "tcp_events.h"

THREAD_LOCAL PegCount normStats[PC_MAX][NORM_MODE_MAX];

static const PegInfo pegName[] =
{ { "tcp trim syn", "tcp segments trimmed on SYN" },
  { "tcp trim rst", "RST packets with data trimmed" },
  { "tcp trim win", "data trimed to window" },
  { "tcp trim mss", "data trimmed to MSS" },
  { "tcp ecn session", "ECN bits cleared" },
  { "tcp ts nop", "timestamp options cleared" },
  { "tcp ips data", "normalized segments" },
  { "tcp block", "blocked segments" },
  { nullptr, nullptr }
};

const PegInfo* Stream_GetNormPegs()
{
    return pegName;
}

NormPegs Stream_GetNormCounts(unsigned& c)
{
    c = PC_MAX;
    return normStats;
}

static inline int SetupOK(const TcpTracker* st)
{
    return ((st->s_mgr.sub_state & SUB_SETUP_OK) == SUB_SETUP_OK);
}

uint32_t StreamGetWindow(Flow* flow, TcpTracker* st, TcpDataBlock* tdb)
{
    int32_t window;

    if (st->l_window)
    {
        // don't use the window if we may have missed scaling
        if (!(flow->session_state & STREAM_STATE_MIDSTREAM))
            return st->l_window;
    }
    // one way zero window is unitialized
    // two way zero window is actually closed (regardless of scaling)
    else if (flow->two_way_traffic())
        return st->l_window;

    // ensure the data is in the window
    window = tdb->end_seq - st->r_win_base;

    if (window < 0)
        window = 0;

    return (uint32_t) window;
}

uint32_t StreamGetTcpTimestamp(Packet* p, uint32_t* ts, int strip)
{
    DebugMessage(DEBUG_STREAM_STATE, "Getting timestamp...\n");

    const NormMode mode = Normalize_GetMode(NORM_TCP_OPT);
    tcp::TcpOptIterator iter(p->ptrs.tcph, p);

    // using const because non-const is not supported
    for (const tcp::TcpOption& opt : iter)
    {
        if (opt.code == tcp::TcpOptCode::TIMESTAMP)
        {
            if (strip)
            {
                NormalStripTimeStamp(p, &opt, mode);
            } else if (!strip || !NormalStripTimeStamp(p, &opt, mode))
            {
                *ts = EXTRACT_32BITS(opt.data);
                DebugFormat(DEBUG_STREAM_STATE, "Found timestamp %lu\n", *ts);

                return TF_TSTAMP;
            }
        }
    }
    *ts = 0;

    DebugMessage(DEBUG_STREAM_STATE, "No timestamp...\n");

    return TF_NONE;
}

// per rfc 793 a rst is valid if the seq number is in window
// for all states but syn-sent (handled above).  however, we
// validate here based on how various implementations actually
// handle a rst.
int ValidRst(Flow* flow, TcpTracker *st, TcpDataBlock *tdb)
{
    DebugFormat(DEBUG_STREAM_STATE, "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
            tdb->end_seq, st->r_win_base, tdb->seq, st->r_nxt_ack+StreamGetWindow(flow, st, tdb));

    switch (st->os_policy) {
        case STREAM_POLICY_HPUX11:
            if (SEQ_GEQ(tdb->seq, st->r_nxt_ack))
            {
                DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (>= next seq)!\n");
                return 1;
            }
            DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (>= next seq)!\n");
            return 0;
            break;
        case STREAM_POLICY_FIRST:
        case STREAM_POLICY_LAST:
        case STREAM_POLICY_MACOS:
        case STREAM_POLICY_WINDOWS:
        case STREAM_POLICY_VISTA:
        case STREAM_POLICY_WINDOWS2K3:
        case STREAM_POLICY_HPUX10:
        case STREAM_POLICY_IRIX:
            if (SEQ_EQ(tdb->seq, st->r_nxt_ack))
            {
                DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (next seq)!\n");
                return 1;
            }
            DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (next seq)!\n");
            return 0;
            break;
        case STREAM_POLICY_BSD:
        case STREAM_POLICY_LINUX:
        case STREAM_POLICY_OLD_LINUX:
        case STREAM_POLICY_SOLARIS:
            if (SEQ_GEQ(tdb->end_seq, st->r_win_base))
            {
                // reset must be admitted when window closed
                if (SEQ_LEQ(tdb->seq,
                            st->r_win_base + StreamGetWindow(flow, st, tdb)))
                {
                    DebugMessage(DEBUG_STREAM_STATE, "rst is valid seq (within window)!\n");
                    return 1;
                }
            }

            DebugMessage(DEBUG_STREAM_STATE, "rst is not valid seq (within window)!\n");
            return 0;
            break;
    }

    DebugMessage(DEBUG_STREAM_STATE, "rst is not valid!\n");
    return 0;
}

int ValidTimestamp(TcpTracker *talker, TcpTracker *listener, TcpDataBlock *tdb, Packet *p,
        int *eventcode, int *got_ts)
{
    if ( ( p->ptrs.tcph->th_flags & TH_RST )
            or listener->config->policy == STREAM_POLICY_PROXY)
        return ACTION_NOTHING;

#if 0
    if ( p->ptrs.tcph->th_flags & TH_ACK &&
            Normalize_IsEnabled(NORM_TCP_OPT) )
    {
        // FIXIT-L validate tsecr here (check that it was previously sent)
        // checking for the most recent ts is easy enough must check if
        // ts are up to date in retransmitted packets
    }
#endif
    /*
     * check PAWS
     */
    if ((talker->flags & TF_TSTAMP) && (listener->flags & TF_TSTAMP))
    {
        char validate_timestamp = 1;
        DebugMessage(DEBUG_STREAM_STATE, "Checking timestamps for PAWS\n");

        *got_ts = StreamGetTcpTimestamp(p, &tdb->ts, 0);

        if (*got_ts)
        {
            if (listener->config->policy == STREAM_POLICY_HPUX11)
            {
                /* HPUX 11 ignores timestamps for out of order segments */
                if ((listener->flags & TF_MISSING_PKT)
                        || !SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                {
                    validate_timestamp = 0;
                }
            }

            if (talker->flags & TF_TSTAMP_ZERO)
            {
                /* Handle the case where the 3whs used a 0 timestamp.  Next packet
                 * from that endpoint should have a valid timestamp... */
                if ((listener->config->policy == STREAM_POLICY_LINUX)
                        || (listener->config->policy == STREAM_POLICY_WINDOWS2K3))
                {
                    /* Linux, Win2k3 et al.  do not support timestamps if
                     * the 3whs used a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP;
                    listener->flags &= ~TF_TSTAMP;
                    validate_timestamp = 0;
                } else if ((listener->config->policy == STREAM_POLICY_OLD_LINUX)
                        || (listener->config->policy == STREAM_POLICY_WINDOWS)
                        || (listener->config->policy == STREAM_POLICY_VISTA))
                {
                    /* Older Linux (2.2 kernel & earlier), Win32 (non 2K3)
                     * allow the 3whs to use a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP_ZERO;
                    if (SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                    {
                        talker->ts_last = tdb->ts;
                        validate_timestamp = 0; /* Ignore the timestamp for this
                                                 * first packet, next one will
                                                 * checked. */
                    }
                }
            }

            if (validate_timestamp)
            {
                int result = 0;
                if (listener->config->policy == STREAM_POLICY_LINUX)
                {
                    /* Linux 2.6 accepts timestamp values that are off
                     * by one. */
                    result = (int) ((tdb->ts - talker->ts_last) + 1);
                } else
                {
                    result = (int) (tdb->ts - talker->ts_last);
                }

                if (result < 0)
                {
                    DebugMessage(DEBUG_STREAM_STATE, "Packet outside PAWS window, dropping\n");
                    /* bail, we've got a packet outside the PAWS window! */
                    //inc_tcp_discards();
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    NormalDropPacketIf(p, NORM_TCP_OPT);
                    return ACTION_BAD_PKT;
                } else if ((talker->ts_last != 0)
                        && ((uint32_t) p->pkth->ts.tv_sec
                            > talker->ts_last_pkt + PAWS_24DAYS))
                {
                    /* this packet is from way too far into the future */
                    DebugFormat(DEBUG_STREAM_STATE, "packet PAWS timestamp way too far ahead of last packet %d %d...\n",
                            p->pkth->ts.tv_sec, talker->ts_last_pkt);
                    //inc_tcp_discards();
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    NormalDropPacketIf(p, NORM_TCP_OPT);
                    return ACTION_BAD_PKT;
                } else
                {
                    DebugMessage(DEBUG_STREAM_STATE, "packet PAWS ok...\n");
                }
            }
        }
        else
        {
            /* we've got a packet with no timestamp, but 3whs indicated talker
             * was doing timestamps.  This breaks protocol, however, some servers
             * still ack the packet with the missing timestamp.  Log an alert,
             * but continue to process the packet
             */
            *eventcode |= EVENT_NO_TIMESTAMP;
            DebugMessage(DEBUG_STREAM_STATE, "packet no timestamp, had one earlier from this side...ok for now...\n");

            if (listener->config->policy == STREAM_POLICY_SOLARIS)
            {
                /* Solaris stops using timestamps if it receives a packet
                 * without a timestamp and there were timestamps in use.
                 */
                listener->flags &= ~TF_TSTAMP;
            }
            NormalDropPacketIf(p, NORM_TCP_OPT);
        }
    }
    else if (p->ptrs.tcph->is_syn_only())
    {
        *got_ts = StreamGetTcpTimestamp(p, &tdb->ts, 0);
        if (*got_ts)
            talker->flags |= TF_TSTAMP;
    }
    else
    {
        // if we are not handling timestamps, and this isn't a syn
        // (only), and we have seen a valid 3way setup, then we strip
        // (nop) the timestamp option.  this includes the cases where
        // we disable timestamp handling.
        int strip = (SetupOK(talker) && SetupOK(listener));
        DebugMessage(DEBUG_STREAM_STATE, "listener not doing timestamps...\n");
        *got_ts = StreamGetTcpTimestamp(p, &tdb->ts, strip);

        if (*got_ts)
        {
            if (!(talker->flags & TF_TSTAMP))
            {
                /* Since we skipped the SYN, may have missed the talker's
                 * timestamp there, so set it now.
                 */
                talker->flags |= TF_TSTAMP;
                if (tdb->ts == 0)
                {
                    talker->flags |= TF_TSTAMP_ZERO;
                }
            }

            /* Only valid to test this if listener is using timestamps.
             * Otherwise, timestamp in this packet is not used, regardless
             * of its value. */
            if ((tdb->ts == 0) && (listener->flags & TF_TSTAMP))
            {
                switch (listener->os_policy) {
                    case STREAM_POLICY_WINDOWS:
                    case STREAM_POLICY_VISTA:
                    case STREAM_POLICY_WINDOWS2K3:
                    case STREAM_POLICY_OLD_LINUX:
                    case STREAM_POLICY_SOLARIS:
                        /* Old Linux & Windows allows a 0 timestamp value. */
                        break;
                    default:
                        DebugMessage(DEBUG_STREAM_STATE, "Packet with 0 timestamp, dropping\n");
                        //inc_tcp_discards();
                        /* bail */
                        *eventcode |= EVENT_BAD_TIMESTAMP;
                        return ACTION_BAD_PKT;
                }
            }
        }
    }
    return ACTION_NOTHING;
}

int RepeatedSyn(TcpTracker *listener, TcpTracker *talker, TcpDataBlock *tdb, TcpSession *tcpssn)
{
    switch (listener->os_policy)
    {
        case STREAM_POLICY_WINDOWS:
        case STREAM_POLICY_WINDOWS2K3:
        case STREAM_POLICY_VISTA:
            /* Windows has some strange behaviour here.  If the
             * sequence of the reset is the next expected sequence,
             * it Resets.  Otherwise it ignores the 2nd SYN.
             */
            if (SEQ_EQ(tdb->seq, listener->r_nxt_ack))
            {
                DebugMessage(DEBUG_STREAM_STATE, "Got syn on established windows ssn, which causes Reset, bailing\n");
                tcpssn->flow->ssn_state.session_flags |= SSNFLAG_RESET;
                talker->s_mgr.state = TCP_STATE_CLOSED;
                return ACTION_RST;
            } else
            {
                DebugMessage(DEBUG_STREAM_STATE, "Got syn on established windows ssn, not causing Reset, bailing\n");
                inc_tcp_discards();
                return ACTION_NOTHING;
            }
            break;

        case STREAM_POLICY_MACOS:
            /* MACOS ignores a 2nd SYN, regardless of the sequence number. */
            DebugMessage(DEBUG_STREAM_STATE, "Got syn on established macos ssn, not causing Reset, bailing\n");
            inc_tcp_discards();
            return ACTION_NOTHING;
            break;

        case STREAM_POLICY_FIRST:
        case STREAM_POLICY_LAST:
        case STREAM_POLICY_LINUX:
        case STREAM_POLICY_OLD_LINUX:
        case STREAM_POLICY_BSD:
        case STREAM_POLICY_SOLARIS:
        case STREAM_POLICY_HPUX11:
        case STREAM_POLICY_HPUX10:
        case STREAM_POLICY_IRIX:
            /* If its not a retransmission of the actual SYN... RESET */
            if (!SEQ_EQ(tdb->seq, talker->isn))
            {
                DebugMessage(DEBUG_STREAM_STATE, "Got syn on established ssn, which causes Reset, bailing\n");
                tcpssn->flow->ssn_state.session_flags |= SSNFLAG_RESET;
                talker->s_mgr.state = TCP_STATE_CLOSED;
                return ACTION_RST;
            } else
            {
                DebugMessage(DEBUG_STREAM_STATE, "Got syn on established ssn, not causing Reset, bailing\n");
                inc_tcp_discards();
                return ACTION_NOTHING;
            }
            break;
    }
    return ACTION_NOTHING;
}
