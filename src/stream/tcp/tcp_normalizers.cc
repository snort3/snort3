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

// tcp_normalizers.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 22, 2015

#include "tcp_module.h"
#include "tcp_normalizers.h"

TcpNormalizer* TcpNormalizerFactory::allocate_normalizer( uint16_t os_policy,
        TcpSession* session, TcpTracker* tracker, TcpTracker* peer )
{
    TcpNormalizer* normalizer;

    switch (os_policy)
    {
    case STREAM_POLICY_FIRST:
        normalizer = new TcpNormalizerFirst( session, tracker );
        break;

    case STREAM_POLICY_LAST:
        normalizer = new TcpNormalizerLast( session, tracker );
        break;

    case STREAM_POLICY_LINUX:
        normalizer = new TcpNormalizerLinux( session, tracker );
        break;

    case STREAM_POLICY_OLD_LINUX:
        normalizer = new TcpNormalizerOldLinux( session, tracker );
        break;

    case STREAM_POLICY_BSD:
        normalizer = new TcpNormalizerBSD( session, tracker );
        break;

    case STREAM_POLICY_MACOS:
        normalizer = new TcpNormalizerMacOS( session, tracker );
        break;

    case STREAM_POLICY_SOLARIS:
        normalizer = new TcpNormalizerSolaris( session, tracker );
        break;

    case STREAM_POLICY_IRIX:
        normalizer = new TcpNormalizerIrix( session, tracker );
        break;

    case STREAM_POLICY_HPUX11:
        normalizer = new TcpNormalizerHpux11( session, tracker );
        break;

    case STREAM_POLICY_HPUX10:
        normalizer = new TcpNormalizerHpux10( session, tracker );
        break;

    case STREAM_POLICY_WINDOWS:
        normalizer = new TcpNormalizerWindows( session, tracker );
        break;

    case STREAM_POLICY_WINDOWS2K3:
        normalizer = new TcpNormalizerWindows2K3( session, tracker );
        break;

    case STREAM_POLICY_VISTA:
        normalizer = new TcpNormalizerVista( session, tracker );
        break;

    case STREAM_POLICY_PROXY:
        normalizer = new TcpNormalizerProxy( session, tracker );
        break;

    default:
        normalizer = new TcpNormalizerBSD( session, tracker );
        break;
    }

    normalizer->set_peer_tracker( peer );
    return normalizer;
}

static inline int handle_repeated_syn_mswin( TcpTracker* talker, TcpTracker* listener,
        TcpDataBlock* tdb, TcpSession* session )
{
    /* Windows has some strange behaviour here.  If the sequence of the reset is the
     *  next expected sequence, it Resets.  Otherwise it ignores the 2nd SYN.
     */
    if (SEQ_EQ(tdb->seq, listener->r_nxt_ack))
    {
        DebugMessage(DEBUG_STREAM_STATE, "Got syn on established windows ssn, which causes Reset, bailing\n");
        session->flow->set_session_flags( SSNFLAG_RESET );
        talker->s_mgr.state = TCP_STATE_CLOSED;
        return ACTION_RST;
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "Got syn on established windows ssn, not causing Reset, bailing\n");
        inc_tcp_discards();
        return ACTION_NOTHING;
    }
}

static inline int handle_repeated_syn_bsd( TcpTracker* talker, TcpDataBlock* tdb, TcpSession* session )
{
    /* If its not a retransmission of the actual SYN... RESET */
     if (!SEQ_EQ(tdb->seq, talker->isn))
     {
         DebugMessage(DEBUG_STREAM_STATE, "Got syn on established ssn, which causes Reset, bailing\n");
         session->flow->set_session_flags( SSNFLAG_RESET );
         talker->s_mgr.state = TCP_STATE_CLOSED;
         return ACTION_RST;
     }
     else
     {
         DebugMessage(DEBUG_STREAM_STATE, "Got syn on established ssn, not causing Reset, bailing\n");
         inc_tcp_discards();
         return ACTION_NOTHING;
     }
}

// Linux, Win2k3 et al.  do not support timestamps if the 3whs used a 0 timestamp.
static inline bool paws_3whs_zero_ts_not_supported(TcpTracker* talker, TcpTracker* listener )
{
    bool check_ts = true;

    if (talker->flags & TF_TSTAMP_ZERO)
    {
        talker->flags &= ~TF_TSTAMP;
        listener->flags &= ~TF_TSTAMP;
        check_ts = false;
    }

    return check_ts;
}

// Older Linux ( <= 2.2 kernel ), Win32 (non 2K3) allow the 3whs to use a 0 timestamp.
static inline bool paws_3whs_zero_ts_supported(TcpTracker* talker, TcpTracker* listener, TcpDataBlock* tdb)
{
    bool check_ts = true;

    if( talker->flags & TF_TSTAMP_ZERO )
    {
        talker->flags &= ~TF_TSTAMP_ZERO;
        if( SEQ_EQ( listener->r_nxt_ack, tdb->seq ) )
        {
            // Ignore timestamp for this first packet, save to check on next
            talker->ts_last = tdb->ts;
            check_ts = false;
        }
    }

    return check_ts;
}

int TcpNormalizerFirst::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

int TcpNormalizerLast::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

bool TcpNormalizerLinux::validate_rst( TcpDataBlock *tdb )
{
    return validate_rst_end_seq_geq( tdb );
}

bool TcpNormalizerLinux::is_paws_ts_checked_required( TcpDataBlock* )
{
    return paws_3whs_zero_ts_not_supported( peer_tracker, tracker );
}

int TcpNormalizerLinux::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

bool TcpNormalizerOldLinux::validate_rst( TcpDataBlock *tdb )
{
    return validate_rst_end_seq_geq( tdb );
}

bool TcpNormalizerOldLinux::is_paws_ts_checked_required( TcpDataBlock* tdb)
{
    return paws_3whs_zero_ts_supported( peer_tracker, tracker, tdb );
}

int TcpNormalizerOldLinux::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

bool TcpNormalizerBSD::validate_rst( TcpDataBlock *tdb )
{
    return validate_rst_end_seq_geq( tdb );
}

int TcpNormalizerBSD::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

int TcpNormalizerMacOS::handle_repeated_syn( TcpDataBlock* )
{
    /* MACOS ignores a 2nd SYN, regardless of the sequence number. */
    DebugMessage(DEBUG_STREAM_STATE, "Got syn on established macos ssn, not causing Reset, bailing\n");
    inc_tcp_discards();
    return ACTION_NOTHING;
}

bool TcpNormalizerSolaris::validate_rst( TcpDataBlock* tdb )
{
    return validate_rst_end_seq_geq( tdb );
}

int TcpNormalizerSolaris::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

int TcpNormalizerIrix::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

bool TcpNormalizerHpux11::validate_rst( TcpDataBlock *tdb )
{
    return validate_rst_seq_geq( tdb );
}

bool TcpNormalizerHpux11::is_paws_ts_checked_required( TcpDataBlock* tdb )
{
    /* HPUX 11 ignores timestamps for out of order segments */
    if ((tracker->flags & TF_MISSING_PKT) || !SEQ_EQ(tracker->r_nxt_ack, tdb->seq))
        return false;
    else
        return true;
}

int TcpNormalizerHpux11::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

int TcpNormalizerHpux10::handle_repeated_syn( TcpDataBlock* tdb )
{
    return handle_repeated_syn_bsd( peer_tracker, tdb, session );
}

bool TcpNormalizerWindows::is_paws_ts_checked_required( TcpDataBlock* tdb)
{
    return paws_3whs_zero_ts_supported( peer_tracker, tracker, tdb );
}

int TcpNormalizerWindows::handle_repeated_syn( TcpDataBlock *tdb )
{
    return handle_repeated_syn_mswin( peer_tracker, tracker, tdb, session );
}


int TcpNormalizerWindows2K3::handle_repeated_syn( TcpDataBlock *tdb )
{
    return handle_repeated_syn_mswin( peer_tracker, tracker, tdb, session );
}

bool TcpNormalizerWindows2K3::is_paws_ts_checked_required( TcpDataBlock* )
{
    return paws_3whs_zero_ts_not_supported( peer_tracker, tracker );
}

bool TcpNormalizerVista::is_paws_ts_checked_required( TcpDataBlock* tdb)
{
    return paws_3whs_zero_ts_supported( peer_tracker, tracker, tdb );
}

int TcpNormalizerVista::handle_repeated_syn( TcpDataBlock *tdb )
{
    return handle_repeated_syn_mswin( peer_tracker, tracker, tdb, session );
}

bool TcpNormalizerProxy::validate_rst( TcpDataBlock *tdb )
{
    // FIXIT - will session->flow ever be null? i would think not, remove this check if possible
    if( session->flow )
    {
        DebugFormat(DEBUG_STREAM_STATE, "Proxy Normalizer - Not Valid\n end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
                tdb->end_seq, tracker->r_win_base, tdb->seq, tracker->r_nxt_ack + get_stream_window( tdb ));
    }

    return false;
}

int TcpNormalizerProxy::handle_paws(TcpDataBlock*, Packet*, int*, int*)
{
    return ACTION_NOTHING;
}

int TcpNormalizerProxy::handle_repeated_syn( TcpDataBlock* )
{
    return ACTION_NOTHING;
}



