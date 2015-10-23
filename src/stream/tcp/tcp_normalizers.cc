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

#include "tcp_defs.h"
#include "tcp_module.h"
#include "tcp_normalizers.h"

class TcpNormalizerFirst : public TcpNormalizer
{
public:
    TcpNormalizerFirst( TcpSession* session, TcpTracker* tracker ) :
        TcpNormalizer( StreamPolicy::OS_FIRST, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerLast : public TcpNormalizer
{
public:
    TcpNormalizerLast( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_LAST, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerLinux : public TcpNormalizer
{
public:
    TcpNormalizerLinux( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_LINUX, session, tracker )
    {
        // Linux 2.6 accepts timestamp values that are off by one. so set fudge factor */
        paws_ts_fudge = 1;
    }

    bool validate_rst( TcpDataBlock* ) override;
    bool is_paws_ts_checked_required( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
    uint16_t set_urg_offset( const tcp::TCPHdr* tcph, uint16_t dsize ) override;

};

class TcpNormalizerOldLinux : public TcpNormalizer
{
public:
    TcpNormalizerOldLinux( TcpSession* session, TcpTracker* tracker ) :
            TcpNormalizer( StreamPolicy::OS_OLD_LINUX, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool validate_rst( TcpDataBlock* ) override;
    bool is_paws_ts_checked_required( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
    uint16_t set_urg_offset( const tcp::TCPHdr* tcph, uint16_t dsize ) override;

};

class TcpNormalizerBSD : public TcpNormalizer
{
public:
    TcpNormalizerBSD( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_BSD, session, tracker )
    { }

    bool validate_rst( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerMacOS : public TcpNormalizer
{
public:
    TcpNormalizerMacOS( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_MACOS, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerSolaris : public TcpNormalizer
{
public:
    TcpNormalizerSolaris( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_SOLARIS, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool validate_rst( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerIrix : public TcpNormalizer
{
public:
    TcpNormalizerIrix( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_IRIX, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerHpux11 : public TcpNormalizer
{
public:
    TcpNormalizerHpux11( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_HPUX11, session, tracker )
    { }

    bool validate_rst( TcpDataBlock* ) override;
    bool is_paws_ts_checked_required( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerHpux10 : public TcpNormalizer
{
public:
    TcpNormalizerHpux10( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_HPUX10, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerWindows : public TcpNormalizer
{
public:
    TcpNormalizerWindows( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_WINDOWS, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool is_paws_ts_checked_required( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerWindows2K3 : public TcpNormalizer
{
public:
    TcpNormalizerWindows2K3( TcpSession* session, TcpTracker* tracker ) :
            TcpNormalizer( StreamPolicy::OS_WINDOWS2K3, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool is_paws_ts_checked_required(  TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerVista : public TcpNormalizer
{
public:
    TcpNormalizerVista( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_VISTA, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool is_paws_ts_checked_required( TcpDataBlock*) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerProxy : public TcpNormalizer
{
public:
    TcpNormalizerProxy( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( StreamPolicy::OS_PROXY, session, tracker )
    { }

    bool validate_rst(TcpDataBlock* ) override;
    int handle_paws( TcpDataBlock*,int*, int* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

TcpNormalizer* TcpNormalizerFactory::create( StreamPolicy os_policy, TcpSession* session,
        TcpTracker* tracker, TcpTracker* peer )
{
    TcpNormalizer* normalizer;

    switch (os_policy)
    {
    case StreamPolicy::OS_FIRST:
        normalizer = new TcpNormalizerFirst( session, tracker );
        break;

    case StreamPolicy::OS_LAST:
        normalizer = new TcpNormalizerLast( session, tracker );
        break;

    case StreamPolicy::OS_LINUX:
        normalizer = new TcpNormalizerLinux( session, tracker );
        break;

    case StreamPolicy::OS_OLD_LINUX:
        normalizer = new TcpNormalizerOldLinux( session, tracker );
        break;

    case StreamPolicy::OS_BSD:
        normalizer = new TcpNormalizerBSD( session, tracker );
        break;

    case StreamPolicy::OS_MACOS:
        normalizer = new TcpNormalizerMacOS( session, tracker );
        break;

    case StreamPolicy::OS_SOLARIS:
        normalizer = new TcpNormalizerSolaris( session, tracker );
        break;

    case StreamPolicy::OS_IRIX:
        normalizer = new TcpNormalizerIrix( session, tracker );
        break;

    case StreamPolicy::OS_HPUX11:
        normalizer = new TcpNormalizerHpux11( session, tracker );
        break;

    case StreamPolicy::OS_HPUX10:
        normalizer = new TcpNormalizerHpux10( session, tracker );
        break;

    case StreamPolicy::OS_WINDOWS:
        normalizer = new TcpNormalizerWindows( session, tracker );
        break;

    case StreamPolicy::OS_WINDOWS2K3:
        normalizer = new TcpNormalizerWindows2K3( session, tracker );
        break;

    case StreamPolicy::OS_VISTA:
        normalizer = new TcpNormalizerVista( session, tracker );
        break;

    case StreamPolicy::OS_PROXY:
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

static inline uint16_t set_urg_offset_linux( const tcp::TCPHdr* tcph, uint16_t dsize )
{
    uint16_t urg_offset = 0;

    if(tcph->are_flags_set( TH_URG) )
    {
        urg_offset = tcph->urp();

            // Linux, Old linux discard data from urgent pointer If urg pointer is 0,
            // it's treated as a 1
            if (tcph->urp() < dsize)
                if (urg_offset == 0)
                    urg_offset = 1;
    }

    return urg_offset;
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

uint16_t TcpNormalizerLinux::set_urg_offset( const tcp::TCPHdr* tcph, uint16_t dsize )
{
    return set_urg_offset_linux( tcph, dsize );
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

uint16_t TcpNormalizerOldLinux::set_urg_offset( const tcp::TCPHdr* tcph, uint16_t dsize )
{
    return set_urg_offset_linux( tcph, dsize );
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

int TcpNormalizerProxy::handle_paws(TcpDataBlock*, int*, int*)
{
    return ACTION_NOTHING;
}

int TcpNormalizerProxy::handle_repeated_syn( TcpDataBlock* )
{
    return ACTION_NOTHING;
}



