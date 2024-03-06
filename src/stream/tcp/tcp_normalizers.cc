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

// tcp_normalizers.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Sep 22, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_normalizers.h"

#include "tcp_module.h"
#include "tcp_segment_descriptor.h"
#include "tcp_stream_session.h"
#include "tcp_stream_tracker.h"

using namespace snort;

class TcpNormalizerFirst : public TcpNormalizer
{
public:
    TcpNormalizerFirst()
    { my_name = "OS_First"; }


    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerLast : public TcpNormalizer
{
public:
    TcpNormalizerLast()
    { my_name = "OS_Last"; }


    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerLinux : public TcpNormalizer
{
public:
    TcpNormalizerLinux()
    { my_name = "OS_Linux"; }


    void init(TcpNormalizerState& tns) override
    {
        // Linux 2.6 accepts timestamp values that are off by one. so set fudge factor */
        tns.paws_ts_fudge = 1;
    }

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerOldLinux : public TcpNormalizer
{
public:
    TcpNormalizerOldLinux()
    { my_name = "OS_OldLinux"; }


    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerBSD : public TcpNormalizer
{
public:
    TcpNormalizerBSD()
    { my_name = "OS_BSD"; }


    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerMacOS : public TcpNormalizer
{
public:
    TcpNormalizerMacOS()
    { my_name = "OS_MacOS"; }


    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerSolaris : public TcpNormalizer
{
public:
    TcpNormalizerSolaris()
    { my_name = "OS_Solaris"; }


    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerIrix : public TcpNormalizer
{
public:
    TcpNormalizerIrix()
    { my_name = "OS_Irix"; }


    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerHpux11 : public TcpNormalizer
{
public:
    TcpNormalizerHpux11()
    { my_name = "OS_Hpux11"; }


    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerHpux10 : public TcpNormalizer
{
public:
    TcpNormalizerHpux10()
    { my_name = "OS_Hpux10"; }


    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerWindows : public TcpNormalizer
{
public:
    TcpNormalizerWindows()
    { my_name = "OS_Windows"; }


    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerWindows2K3 : public TcpNormalizer
{
public:
    TcpNormalizerWindows2K3()
    { my_name = "OS_Windows2K3"; }


    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerVista : public TcpNormalizer
{
public:
    TcpNormalizerVista()
    { my_name = "OS_Vista"; }


    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerProxy : public TcpNormalizer
{
public:
    TcpNormalizerProxy()
    { my_name = "OS_Proxy"; }

    TcpNormalizer::NormStatus apply_normalizations(
        TcpNormalizerState&, TcpSegmentDescriptor&, uint32_t seq, bool stream_is_inorder) override;
    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_paws(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};


static inline int handle_repeated_syn_mswin(
    TcpStreamTracker* talker, TcpStreamTracker* listener,
    const TcpSegmentDescriptor& tsd, TcpStreamSession* session)
{
    /* Windows has some strange behavior here.  If the sequence of the reset is the
     * next expected sequence, it Resets.  Otherwise it ignores the 2nd SYN.
     */
    if ( SEQ_EQ(tsd.get_seq(), listener->rcv_nxt) )
    {
        session->flow->set_session_flags(SSNFLAG_RESET);
        talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
        return ACTION_RST;
    }
    else
        return ACTION_NOTHING;
}

static inline int handle_repeated_syn_bsd(
    TcpStreamTracker* talker, const TcpSegmentDescriptor& tsd, TcpStreamSession* session)
{
    /* If its not a retransmission of the actual SYN... RESET */
    if ( !SEQ_EQ(tsd.get_seq(), talker->get_iss()) )
    {
        session->flow->set_session_flags(SSNFLAG_RESET);
        talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
        return ACTION_RST;
    }
    else
        return ACTION_NOTHING;
}

// Linux, Win2k3 et al.  do not support timestamps if the 3whs used a 0 timestamp.
static inline bool paws_3whs_zero_ts_not_supported(
    TcpStreamTracker* talker, TcpStreamTracker* listener)
{
    bool check_ts = true;

    if ( talker->get_tf_flags() & TF_TSTAMP_ZERO )
    {
        talker->clear_tf_flags(TF_TSTAMP);
        listener->clear_tf_flags(TF_TSTAMP);
        check_ts = false;
    }

    return check_ts;
}

// Older Linux ( <= 2.2 kernel ), Win32 (non 2K3) allow the 3whs to use a 0 timestamp.
static inline bool paws_3whs_zero_ts_supported(
    TcpStreamTracker* talker, TcpStreamTracker* listener, const TcpSegmentDescriptor& tsd)
{
    bool check_ts = true;

    if ( talker->get_tf_flags() & TF_TSTAMP_ZERO )
    {
        talker->clear_tf_flags(TF_TSTAMP_ZERO);
        if ( SEQ_EQ(listener->rcv_nxt, tsd.get_seq() ) )
        {
            // Ignore timestamp for this first packet, save to check on next
            talker->set_ts_last(tsd.get_timestamp());
            check_ts = false;
        }
    }

    return check_ts;
}

#if 0
// FIXIT-L urgent pointer schizzle - outdated
static inline uint16_t set_urg_offset_linux(const tcp::TCPHdr* tcph, uint16_t dsize)
{
    uint16_t urg_offset = 0;

    if ( tcph->are_flags_set(TH_URG) )
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
#endif

int TcpNormalizerFirst::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

int TcpNormalizerLast::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

bool TcpNormalizerLinux::validate_rst(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return validate_rst_end_seq_geq(tns, tsd);
}

bool TcpNormalizerLinux::is_paws_ts_checked_required(
    TcpNormalizerState& tns, TcpSegmentDescriptor&)
{
    return paws_3whs_zero_ts_not_supported(tns.peer_tracker, tns.tracker);
}

int TcpNormalizerLinux::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

bool TcpNormalizerOldLinux::validate_rst(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return validate_rst_end_seq_geq(tns, tsd);
}

bool TcpNormalizerOldLinux::is_paws_ts_checked_required(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return paws_3whs_zero_ts_supported(tns.peer_tracker, tns.tracker, tsd);
}

int TcpNormalizerOldLinux::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

bool TcpNormalizerBSD::validate_rst(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return validate_rst_end_seq_geq(tns, tsd);
}

int TcpNormalizerBSD::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

int TcpNormalizerMacOS::handle_repeated_syn(
    TcpNormalizerState&, TcpSegmentDescriptor&)
{
    /* MACOS ignores a 2nd SYN, regardless of the sequence number. */
    return ACTION_NOTHING;
}

bool TcpNormalizerSolaris::validate_rst(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return validate_rst_end_seq_geq(tns, tsd);
}

int TcpNormalizerSolaris::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

int TcpNormalizerIrix::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

bool TcpNormalizerHpux11::validate_rst(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return validate_rst_seq_geq(tns, tsd);
}

bool TcpNormalizerHpux11::is_paws_ts_checked_required(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    /* HPUX 11 ignores timestamps for out of order segments */
    if ( (tns.tracker->get_tf_flags() & TF_MISSING_PKT)
        || !SEQ_EQ(tns.tracker->rcv_nxt, tsd.get_seq()) )
        return false;
    else
        return true;
}

int TcpNormalizerHpux11::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

int TcpNormalizerHpux10::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_bsd(tns.peer_tracker, tsd, tns.session);
}

bool TcpNormalizerWindows::is_paws_ts_checked_required(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return paws_3whs_zero_ts_supported(tns.peer_tracker, tns.tracker, tsd);
}

int TcpNormalizerWindows::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_mswin(tns.peer_tracker, tns.tracker, tsd, tns.session);
}

int TcpNormalizerWindows2K3::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_mswin(tns.peer_tracker, tns.tracker, tsd, tns.session);
}

bool TcpNormalizerWindows2K3::is_paws_ts_checked_required(
    TcpNormalizerState& tns, TcpSegmentDescriptor&)
{
    return paws_3whs_zero_ts_not_supported(tns.peer_tracker, tns.tracker);
}

bool TcpNormalizerVista::is_paws_ts_checked_required(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return paws_3whs_zero_ts_supported(tns.peer_tracker, tns.tracker, tsd);
}

int TcpNormalizerVista::handle_repeated_syn(
    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)
{
    return handle_repeated_syn_mswin(tns.peer_tracker, tns.tracker, tsd, tns.session);
}

TcpNormalizer::NormStatus TcpNormalizerProxy::apply_normalizations(
    TcpNormalizerState&, TcpSegmentDescriptor&, uint32_t, bool)
{
    // when Proxy policy is active packet normalizations are skipped
    return NORM_OK;
}

bool TcpNormalizerProxy::validate_rst(
    TcpNormalizerState&, TcpSegmentDescriptor&)
{
    return true;
}

int TcpNormalizerProxy::handle_paws(
    TcpNormalizerState&, TcpSegmentDescriptor&)
{
    return ACTION_NOTHING;
}

int TcpNormalizerProxy::handle_repeated_syn(
    TcpNormalizerState&, TcpSegmentDescriptor&)
{
    return ACTION_NOTHING;
}

void TcpNormalizerPolicy::init(StreamPolicy os, TcpStreamSession* ssn, TcpStreamTracker* trk, TcpStreamTracker* peer)
{
    tns.os_policy = os;
    tns.session = ssn;
    tns.tracker = trk;
    tns.peer_tracker = peer;

    tns.paws_ts_fudge = 0;
    tns.paws_drop_zero_ts = true;
    tns.tcp_ts_flags = 0;

    tns.tcp_ips_enabled = Normalize_IsEnabled(NORM_TCP_IPS);
    tns.trim_syn = Normalize_GetMode(NORM_TCP_TRIM_SYN);
    tns.trim_rst = Normalize_GetMode(NORM_TCP_TRIM_RST);
    tns.trim_win = Normalize_GetMode(NORM_TCP_TRIM_WIN);
    tns.trim_mss = Normalize_GetMode(NORM_TCP_TRIM_MSS);
    tns.strip_ecn = Normalize_GetMode(NORM_TCP_ECN_STR);
    tns.tcp_block = Normalize_GetMode(NORM_TCP_BLOCK);
    tns.opt_block = Normalize_GetMode(NORM_TCP_OPT);

    norm = TcpNormalizerFactory::get_instance(os);
    norm->init(tns);
}

TcpNormalizer* TcpNormalizerFactory::normalizers[StreamPolicy::OS_END_OF_LIST];

void TcpNormalizerFactory::initialize()
{
    normalizers[StreamPolicy::OS_FIRST] = new TcpNormalizerFirst;
    normalizers[StreamPolicy::OS_LAST] = new TcpNormalizerLast;
    normalizers[StreamPolicy::OS_LINUX] = new TcpNormalizerLinux;
    normalizers[StreamPolicy::OS_OLD_LINUX] = new TcpNormalizerOldLinux;
    normalizers[StreamPolicy::OS_BSD] = new TcpNormalizerBSD;
    normalizers[StreamPolicy::OS_MACOS] = new TcpNormalizerMacOS;
    normalizers[StreamPolicy::OS_SOLARIS] = new TcpNormalizerSolaris;
    normalizers[StreamPolicy::OS_IRIX] = new TcpNormalizerIrix;
    normalizers[StreamPolicy::OS_HPUX11] = new TcpNormalizerHpux11;
    normalizers[StreamPolicy::OS_HPUX10] = new TcpNormalizerHpux10;
    normalizers[StreamPolicy::OS_WINDOWS] = new TcpNormalizerWindows;
    normalizers[StreamPolicy::OS_WINDOWS2K3] = new TcpNormalizerWindows2K3;
    normalizers[StreamPolicy::OS_VISTA] = new TcpNormalizerVista;
    normalizers[StreamPolicy::OS_PROXY] = new TcpNormalizerProxy;
}

void TcpNormalizerFactory::term()
{
    for ( auto sp = StreamPolicy::OS_FIRST; sp <= StreamPolicy::OS_PROXY; sp++ )
        delete normalizers[sp];
}

TcpNormalizer* TcpNormalizerFactory::get_instance(StreamPolicy sp)
{
    assert( sp <= StreamPolicy::OS_PROXY );
    return normalizers[sp];
}

