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

// tcp_normalizers.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 22, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_normalizers.h"

#include "tcp_module.h"
#include "stream/libtcp/tcp_segment_descriptor.h"
#include "stream/libtcp/tcp_stream_session.h"
#include "stream/libtcp/tcp_stream_tracker.h"

using namespace snort;

class TcpNormalizerFirst : public TcpNormalizer
{
public:
    TcpNormalizerFirst() = default;

    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerLast : public TcpNormalizer
{
public:
    TcpNormalizerLast() = default;

    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerLinux : public TcpNormalizer
{
public:
    TcpNormalizerLinux() = default;

    void init(TcpNormalizerState& tns) override
    {
        // Linux 2.6 accepts timestamp values that are off by one. so set fudge factor */
        tns.paws_ts_fudge = 1;
    }

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    uint16_t set_urg_offset(
        TcpNormalizerState&, const tcp::TCPHdr* tcph, uint16_t dsize) override;
};

class TcpNormalizerOldLinux : public TcpNormalizer
{
public:
    TcpNormalizerOldLinux() = default;

    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    uint16_t set_urg_offset(
        TcpNormalizerState&, const tcp::TCPHdr* tcph, uint16_t dsize) override;
};

class TcpNormalizerBSD : public TcpNormalizer
{
public:
    TcpNormalizerBSD() = default;

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerMacOS : public TcpNormalizer
{
public:
    TcpNormalizerMacOS() = default;

    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerSolaris : public TcpNormalizer
{
public:
    TcpNormalizerSolaris() = default;

    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerIrix : public TcpNormalizer
{
public:
    TcpNormalizerIrix() = default;

    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerHpux11 : public TcpNormalizer
{
public:
    TcpNormalizerHpux11() = default;

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerHpux10 : public TcpNormalizer
{
public:
    TcpNormalizerHpux10() = default;

    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerWindows : public TcpNormalizer
{
public:
    TcpNormalizerWindows() = default;

    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerWindows2K3 : public TcpNormalizer
{
public:
    TcpNormalizerWindows2K3() = default;

    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerVista : public TcpNormalizer
{
public:
    TcpNormalizerVista() = default;

    void init(TcpNormalizerState& tns) override
    { tns.paws_drop_zero_ts = false; }

    bool is_paws_ts_checked_required(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};

class TcpNormalizerProxy : public TcpNormalizer
{
public:
    TcpNormalizerProxy() = default;

    bool validate_rst(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_paws(TcpNormalizerState&, TcpSegmentDescriptor&) override;
    int handle_repeated_syn(TcpNormalizerState&, TcpSegmentDescriptor&) override;
};


static inline int handle_repeated_syn_mswin(
    TcpStreamTracker* talker, TcpStreamTracker* listener,
    TcpSegmentDescriptor& tsd, TcpStreamSession* session)
{
    /* Windows has some strange behavior here.  If the sequence of the reset is the
     * next expected sequence, it Resets.  Otherwise it ignores the 2nd SYN.
     */
    if (SEQ_EQ(tsd.get_seg_seq(), listener->rcv_nxt))
    {
        session->flow->set_session_flags(SSNFLAG_RESET);
        talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
        return ACTION_RST;
    }
    else
    {
        inc_tcp_discards();
        return ACTION_NOTHING;
    }
}

static inline int handle_repeated_syn_bsd(
    TcpStreamTracker* talker, TcpSegmentDescriptor& tsd, TcpStreamSession* session)
{
    /* If its not a retransmission of the actual SYN... RESET */
    if (!SEQ_EQ(tsd.get_seg_seq(), talker->get_iss()))
    {
        session->flow->set_session_flags(SSNFLAG_RESET);
        talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
        return ACTION_RST;
    }
    else
    {
        inc_tcp_discards();
        return ACTION_NOTHING;
    }
}

// Linux, Win2k3 et al.  do not support timestamps if the 3whs used a 0 timestamp.
static inline bool paws_3whs_zero_ts_not_supported(
    TcpStreamTracker* talker, TcpStreamTracker* listener)
{
    bool check_ts = true;

    if (talker->get_tf_flags() & TF_TSTAMP_ZERO)
    {
        talker->clear_tf_flags(TF_TSTAMP);
        listener->clear_tf_flags(TF_TSTAMP);
        check_ts = false;
    }

    return check_ts;
}

// Older Linux ( <= 2.2 kernel ), Win32 (non 2K3) allow the 3whs to use a 0 timestamp.
static inline bool paws_3whs_zero_ts_supported(
    TcpStreamTracker* talker, TcpStreamTracker* listener, TcpSegmentDescriptor& tsd)
{
    bool check_ts = true;

    if ( talker->get_tf_flags() & TF_TSTAMP_ZERO )
    {
        talker->clear_tf_flags(TF_TSTAMP_ZERO);
        if ( SEQ_EQ(listener->rcv_nxt, tsd.get_seg_seq() ) )
        {
            // Ignore timestamp for this first packet, save to check on next
            talker->set_ts_last(tsd.get_ts() );
            check_ts = false;
        }
    }

    return check_ts;
}

static inline uint16_t set_urg_offset_linux(const tcp::TCPHdr* tcph, uint16_t dsize)
{
    uint16_t urg_offset = 0;

    if (tcph->are_flags_set(TH_URG) )
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

uint16_t TcpNormalizerLinux::set_urg_offset(
    TcpNormalizerState&, const tcp::TCPHdr* tcph, uint16_t dsize)
{
    return set_urg_offset_linux(tcph, dsize);
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

uint16_t TcpNormalizerOldLinux::set_urg_offset(
    TcpNormalizerState&, const tcp::TCPHdr* tcph, uint16_t dsize)
{
    return set_urg_offset_linux(tcph, dsize);
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
    inc_tcp_discards();
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
    if ((tns.tracker->get_tf_flags() & TF_MISSING_PKT) || !SEQ_EQ(tns.tracker->rcv_nxt,
        tsd.get_seg_seq()))
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

bool TcpNormalizerProxy::validate_rst(
    TcpNormalizerState&, TcpSegmentDescriptor&)

{
    return false;
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

    norm = TcpNormalizerFactory::create(os);
    norm->init(tns);
}

TcpNormalizer* TcpNormalizerFactory::create(StreamPolicy os_policy)
{
    static TcpNormalizerFirst first;
    static TcpNormalizerLast last;
    static TcpNormalizerLinux new_linux;
    static TcpNormalizerOldLinux old_linux;
    static TcpNormalizerBSD bsd;
    static TcpNormalizerMacOS mac_os;
    static TcpNormalizerSolaris solaris;
    static TcpNormalizerIrix irix;
    static TcpNormalizerHpux11 hpux11;
    static TcpNormalizerHpux10 hpux10;
    static TcpNormalizerWindows windows;
    static TcpNormalizerWindows2K3 windows_2K3;
    static TcpNormalizerVista vista;
    static TcpNormalizerProxy proxy;

    TcpNormalizer* normalizer;

    switch (os_policy)
    {
    case StreamPolicy::OS_FIRST: normalizer = &first; break;
    case StreamPolicy::OS_LAST: normalizer = &last; break;
    case StreamPolicy::OS_LINUX: normalizer = &new_linux; break;
    case StreamPolicy::OS_OLD_LINUX: normalizer = &old_linux; break;
    case StreamPolicy::OS_BSD: normalizer = &bsd; break;
    case StreamPolicy::OS_MACOS: normalizer = &mac_os; break;
    case StreamPolicy::OS_SOLARIS: normalizer = &solaris; break;
    case StreamPolicy::OS_IRIX: normalizer = &irix; break;
    case StreamPolicy::OS_HPUX11: normalizer = &hpux11; break;
    case StreamPolicy::OS_HPUX10: normalizer = &hpux10; break;
    case StreamPolicy::OS_WINDOWS: normalizer = &windows; break;
    case StreamPolicy::OS_WINDOWS2K3: normalizer = &windows_2K3; break;
    case StreamPolicy::OS_VISTA: normalizer = &vista; break;
    case StreamPolicy::OS_PROXY: normalizer = &proxy; break;
    default: normalizer = &bsd; break;
    }

    return normalizer;
}

