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

// tcp_reassemblers.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 9, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassemblers.h"
#include "stream/libtcp/tcp_stream_tracker.h"

class TcpReassemblerFirst : public TcpReassembler
{
public:
    TcpReassemblerFirst() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os5(trs); }
};

class TcpReassemblerLast : public TcpReassembler
{
public:
    TcpReassemblerLast() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_last(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os4(trs); }
};

class TcpReassemblerLinux : public TcpReassembler
{
public:
    TcpReassemblerLinux() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os2(trs); }
};

class TcpReassemblerOldLinux : public TcpReassembler
{
public:
    TcpReassemblerOldLinux() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os4(trs); }
};

class TcpReassemblerBSD : public TcpReassembler
{
public:
    TcpReassemblerBSD() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os1(trs); }
};

class TcpReassemblerMacOS : public TcpReassembler
{
public:
    TcpReassemblerMacOS() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os1(trs); }
};

class TcpReassemblerSolaris : public TcpReassembler
{
public:
    TcpReassemblerSolaris() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_trim_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os3(trs); }
};

class TcpReassemblerIrix : public TcpReassembler
{
public:
    TcpReassemblerIrix() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs);  }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os2(trs); }
};

class TcpReassemblerHpux11 : public TcpReassembler
{
public:
    TcpReassemblerHpux11() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_trim_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os3(trs); }
};

class TcpReassemblerHpux10 : public TcpReassembler
{
public:
    TcpReassemblerHpux10() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os2(trs); }
};

class TcpReassemblerWindows : public TcpReassembler
{
public:
    TcpReassemblerWindows() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os1(trs); }
};

class TcpReassemblerWindows2K3 : public TcpReassembler
{
public:
    TcpReassemblerWindows2K3() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os1(trs); }
};

class TcpReassemblerVista : public TcpReassembler
{
public:
    TcpReassemblerVista() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os5 (trs); }
};

class TcpReassemblerProxy : public TcpReassemblerFirst
{
public:
    TcpReassemblerProxy() = default;

private:
    int insert_left_overlap(TcpReassemblerState& trs) override
    { return left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    int insert_full_overlap(TcpReassemblerState& trs) override
    { return full_right_overlap_os5(trs); }
};

static ReassemblyPolicy stream_reassembly_policy_map[] =
{
    ReassemblyPolicy::OS_INVALID,
    ReassemblyPolicy::OS_FIRST,
    ReassemblyPolicy::OS_LAST,
    ReassemblyPolicy::OS_LINUX,
    ReassemblyPolicy::OS_OLD_LINUX,
    ReassemblyPolicy::OS_BSD,
    ReassemblyPolicy::OS_MACOS,
    ReassemblyPolicy::OS_SOLARIS,
    ReassemblyPolicy::OS_IRIX,
    ReassemblyPolicy::OS_HPUX11,
    ReassemblyPolicy::OS_HPUX10,
    ReassemblyPolicy::OS_WINDOWS,
    ReassemblyPolicy::OS_WINDOWS2K3,
    ReassemblyPolicy::OS_VISTA,
    ReassemblyPolicy::OS_PROXY,
    ReassemblyPolicy::OS_DEFAULT
};

void TcpReassemblerPolicy::init(TcpSession* ssn, TcpStreamTracker* trk, StreamPolicy pol, bool server)
{
    trs.sos.init_sos(ssn, stream_reassembly_policy_map[ static_cast<int>(pol) ]);
    trs.server_side = server;
    trs.tracker = trk;

    if ( trs.server_side )
    {
        trs.ignore_dir = SSN_DIR_FROM_CLIENT;
        trs.packet_dir = PKT_FROM_CLIENT;
    }
    else
    {
        trs.ignore_dir = SSN_DIR_FROM_SERVER;
        trs.packet_dir = PKT_FROM_SERVER;
    }

    trs.flush_count = 0;
    trs.xtradata_mask = 0;

    reassembler = TcpReassemblerFactory::create(pol);
}

void TcpReassemblerPolicy::reset()
{
    init(nullptr, nullptr, StreamPolicy::OS_INVALID, false);
}

TcpReassembler* TcpReassemblerFactory::create(StreamPolicy os_policy)
{
    static TcpReassemblerFirst first;
    static TcpReassemblerLast last;
    static TcpReassemblerLinux new_linux;
    static TcpReassemblerOldLinux old_linux;
    static TcpReassemblerBSD bsd;
    static TcpReassemblerMacOS mac_os;
    static TcpReassemblerSolaris solaris;
    static TcpReassemblerIrix irix;
    static TcpReassemblerHpux11 hpux11;
    static TcpReassemblerHpux10 hpux10;
    static TcpReassemblerWindows windows;
    static TcpReassemblerWindows2K3 windows_2K3;
    static TcpReassemblerVista vista;
    static TcpReassemblerProxy proxy;

    NormMode tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
    StreamPolicy actual = (tcp_ips_data == NORM_MODE_ON) ? StreamPolicy::OS_FIRST : os_policy;
    TcpReassembler* reassembler;

    switch (actual)
    {
    case StreamPolicy::OS_FIRST: reassembler = &first; break;
    case StreamPolicy::OS_LAST: reassembler = &last; break;
    case StreamPolicy::OS_LINUX: reassembler = &new_linux; break;
    case StreamPolicy::OS_OLD_LINUX: reassembler = &old_linux; break;
    case StreamPolicy::OS_BSD: reassembler = &bsd; break;
    case StreamPolicy::OS_MACOS: reassembler = &mac_os; break;
    case StreamPolicy::OS_SOLARIS: reassembler = &solaris; break;
    case StreamPolicy::OS_IRIX: reassembler = &irix; break;
    case StreamPolicy::OS_HPUX11: reassembler = &hpux11; break;
    case StreamPolicy::OS_HPUX10: reassembler = &hpux10; break;
    case StreamPolicy::OS_WINDOWS: reassembler = &windows; break;
    case StreamPolicy::OS_WINDOWS2K3: reassembler = &windows_2K3; break;
    case StreamPolicy::OS_VISTA: reassembler = &vista; break;
    case StreamPolicy::OS_PROXY: reassembler = &proxy; break;
    default: reassembler = &bsd; break;
    }

    return reassembler;
}

