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

// tcp_reassemblers.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 9, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassemblers.h"

#include "tcp_defs.h"
#include "tcp_stream_tracker.h"

class TcpReassemblerFirst : public TcpReassembler
{
public:
    TcpReassemblerFirst() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os5(trs); }
};

class TcpReassemblerLast : public TcpReassembler
{
public:
    TcpReassemblerLast() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_last(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os4(trs); }
};

class TcpReassemblerLinux : public TcpReassembler
{
public:
    TcpReassemblerLinux() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os2(trs); }
};

class TcpReassemblerOldLinux : public TcpReassembler
{
public:
    TcpReassemblerOldLinux() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os4(trs); }
};

class TcpReassemblerBSD : public TcpReassembler
{
public:
    TcpReassemblerBSD() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os1(trs); }
};

class TcpReassemblerMacOS : public TcpReassembler
{
public:
    TcpReassemblerMacOS() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os1(trs); }
};

class TcpReassemblerSolaris : public TcpReassembler
{
public:
    TcpReassemblerSolaris() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_trim_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os3(trs); }
};

class TcpReassemblerIrix : public TcpReassembler
{
public:
    TcpReassemblerIrix() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs);  }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os2(trs); }
};

class TcpReassemblerHpux11 : public TcpReassembler
{
public:
    TcpReassemblerHpux11() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_trim_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os3(trs); }
};

class TcpReassemblerHpux10 : public TcpReassembler
{
public:
    TcpReassemblerHpux10() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os2(trs); }
};

class TcpReassemblerWindows : public TcpReassembler
{
public:
    TcpReassemblerWindows() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os1(trs); }
};

class TcpReassemblerWindows2K3 : public TcpReassembler
{
public:
    TcpReassemblerWindows2K3() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_existing(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os1(trs); }
};

class TcpReassemblerVista : public TcpReassembler
{
public:
    TcpReassemblerVista() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os5 (trs); }
};

class TcpReassemblerProxy : public TcpReassemblerFirst
{
public:
    TcpReassemblerProxy() = default;

private:
    void insert_left_overlap(TcpReassemblerState& trs) override
    { left_overlap_keep_first(trs); }

    void insert_right_overlap(TcpReassemblerState& trs) override
    { right_overlap_truncate_new(trs); }

    void insert_full_overlap(TcpReassemblerState& trs) override
    { full_right_overlap_os5(trs); }
};

void TcpReassemblerPolicy::init(TcpSession* ssn, TcpStreamTracker* trk, StreamPolicy pol, bool server)
{
    trs.sos.init_sos(ssn, pol);
    setup_paf();
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
    trs.alerts.clear();

    reassembler = TcpReassemblerFactory::get_instance(pol);
}

void TcpReassemblerPolicy::reset()
{ init(nullptr, nullptr, StreamPolicy::OS_DEFAULT, false); }

TcpReassembler* TcpReassemblerFactory::reassemblers[StreamPolicy::OS_END_OF_LIST];

void TcpReassemblerFactory::initialize()
{
    reassemblers[StreamPolicy::OS_FIRST] = new TcpReassemblerFirst;
    reassemblers[StreamPolicy::OS_LAST] = new TcpReassemblerLast;
    reassemblers[StreamPolicy::OS_LINUX] = new TcpReassemblerLinux;
    reassemblers[StreamPolicy::OS_OLD_LINUX] = new TcpReassemblerOldLinux;
    reassemblers[StreamPolicy::OS_BSD] = new TcpReassemblerBSD;
    reassemblers[StreamPolicy::OS_MACOS] = new TcpReassemblerMacOS;
    reassemblers[StreamPolicy::OS_SOLARIS] = new TcpReassemblerSolaris;
    reassemblers[StreamPolicy::OS_IRIX] = new TcpReassemblerIrix;
    reassemblers[StreamPolicy::OS_HPUX11] = new TcpReassemblerHpux11;
    reassemblers[StreamPolicy::OS_HPUX10] = new TcpReassemblerHpux10;
    reassemblers[StreamPolicy::OS_WINDOWS] = new TcpReassemblerWindows;
    reassemblers[StreamPolicy::OS_WINDOWS2K3] = new TcpReassemblerWindows2K3;
    reassemblers[StreamPolicy::OS_VISTA] = new TcpReassemblerVista;
    reassemblers[StreamPolicy::OS_PROXY] = new TcpReassemblerProxy;
}

void TcpReassemblerFactory::term()
{
    for ( auto sp = StreamPolicy::OS_FIRST; sp <= StreamPolicy::OS_PROXY; sp++ )
        delete reassemblers[sp];
}

TcpReassembler* TcpReassemblerFactory::get_instance(StreamPolicy os_policy)
{
    NormMode tcp_ips_data = Normalize_GetMode(NORM_TCP_IPS);
    StreamPolicy sp = (tcp_ips_data == NORM_MODE_ON) ? StreamPolicy::OS_FIRST : os_policy;

    assert( sp <= StreamPolicy::OS_PROXY );
    return reassemblers[sp];
}
