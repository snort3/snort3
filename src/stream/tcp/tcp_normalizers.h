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

// tcp_normalizers.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 22, 2015

#ifndef TCP_NORMALIZERS_H
#define TCP_NORMALIZERS_H

#include "tcp_defs.h"
#include "tcp_normalizer.h"


class TcpNormalizerFirst : public TcpNormalizer
{
public:
    TcpNormalizerFirst( TcpSession* session, TcpTracker* tracker ) :
        TcpNormalizer( STREAM_POLICY_FIRST, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerLast : public TcpNormalizer
{
public:
    TcpNormalizerLast( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_LAST, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerLinux : public TcpNormalizer
{
public:
    TcpNormalizerLinux( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_LINUX, session, tracker )
    {
        // Linux 2.6 accepts timestamp values that are off by one. so set fudge factor */
        paws_ts_fudge = 1;
    }

    bool validate_rst( TcpDataBlock* ) override;
    bool is_paws_ts_checked_required( TcpDataBlock* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerOldLinux : public TcpNormalizer
{
public:
    TcpNormalizerOldLinux( TcpSession* session, TcpTracker* tracker ) :
            TcpNormalizer( STREAM_POLICY_OLD_LINUX, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool validate_rst( TcpDataBlock* );
    bool is_paws_ts_checked_required( TcpDataBlock* );
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerBSD : public TcpNormalizer
{
public:
    TcpNormalizerBSD( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_BSD, session, tracker )
    { }

    bool validate_rst( TcpDataBlock* );
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerMacOS : public TcpNormalizer
{
public:
    TcpNormalizerMacOS( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_MACOS, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerSolaris : public TcpNormalizer
{
public:
    TcpNormalizerSolaris( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_SOLARIS, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool validate_rst( TcpDataBlock* );
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerIrix : public TcpNormalizer
{
public:
    TcpNormalizerIrix( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_IRIX, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerHpux11 : public TcpNormalizer
{
public:
    TcpNormalizerHpux11( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_HPUX11, session, tracker )
    { }

    bool validate_rst( TcpDataBlock* );
    bool is_paws_ts_checked_required( TcpDataBlock* );
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerHpux10 : public TcpNormalizer
{
public:
    TcpNormalizerHpux10( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_HPUX10, session, tracker )
    { }

    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerWindows : public TcpNormalizer
{
public:
    TcpNormalizerWindows( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_WINDOWS, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool is_paws_ts_checked_required( TcpDataBlock* );
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerWindows2K3 : public TcpNormalizer
{
public:
    TcpNormalizerWindows2K3( TcpSession* session, TcpTracker* tracker ) :
            TcpNormalizer( STREAM_POLICY_WINDOWS2K3, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool is_paws_ts_checked_required(  TcpDataBlock* );
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerVista : public TcpNormalizer
{
public:
    TcpNormalizerVista( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_VISTA, session, tracker )
    {
        paws_drop_zero_ts = false;
    }

    bool is_paws_ts_checked_required( TcpDataBlock*);
    int handle_repeated_syn( TcpDataBlock* );
};

class TcpNormalizerProxy : public TcpNormalizer
{
public:
    TcpNormalizerProxy( TcpSession* session, TcpTracker* tracker  ) :
            TcpNormalizer( STREAM_POLICY_PROXY, session, tracker )
    { }

    bool validate_rst(TcpDataBlock* ) override;
    int handle_paws( TcpDataBlock*,int*, int* ) override;
    int handle_repeated_syn( TcpDataBlock* ) override;
};

class TcpNormalizerFactory
{
public:
    static TcpNormalizer* allocate_normalizer( uint16_t, TcpSession*, TcpTracker*, TcpTracker* );
};




#endif /* TCP_NORMALIZERS_H_ */
