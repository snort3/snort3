//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_fin_wait1.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#include <iostream>
using namespace std;

#include "tcp_module.h"
#include "tcp_tracker.h"
#include "tcp_session.h"
#include "tcp_normalizer.h"
#include "tcp_state_fin_wait1.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

TcpStateFinWait1::TcpStateFinWait1(TcpStateMachine& tsm, TcpSession& ssn) :
    TcpStateHandler(TcpStreamTracker::TCP_FIN_WAIT1, tsm), session(ssn)
{
}

TcpStateFinWait1::~TcpStateFinWait1()
{
}

bool TcpStateFinWait1::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

bool TcpStateFinWait1::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    TcpTracker& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk, __func__);
}

