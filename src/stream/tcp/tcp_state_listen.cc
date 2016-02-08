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

// tcp_state_listen.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#include "tcp_module.h"
#include "tcp_tracker.h"
#include "tcp_session.h"
#include "tcp_normalizer.h"
#include "tcp_state_listen.h"

TcpStateListen::TcpStateListen(TcpStateMachine& tsm, TcpSession& ssn) :
    TcpStateHandler(TcpStreamTracker::TCP_LISTEN, tsm), session(ssn)
{
}

TcpStateListen::~TcpStateListen()
{
}

bool TcpStateListen::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->require_3whs() || tsd.has_wscale() || ( tsd.get_seg_len() > 0 ) )
    {
        // FIXIT - do we need this check? only server goes into Listen state...
        if ( tsd.get_pkt()->packet_flags & PKT_FROM_SERVER )
            session.tel.set_tcp_event(EVENT_4WHS);
    }

    trk.s_mgr.sub_state |= SUB_SYN_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateListen::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( true || session.config->require_3whs() || tsd.has_wscale() || ( tsd.get_seg_len() > 0 ) )
    {
        trk.init_on_syn_recv(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
        if ( tsd.get_seg_len() )
            session.handle_data_on_syn(tsd);
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    auto& trk = static_cast< TcpTracker& >( tracker );

    flow->session_state |= ( STREAM_STATE_SYN | STREAM_STATE_SYN_ACK );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
        trk.init_on_synack_sent(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
        session.init_new_tcp_session(tsd);
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( !session.config->require_3whs() || session.config->midstream_allowed(tsd.get_pkt() ) )
    {
        trk.init_on_synack_recv(tsd);
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) && ( tsd.has_wscale() ||
        ( tsd.get_seg_len() > 0 ) ) )
    {
        Flow* flow = tsd.get_flow();

        /* FIXIT: do we need to verify the ACK field is >= the seq of the SYN-ACK?
                   3-way Handshake complete, create TCP session */
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_SYN_ACK |
            STREAM_STATE_ESTABLISHED );
        trk.init_on_3whs_ack_sent(tsd);
        session.init_new_tcp_session(tsd);
        session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        tcpStats.sessions_on_3way++;
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) && ( tsd.has_wscale() ||
        ( tsd.get_seg_len() > 0 ) ) )
    {
        Flow* flow = tsd.get_flow();

        if ( !tsd.get_tcph()->is_rst() && ( flow->session_state & STREAM_STATE_SYN_ACK ) )
        {
            trk.init_on_3whs_ack_recv(tsd);
            trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
        }
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);

        trk.init_on_data_seg_sent(tsd);
        session.init_new_tcp_session(tsd);

        if ( flow->session_state & STREAM_STATE_ESTABLISHED )
            session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);

        tcpStats.sessions_on_data++;
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);
        trk.init_on_data_seg_recv(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
        // FIXIT - handle this
    }
    else if ( session.config->require_3whs() )
    {
        session.generate_no_3whs_event();
        return false;
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
    }

    return default_state_action(tsd, trk);
}

bool TcpStateListen::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt() ) )
    {
        // FIXIT - handle this
    }

    return default_state_action(tsd, trk);
}

