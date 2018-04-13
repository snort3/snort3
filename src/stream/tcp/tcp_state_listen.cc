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

// tcp_state_listen.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_listen.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateListen::TcpStateListen(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_LISTEN, tsm)
{
}

bool TcpStateListen::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->require_3whs() || tsd.has_wscale() || ( tsd.get_seg_len() > 0 ) )
    {
        // FIXIT-L do we need this check? only server goes into Listen state...
        if ( tsd.get_pkt()->is_from_server() )
            trk.session->tel.set_tcp_event(EVENT_4WHS);
    }
    return true;
}

bool TcpStateListen::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.init_on_syn_recv(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
    trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd) );
    if ( tsd.get_seg_len() > 0 )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateListen::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();
    flow->session_state |= ( STREAM_STATE_SYN | STREAM_STATE_SYN_ACK );

    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        trk.init_on_synack_sent(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
        trk.session->init_new_tcp_session(tsd);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( !trk.session->config->require_3whs() or
         trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        trk.init_on_synack_recv(tsd);
        if ( tsd.get_seg_len() > 0 )
            trk.session->handle_data_segment(tsd);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() )
            && ( tsd.has_wscale() || ( tsd.get_seg_len() > 0 ) ) )
    {
        Flow* flow = tsd.get_flow();

        // FIXIT-H do we need to verify the ACK field is >= the seq of the SYN-ACK?
        // 3-way Handshake complete, create TCP session
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_SYN_ACK |
            STREAM_STATE_ESTABLISHED );
        trk.init_on_3whs_ack_sent(tsd);
        trk.session->init_new_tcp_session(tsd);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() )
            && ( tsd.has_wscale() || ( tsd.get_seg_len() > 0 ) ) )
    {
        Flow* flow = tsd.get_flow();

        if ( !tsd.get_tcph()->is_rst() && ( flow->session_state & STREAM_STATE_SYN_ACK ) )
        {
            trk.init_on_3whs_ack_recv(tsd);
            trk.normalizer.ecn_tracker(
                tsd.get_tcph(), trk.session->config->require_3whs());
        }
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);

        trk.init_on_data_seg_sent(tsd);
        trk.session->init_new_tcp_session(tsd);

        if ( flow->session_state & STREAM_STATE_ESTABLISHED )
            trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        flow->set_session_flags(SSNFLAG_MIDSTREAM);
        trk.init_on_data_seg_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
        trk.session->handle_data_segment(tsd);
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( !trk.session->config->midstream_allowed(tsd.get_pkt()) and
        trk.session->config->require_3whs() )
    {
        // FIXIT-L listen gets fin triggers 129:20 ??
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt() ) )
    {
        // FIXIT-L handle FIN on midstream
    }
    else if ( trk.session->config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.normalizer.trim_rst_payload(tsd);
    return true;
}

