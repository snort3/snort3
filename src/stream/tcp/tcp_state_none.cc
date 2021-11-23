//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_none.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_none.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateNone::TcpStateNone(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_STATE_NONE, tsm)
{ }

bool TcpStateNone::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();
    flow->ssn_state.direction = FROM_CLIENT;
    flow->session_state |= STREAM_STATE_SYN;

    trk.init_on_syn_sent(tsd);
    trk.session->init_new_tcp_session(tsd);
    return true;
}

bool TcpStateNone::syn_recv(TcpSegmentDescriptor&, TcpStreamTracker&)
{
    return true;
}

bool TcpStateNone::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();

    if ( !trk.session->tcp_config->require_3whs() or trk.session->is_midstream_allowed(tsd) )
    {
        flow->session_state |= ( STREAM_STATE_SYN | STREAM_STATE_SYN_ACK );
        trk.init_on_synack_sent(tsd);
        trk.session->init_new_tcp_session(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        trk.init_on_synack_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
        if ( tsd.is_data_segment() )
            trk.session->handle_data_segment(tsd);
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) && tsd.has_wscale() )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_SYN_ACK |
            STREAM_STATE_ESTABLISHED );
        trk.init_on_3whs_ack_sent(tsd);
        trk.session->init_new_tcp_session(tsd);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) && tsd.has_wscale() )
    {
        Flow* flow = tsd.get_flow();

        if ( !tsd.get_tcph()->is_rst() && ( flow->session_state & STREAM_STATE_SYN_ACK ) )
        {
            trk.init_on_3whs_ack_recv(tsd);
            trk.normalizer.ecn_tracker(
                tsd.get_tcph(), trk.session->tcp_config->require_3whs());
        }
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        if ( !Stream::is_midstream(flow) )
        {
            flow->set_session_flags(SSNFLAG_MIDSTREAM);
            DataBus::publish(STREAM_TCP_MIDSTREAM_EVENT, tsd.get_pkt());
        }

        trk.init_on_data_seg_sent(tsd);
        trk.session->init_new_tcp_session(tsd);

        if ( flow->session_state & STREAM_STATE_ESTABLISHED )
            trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        if ( !Stream::is_midstream(flow) )
        {
            flow->set_session_flags(SSNFLAG_MIDSTREAM);
            DataBus::publish(STREAM_TCP_MIDSTREAM_EVENT, tsd.get_pkt());
        }

        trk.init_on_data_seg_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
        trk.session->handle_data_segment(tsd);
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        // FIXIT-M handle FIN on midstream
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        // FIXIT-M handle FIN on midstream
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateNone::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        // FIXIT-M handle RST on midstream
    }
    return true;
}

bool TcpStateNone::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, false);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
    }

    return true;
}

