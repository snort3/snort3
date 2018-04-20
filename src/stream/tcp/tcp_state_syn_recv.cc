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

// tcp_state_syn_recv.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Aug 5, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_syn_recv.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;
using namespace std;

TcpStateSynRecv::TcpStateSynRecv(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_SYN_RECV, tsm)
{
}

bool TcpStateSynRecv::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();

    trk.finish_server_init(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
    trk.session->update_timestamp_tracking(tsd);
    if ( tsd.get_tcph()->are_flags_set(TH_ECE) &&
        ( flow->get_session_flags() & SSNFLAG_ECN_CLIENT_QUERY ) )
        flow->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

    if ( tsd.get_pkt()->is_from_server() )
    {
        flow->set_session_flags(SSNFLAG_SEEN_SERVER);
        trk.session->tel.set_tcp_event(EVENT_4WHS);
    }
    return true;
}

bool TcpStateSynRecv::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.get_seg_len() )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateSynRecv::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();

    // FIXIT-H verify ack being sent is valid...
    trk.finish_server_init(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
    flow->session_state |= STREAM_STATE_SYN_ACK;
    return true;
}

bool TcpStateSynRecv::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.is_ack_valid(tsd.get_seg_ack() ) )
    {
        Flow* flow = tsd.get_flow();

        trk.update_tracker_ack_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
        flow->set_session_flags(SSNFLAG_ESTABLISHED);
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        if ( tsd.get_seg_len() )
            trk.session->handle_data_on_syn(tsd);
    }
    return true;
}

bool TcpStateSynRecv::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->config->midstream_allowed(tsd.get_pkt()) )
    {
        trk.session->update_session_on_ack( );
    }
    return true;
}

bool TcpStateSynRecv::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.is_ack_valid(tsd.get_seg_ack() ) )
    {
        Flow* flow = tsd.get_flow();

        trk.update_tracker_ack_recv(tsd);
        trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd));
        tsd.get_pkt()->packet_flags |= PKT_STREAM_TWH;
        flow->set_session_flags(SSNFLAG_ESTABLISHED);
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        if ( tsd.get_seg_len() > 0 )
            trk.session->handle_data_segment(tsd);
        else
            trk.session->check_for_window_slam(tsd);
    }
    return true;
}

bool TcpStateSynRecv::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.is_ack_valid(tsd.get_seg_ack() ) )
    {
        trk.update_tracker_ack_recv(tsd);
        tsd.get_pkt()->packet_flags |= PKT_STREAM_TWH;
        trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd));
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    if ( tsd.get_seg_len() > 0 )
        trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateSynRecv::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.get_tcph()->is_ack() )
    {
        Flow* flow = tsd.get_flow();

        trk.update_tracker_ack_recv(tsd);
        trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd));
        flow->session_state |= STREAM_STATE_ACK;
        if ( tsd.get_seg_len() > 0 )
        {
            trk.session->handle_data_segment(tsd);
            trk.flush_data_on_fin_recv(tsd);
        }

        if ( trk.update_on_fin_recv(tsd) )
        {
            trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
            trk.set_tcp_state(TcpStreamTracker::TCP_CLOSE_WAIT);
        }
    }
    return true;
}

bool TcpStateSynRecv::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.normalizer.trim_rst_payload(tsd);
    if ( trk.normalizer.validate_rst(tsd) )
    {
        Flow* flow = tsd.get_flow();

        flow->set_session_flags(SSNFLAG_RESET);
        if ( trk.normalizer.is_tcp_ips_enabled() )
            tcp_state = TcpStreamTracker::TCP_LISTEN;
    }
    else
    {
        inc_tcp_discards();
        trk.normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        trk.session->tel.set_tcp_event(EVENT_BAD_RST);
    }

    // FIXIT-L might be good to create alert specific to RST with data
    if ( tsd.get_seg_len() > 0 )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    return true;
}

bool TcpStateSynRecv::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_window_slam(tsd);

    return true;
}

