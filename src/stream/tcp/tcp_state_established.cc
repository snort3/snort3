//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_established.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_established.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateEstablished::TcpStateEstablished(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_ESTABLISHED, tsm)
{ }

bool TcpStateEstablished::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateEstablished::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
    return true;
}

bool TcpStateEstablished::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->tcp_config->midstream_allowed(tsd.get_pkt()) )
    {
        // FIXIT-M there may be an issue when syn/ack from server is seen
        // after ack from client which causes some tracker state variables to
        // not be initialized... update_tracker_ack_sent may fix that but needs
        // more testing
        //trk.update_tracker_ack_sent( tsd );
        Flow* flow = tsd.get_flow();
        if ( !(flow->session_state & STREAM_STATE_ESTABLISHED) )
        {
            /* SYN-ACK from server */
            if (flow->session_state != STREAM_STATE_NONE)
                trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }

    if ( trk.is_server_tracker() )
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs() );

    return true;
}

bool TcpStateEstablished::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateEstablished::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateEstablished::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    if ( trk.session->no_ack_mode_enabled() )
        trk.update_tracker_no_ack_recv(tsd);
    return true;
}

bool TcpStateEstablished::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    trk.session->handle_data_segment(tsd);
    if ( trk.session->no_ack_mode_enabled() )
        trk.update_tracker_no_ack_sent(tsd);
    return true;
}

bool TcpStateEstablished::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_on_fin_sent(tsd);
    trk.session->flow->call_handlers(tsd.get_pkt(), true);
    trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT1);
    return true;
}

bool TcpStateEstablished::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.set_fin_seq_status_seen(tsd);
    trk.update_tracker_ack_recv(tsd);
    trk.perform_fin_recv_flush(tsd);

    if ( trk.update_on_fin_recv(tsd) )
    {
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.set_tcp_state(TcpStreamTracker::TCP_CLOSE_WAIT);
    }

    return true;
}

bool TcpStateEstablished::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, false);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
    }

    // FIXIT-L might be good to create alert specific to RST with data
    if ( tsd.is_data_segment() )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);

    return true;
}

bool TcpStateEstablished::do_pre_sm_packet_actions(
    TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    return trk.session->validate_packet_established_session(tsd);
}

bool TcpStateEstablished::do_post_sm_packet_actions(
    TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->update_paws_timestamps(tsd);
    trk.session->check_for_window_slam(tsd);

    return true;
}

