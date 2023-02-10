//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_mid_stream_recv.cc author Ron Dempster <rdempste@cisco.com>
// Created on: Dec 7, 2022

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_mid_stream_recv.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateMidStreamRecv::TcpStateMidStreamRecv(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_MID_STREAM_RECV, tsm)
{
}

bool TcpStateMidStreamRecv::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateMidStreamRecv::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
    return true;
}

bool TcpStateMidStreamRecv::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateMidStreamRecv::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateMidStreamRecv::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateMidStreamRecv::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    if ( trk.session->no_ack_mode_enabled() )
        trk.update_tracker_no_ack_recv(tsd);
    return true;
}

bool TcpStateMidStreamRecv::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateMidStreamRecv::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_on_fin_sent(tsd);
    trk.session->flow->call_handlers(tsd.get_pkt(), true);
    TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
    // If one sided has sent a FIN
    if ( TcpStreamTracker::TCP_FIN_WAIT1 == listener_state )
        trk.set_tcp_state(TcpStreamTracker::TCP_LAST_ACK);
    else
        trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT1);
    return true;
}

bool TcpStateMidStreamRecv::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
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

bool TcpStateMidStreamRecv::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
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

bool TcpStateMidStreamRecv::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    // Always need to check for one sided
    bool one_sided = trk.session->check_for_one_sided_session(tsd.get_pkt());
    if ( one_sided && TcpStreamTracker::TCP_MID_STREAM_RECV == trk.get_tcp_state() )
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

