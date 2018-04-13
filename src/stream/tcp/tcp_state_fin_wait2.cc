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

// tcp_state_fin_wait2.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_fin_wait2.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace std;

TcpStateFinWait2::TcpStateFinWait2(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_FIN_WAIT2, tsm)
{
}

bool TcpStateFinWait2::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateFinWait2::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->config->require_3whs());
    if ( tsd.get_seg_len() )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateFinWait2::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.get_seg_len() )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateFinWait2::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateFinWait2::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( SEQ_GT(tsd.get_seg_ack(), trk.get_snd_nxt() ) )
    {
        trk.normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        trk.session->tel.set_tcp_event(EVENT_BAD_ACK);
        trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
    }
    else
        trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateFinWait2::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    // data on a segment when we shouldn't be sending data any more alert!
    trk.session->tel.set_tcp_event(EVENT_DATA_ON_CLOSED);
    trk.session->mark_packet_for_drop(tsd);
    return true;
}

bool TcpStateFinWait2::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( SEQ_GT(tsd.get_seg_ack(), trk.get_snd_nxt() ) )
    {
        trk.normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        trk.session->tel.set_tcp_event(EVENT_BAD_ACK);
        trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
    }
    else
    {
        trk.update_tracker_ack_recv(tsd);
        if ( tsd.get_seg_len() > 0 )
            trk.session->handle_data_segment(tsd);
    }
    return true;
}

bool TcpStateFinWait2::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    snort::Flow* flow = tsd.get_flow();

    trk.update_tracker_ack_recv(tsd);
    if ( trk.update_on_fin_recv(tsd) )
    {
        if ( tsd.get_seg_len() > 0 )
            trk.session->handle_data_segment(tsd);

        if ( !flow->two_way_traffic() )
            trk.set_tf_flags(TF_FORCE_FLUSH);

        trk.set_tcp_state(TcpStreamTracker::TCP_TIME_WAIT);
    }
    return true;
}

bool TcpStateFinWait2::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, true);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
        tsd.get_pkt()->flow->session_state |= STREAM_STATE_CLOSED;
    }
    else
    {
        trk.session->tel.set_tcp_event(EVENT_BAD_RST);
    }
    return true;
}

bool TcpStateFinWait2::do_pre_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    return trk.session->validate_packet_established_session(tsd);
}

bool TcpStateFinWait2::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->update_paws_timestamps(tsd);
    trk.session->check_for_window_slam(tsd);
    return true;
}

