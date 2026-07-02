//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_mid_stream_sent.cc author Ron Dempster <rdempste@cisco.com>
// Created on: Dec 7, 2022

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_mid_stream_sent.h"

#include "stream/stream_log.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateMidStreamSent::TcpStateMidStreamSent(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_MID_STREAM_SENT, tsm)
{ }

bool TcpStateMidStreamSent::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateMidStreamSent::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph());
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateMidStreamSent::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateMidStreamSent::syn_ack_recv(TcpSegmentDescriptor&, TcpStreamTracker& trk)
{
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateMidStreamSent::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.validate_sent_seq(tsd) )
        trk.update_tracker_ack_sent(tsd);

    return true;
}

bool TcpStateMidStreamSent::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.normalizer.validate_rcvd_seq(tsd) )
        trk.update_tracker_ack_recv(tsd);

    trk.session->set_established(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);

    return true;
}

bool TcpStateMidStreamSent::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateMidStreamSent::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    trk.seglist.set_seglist_base_seq(tsd.get_seq());
    trk.session->handle_data_segment(tsd);
    trk.session->set_established(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
 }

bool TcpStateMidStreamSent::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.validate_sent_seq(tsd) )
    {
        trk.update_on_fin_sent(tsd);
        trk.session->flow->call_handlers(tsd.get_pkt(), FlowDataStore::HANDLER_EOF);

        TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
        if ( TcpStreamTracker::TCP_FIN_WAIT1 == listener_state )
            trk.set_tcp_state(TcpStreamTracker::TCP_LAST_ACK);
        else
            trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT1);
    }

    return true;
}

bool TcpStateMidStreamSent::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( !trk.normalizer.validate_rcvd_seq(tsd) )
        return true;

    TcpStreamTracker::TcpState talker_state = tsd.get_talker()->get_tcp_state();
    if ( TcpStreamTracker::TCP_LAST_ACK == talker_state )
    {
        trk.set_fin_seq_status_seen(tsd);
        bool is_ack_valid = false;
        bool seq_in_window = SEQ_GEQ(tsd.get_end_seq(), trk.r_win_base);
        bool slam_ok = seq_in_window and check_for_window_slam(tsd, trk, is_ack_valid);
        trk.update_tracker_ack_recv(tsd);
        if ( slam_ok )
        {
            trk.perform_fin_recv_flush(tsd);
            trk.update_on_fin_recv(tsd);

            if ( is_ack_valid )
                trk.set_tcp_state(TcpStreamTracker::TCP_TIME_WAIT);
            else
                trk.set_tcp_state(TcpStreamTracker::TCP_CLOSING);
        }
    }
    else if ( trk.update_on_fin_recv(tsd) )
    {
        trk.set_fin_seq_status_seen(tsd);
        trk.update_tracker_ack_recv(tsd);
        trk.session->set_established(tsd);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.perform_fin_recv_flush(tsd);

        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.set_tcp_state(TcpStreamTracker::TCP_CLOSE_WAIT);
    }
    return true;
}

bool TcpStateMidStreamSent::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.is_data_segment() )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);

    trk.handle_rst_packet(tsd, false);

    return true;
}

bool TcpStateMidStreamSent::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_pseudo_established(tsd.get_pkt());
    trk.session->update_paws_timestamps(tsd);
    trk.session->check_for_window_slam(tsd);
    return true;
}

bool TcpStateMidStreamSent::check_for_window_slam(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk, bool& is_ack_valid)
{
    // Transition to FIN_WAIT2 when ACK exactly acknowledges our FIN; drop Windows zero-window slam (RFC 9293 s3.10.7.4).
    if ( SEQ_EQ(tsd.get_ack(), trk.get_snd_nxt() ) )
    {
        if ( (trk.normalizer.get_norm_policy() == Normalizer::Policy::OS_WINDOWS)
            && (tsd.get_wnd() == 0))
        {
            stream_log(tsd.get_pkt(), "stream_tcp: window slam, wnd=0 in MID_STREAM_SENT\n");
            trk.session->tel.set_tcp_event(EVENT_WINDOW_SLAM);
            trk.normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
            trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
            return false;
        }

        trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT2);
        is_ack_valid = true;
    }

    return true;
}
