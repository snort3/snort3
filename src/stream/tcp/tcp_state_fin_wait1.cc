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

// tcp_state_fin_wait1.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_fin_wait1.h"

#include "tcp_normalizers.h"
#include "tcp_module.h"
#include "tcp_session.h"

using namespace snort;

TcpStateFinWait1::TcpStateFinWait1(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_FIN_WAIT1, tsm)
{ }

bool TcpStateFinWait1::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateFinWait1::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
    if ( tsd.is_data_segment() )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateFinWait1::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.is_data_segment() )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateFinWait1::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateFinWait1::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    check_for_window_slam(tsd, trk);
    return true;
}

bool TcpStateFinWait1::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateFinWait1::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    if ( check_for_window_slam(tsd, trk) )
        trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateFinWait1::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateFinWait1::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();
    bool is_ack_valid = false;

    trk.set_fin_seq_status_seen(tsd);
    trk.update_tracker_ack_recv(tsd);
    if ( SEQ_GEQ(tsd.get_end_seq(), trk.r_win_base) and
         check_for_window_slam(tsd, trk, &is_ack_valid) )
    {
        trk.perform_fin_recv_flush(tsd);
        trk.update_on_fin_recv(tsd);

        if ( !flow->two_way_traffic() )
            trk.set_tf_flags(TF_FORCE_FLUSH);

        if ( is_ack_valid )
            trk.set_tcp_state(TcpStreamTracker::TCP_TIME_WAIT);
        else
            trk.set_tcp_state(TcpStreamTracker::TCP_CLOSING);
    }
    return true;
}

bool TcpStateFinWait1::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, true);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
        tsd.get_flow()->session_state |= STREAM_STATE_CLOSED;
    }

    // FIXIT-L might be good to create alert specific to RST with data
    if ( tsd.is_data_segment() )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    return true;
}

bool TcpStateFinWait1::check_for_window_slam(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk, bool* is_ack_valid)
{
    if ( SEQ_EQ(tsd.get_ack(), trk.get_snd_nxt() ) )
    {
        if ( (trk.normalizer.get_os_policy() == StreamPolicy::OS_WINDOWS)
            && (tsd.get_wnd() == 0))
        {
            trk.session->tel.set_tcp_event(EVENT_WINDOW_SLAM);
            trk.normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
            trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
            return false;
        }

        trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT2);
        if ( is_ack_valid )
            *is_ack_valid = true;
    }
    else if ( is_ack_valid )
        *is_ack_valid = false;

    return true;
}

bool TcpStateFinWait1::do_pre_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    return trk.session->validate_packet_established_session(tsd);
}

bool TcpStateFinWait1::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->update_paws_timestamps(tsd);
    trk.session->check_for_window_slam(tsd);
    return true;
}

