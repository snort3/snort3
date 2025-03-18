//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "packet_io/packet_tracer.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"

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

    trk.init_on_syn_sent(tsd);
    trk.session->init_new_tcp_session(tsd);
    return true;
}

bool TcpStateNone::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.init_on_synack_recv(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph());
    if ( tsd.is_data_segment() )
        trk.session->handle_data_segment(tsd, !trk.normalizer.is_tcp_ips_enabled());
    return true;
}

bool TcpStateNone::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();
    flow->session_state |= STREAM_STATE_MIDSTREAM;

    assert ( !Stream::is_midstream(flow) );

    trk.normalizer.init(Normalizer::Policy::MISSED_3WHS, trk.session, &trk, tsd.get_listener());
    flow->set_session_flags(SSNFLAG_MIDSTREAM);
    DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_MIDSTREAM, tsd.get_pkt());

    trk.init_on_data_seg_sent(tsd);
    trk.session->init_new_tcp_session(tsd);
    return true;
}

bool TcpStateNone::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.normalizer.init(Normalizer::Policy::MISSED_3WHS, trk.session, &trk, tsd.get_talker());
    trk.init_on_data_seg_recv(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph());
    trk.session->handle_data_segment(tsd, !trk.normalizer.is_tcp_ips_enabled());
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

bool TcpStateNone::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_one_sided_session(tsd.get_pkt());
    return true;
}

