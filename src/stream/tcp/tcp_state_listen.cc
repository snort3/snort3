//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_listen.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_listen.h"

#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"

#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateListen::TcpStateListen(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_LISTEN, tsm)
{
}

bool TcpStateListen::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.init_on_syn_recv(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
    trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd) );
    if ( tsd.is_data_segment() )
        trk.session->handle_data_on_syn(tsd);
    return true;
}

bool TcpStateListen::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        trk.init_on_synack_sent(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph(), trk.session->tcp_config->require_3whs());
        trk.session->init_new_tcp_session(tsd);
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::ack_sent(TcpSegmentDescriptor&, TcpStreamTracker& trk)
{
    if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        Flow* flow = tsd.get_flow();

        flow->session_state |= STREAM_STATE_MIDSTREAM;
        if ( !Stream::is_midstream(flow) )
        {
            flow->set_session_flags(SSNFLAG_MIDSTREAM);
            DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_MIDSTREAM, tsd.get_pkt());
        }

        trk.init_on_data_seg_sent(tsd);
        trk.session->init_new_tcp_session(tsd);
    }
    else if ( trk.session->tcp_config->require_3whs() )
    {
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        Flow* flow = tsd.get_flow();
        flow->session_state |= STREAM_STATE_MIDSTREAM;
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

bool TcpStateListen::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( !trk.session->is_midstream_allowed(tsd) && trk.session->tcp_config->require_3whs() )
    {
        // FIXIT-L listen gets fin triggers 129:20 ??
        trk.session->generate_no_3whs_event();
        return false;
    }
    return true;
}

bool TcpStateListen::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->is_midstream_allowed(tsd) )
    {
        // FIXIT-L handle FIN on midstream
    }
    else if ( trk.session->tcp_config->require_3whs() )
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

bool TcpStateListen::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_one_sided_session(tsd.get_pkt());
    return true;
}

