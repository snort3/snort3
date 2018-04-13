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

// tcp_state_closed.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_closed.h"

#include "tcp_session.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

TcpStateClosed::TcpStateClosed(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_CLOSED, tsm)
{
}

bool TcpStateClosed::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateClosed::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    snort::Flow* flow = tsd.get_flow();
    flow->set_expire(tsd.get_pkt(), trk.session->config->session_timeout);
    return true;
}

bool TcpStateClosed::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateClosed::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateClosed::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    snort::Flow* flow = tsd.get_flow();

    trk.update_tracker_ack_sent(tsd);
    // data on a segment when we're not accepting data any more alert!
    if ( flow->get_session_flags() & SSNFLAG_RESET )
    {
        if ( trk.is_rst_pkt_sent() )
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RESET);
        else
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    }
    else
        trk.session->tel.set_tcp_event(EVENT_DATA_ON_CLOSED);

    trk.session->mark_packet_for_drop(tsd);
    return true;
}

bool TcpStateClosed::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateClosed::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateClosed::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);

    if( tsd.get_seg_len() > 0 )
    {
        if ( trk.is_rst_pkt_sent() )
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RESET);
        else
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    }
    return true;
}

bool TcpStateClosed::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, false);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
    }
    else
    {
        trk.session->tel.set_tcp_event(EVENT_BAD_RST);
    }
    return true;
}

bool TcpStateClosed::do_pre_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    return trk.session->validate_packet_established_session(tsd);
}

bool TcpStateClosed::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->update_paws_timestamps(tsd);
    trk.session->check_for_window_slam(tsd);

    if ( trk.get_tcp_event() != TcpStreamTracker::TCP_FIN_RECV_EVENT )
    {
        TcpStreamTracker::TcpState talker_state = trk.session->get_talker_state();
        snort::Flow* flow = tsd.get_flow();

        if ( ( talker_state == TcpStreamTracker::TCP_TIME_WAIT ) || !flow->two_way_traffic() )
        {
            // The last ACK is a part of the session. Delete the session after processing is
            // complete.
            trk.session->clear_session(false, true, false, tsd.get_pkt() );
            flow->session_state |= STREAM_STATE_CLOSED;
            trk.session->set_pkt_action_flag(ACTION_LWSSN_CLOSED);
        }
    }

    return true;
}

#ifdef FOO  // FIXIT-H UNIT_TEST need work
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"

TEST_CASE("TCP State Closed", "[tcp_closed_state][stream_tcp]")
{
    // initialization code here
    snort::Flow* flow = new snort::Flow;
    TcpStreamTracker* ctrk = new TcpStreamTracker(true);
    TcpStreamTracker* strk = new TcpStreamTracker(false);
    TcpEventLogger* tel = new TcpEventLogger;
    TcpSession* session = new TcpSession(flow);
    TcpStateMachine* tsm =  new TcpStateMachine;
    TcpStateHandler* tsh = new TcpStateClosed(*tsm, *session);
    ctrk->normalizer = TcpNormalizerFactory::create(StreamPolicy::OS_LINUX, session, ctrk, strk);
    strk->normalizer = TcpNormalizerFactory::create(StreamPolicy::OS_LINUX, session, strk, ctrk);
    ctrk->reassembler = TcpReassemblerFactory::create(session, ctrk, StreamPolicy::OS_LINUX,
        false);
    strk->reassembler = TcpReassemblerFactory::create(session, strk, StreamPolicy::OS_LINUX, true);

    SECTION("syn_packet")
    {
        Packet* pkt = get_syn_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("syn_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK(TcpStreamTracker::TCP_SYN_SENT_EVENT == ctrk->get_tcp_event() );
            //CHECK( ( ctrk->get_iss() == 9050 ) );
            //CHECK( ( ctrk->get_snd_una() == 9051 ) );
            //CHECK( ( ctrk->get_snd_nxt() == 9050 ) );
            //CHECK( ( ctrk->get_snd_wnd() == 8192 ) );
        }

        SECTION("syn_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("syn_ack_packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("syn_ack_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("syn_ack_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("ack_packet")
    {
        Packet* pkt = get_ack_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("ack_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("ack_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("data_seg_packet")
    {
        Packet* pkt = get_data_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("data_seg_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("data_seg_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("fin_packet")
    {
        Packet* pkt = get_fin_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("fin_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        SECTION("fin_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    SECTION("rst_packet")
    {
        Packet* pkt = get_rst_packet(flow);
        REQUIRE( ( pkt != nullptr  ));

        SECTION("rst_sent")
        {
            flow->ssn_state.direction = FROM_CLIENT;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ));
        }

        SECTION("rst_recv")
        {
            flow->ssn_state.direction = FROM_SERVER;
            TcpSegmentDescriptor tsd(flow, pkt, tel);
            ctrk->set_tcp_event(tsd);
            ctrk->set_require_3whs(false);
            tsh->eval(tsd, *ctrk);
            CHECK( ( tsh->get_tcp_event() == ctrk->get_tcp_event() ) );
        }

        delete pkt;
    }

    delete flow;
    delete tsh;
    delete ctrk;
    delete strk;
}

#endif

