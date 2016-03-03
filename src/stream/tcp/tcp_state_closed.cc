//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "stream/stream.h"

#include "tcp_module.h"
#include "tcp_tracker.h"
#include "tcp_session.h"
#include "tcp_normalizer.h"
#include "tcp_state_closed.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#include "stream/libtcp/stream_tcp_unit_test.h"
#endif

TcpStateClosed::TcpStateClosed(TcpStateMachine& tsm, TcpSession& ssn) :
    TcpStateHandler(TcpStreamTracker::TCP_CLOSED, tsm), session(ssn)
{
}

TcpStateClosed::~TcpStateClosed()
{
}

bool TcpStateClosed::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.s_mgr.sub_state |= SUB_SYN_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
    if ( tsd.get_seg_len() )
        session.handle_data_on_syn(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.s_mgr.sub_state |= ( SUB_SYN_SENT | SUB_ACK_SENT );

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_sent(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_recv(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_sent(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_recv(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_sent(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_recv(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk);
}

bool TcpStateClosed::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.update_on_rst_recv(tsd) )
    {
        session.update_session_on_rst(tsd, false);
        session.update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        session.set_pkt_action_flag(ACTION_RST);
    }
    else
    {
        session.tel.set_tcp_event(EVENT_BAD_RST);
    }

    return default_state_action(tsd, trk);
}

#ifdef FOO  // FIXIT - UNIT_TEST need work!!
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"

TEST_CASE("TCP State Closed", "[tcp_closed_state][stream_tcp]")
{
    // initialization code here
    Flow* flow = new Flow;
    TcpTracker* ctrk = new TcpTracker(true);
    TcpTracker* strk = new TcpTracker(false);
    TcpEventLogger* tel = new TcpEventLogger;
    TcpSession* session = new TcpSession(flow);
    TcpStateMachine* tsm =  new TcpStateMachine;
    TcpStateHandler* tsh = new TcpStateClosed(*tsm, *session);
    ctrk->normalizer = TcpNormalizerFactory::create(session, StreamPolicy::OS_LINUX, ctrk, strk);
    strk->normalizer = TcpNormalizerFactory::create(session, StreamPolicy::OS_LINUX, strk, ctrk);
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

