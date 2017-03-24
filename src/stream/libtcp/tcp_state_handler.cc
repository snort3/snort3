//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_handler.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jun 24, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_handler.h"

#include <iostream>

#include "main/snort_debug.h"

#include "tcp_state_machine.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

using namespace std;

TcpStateHandler::TcpStateHandler(TcpStreamTracker::TcpState state, TcpStateMachine& tsm)
    : tsm(&tsm), tcp_state(state)
{
    tsm.register_state_handler(state, *this);
}

//TcpStateHandler::TcpStateHandler() :
//    tsm(nullptr), tcp_state(TcpStreamTracker::TCP_CLOSED), session(*(new
// TcpStreamSession(nullptr)))
//{
//}

TcpStateHandler::~TcpStateHandler()
{
    // TODO Auto-generated destructor stub
}

bool TcpStateHandler::do_pre_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&)
{
    return true;
}

bool TcpStateHandler::do_post_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&)
{
    return true;
}

bool TcpStateHandler::eval(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    bool handled = false;

    switch ( tracker.get_tcp_event() )
    {
    case TcpStreamTracker::TCP_SYN_SENT_EVENT:
        handled = syn_sent(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_SYN_RECV_EVENT:
        handled = syn_recv(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_SYN_ACK_SENT_EVENT:
        handled = syn_ack_sent(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_SYN_ACK_RECV_EVENT:
        handled = syn_ack_recv(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_ACK_SENT_EVENT:
        handled = ack_sent(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_ACK_RECV_EVENT:
        handled = ack_recv(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_DATA_SEG_SENT_EVENT:
        handled = data_seg_sent(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_DATA_SEG_RECV_EVENT:
        handled = data_seg_recv(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_FIN_SENT_EVENT:
        handled = fin_sent(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_FIN_RECV_EVENT:
        handled = fin_recv(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_RST_SENT_EVENT:
        handled = rst_sent(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_RST_RECV_EVENT:
        handled = rst_recv(tsd, tracker);
        break;

    case TcpStreamTracker::TCP_MAX_EVENTS:
    default:
        cout << "Invalid Tcp Event " << tracker.get_tcp_event() << endl;
        break;
    }

    return handled;
}

bool TcpStateHandler::default_state_action(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_STREAM_STATE, "tsd: %p tracker: %p state: %u event: %u\n",
        (void*) &tsd, (void*) &tracker, tracker.get_tcp_state(), tracker.get_tcp_event() );
#else
    UNUSED(tsd);
    UNUSED(tracker);
#endif

    return true;
}

bool TcpStateHandler::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

bool TcpStateHandler::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    return default_state_action(tsd, tracker);
}

// FIXIT-H get the unit test working again
#ifdef UNIT_TEST_FOO

SCENARIO("TCP State Handler Base Class", "[state_handlers][stream_tcp]")
{
    // initialization code here
    Flow* flow = new Flow;
    TcpStateHandler* tsh = new TcpStateHandler;
    TcpStreamTracker* client_tracker = new TcpStreamTracker(true);
    TcpStreamTracker* server_tracker = new TcpStreamTracker(false);
    TcpEventLogger tel;

    GIVEN("a SYN Packet")
    {
        Packet* pkt = get_syn_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        WHEN("SYN is sent")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            client_tracker->set_tcp_event(TcpStreamTracker::TCP_SYN_SENT_EVENT);
            tsh->eval(*tsd, *client_tracker);
            THEN("Event should be TCP_SYN_SENT_EVENT")
            {
                CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
            }
            delete tsd;
        }

        SECTION("SYN is received")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            server_tracker->set_tcp_event(TcpStreamTracker::TCP_SYN_RECV_EVENT);
            tsh->eval(*tsd, *server_tracker);
            CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
            delete tsd;
        }

        delete pkt;
    }

    SECTION("syn_ack_packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("syn_ack_sent")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            client_tracker->set_tcp_event(TcpStreamTracker::TCP_SYN_ACK_SENT_EVENT);
            tsh->eval(*tsd, *client_tracker);
            CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
            delete tsd;
        }

        SECTION("syn_ack_recv")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            server_tracker->set_tcp_event(TcpStreamTracker::TCP_SYN_ACK_RECV_EVENT);
            tsh->eval(*tsd, *server_tracker);
            CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
            delete tsd;
        }

        delete pkt;
    }

    SECTION("ack_packet")
    {
        Packet* pkt = get_ack_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("ack_sent")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            client_tracker->set_tcp_event(TcpStreamTracker::TCP_ACK_SENT_EVENT);
            tsh->eval(*tsd, *client_tracker);
            CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
            delete tsd;
        }

        SECTION("ack_recv")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            server_tracker->set_tcp_event(TcpStreamTracker::TCP_ACK_RECV_EVENT);
            tsh->eval(*tsd, *server_tracker);
            CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
            delete tsd;
        }

        delete pkt;
    }

    SECTION("data_seg_packet")
    {
        Packet* pkt = get_data_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("data_seg_sent")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            client_tracker->set_tcp_event(TcpStreamTracker::TCP_DATA_SEG_SENT_EVENT);
            tsh->eval(*tsd, *client_tracker);
            CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
            delete tsd;
        }

        SECTION("data_seg_recv")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            server_tracker->set_tcp_event(TcpStreamTracker::TCP_DATA_SEG_RECV_EVENT);
            tsh->eval(*tsd, *server_tracker);
            CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
            delete tsd;
        }

        delete pkt;
    }

    SECTION("fin_packet")
    {
        Packet* pkt = get_fin_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("fin_sent")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            client_tracker->set_tcp_event(TcpStreamTracker::TCP_FIN_SENT_EVENT);
            tsh->eval(*tsd, *client_tracker);
            CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
            delete tsd;
        }

        SECTION("fin_recv")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            server_tracker->set_tcp_event(TcpStreamTracker::TCP_FIN_RECV_EVENT);
            tsh->eval(*tsd, *server_tracker);
            CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
            delete tsd;
        }

        delete pkt;
    }

    SECTION("rst_packet")
    {
        Packet* pkt = get_rst_packet(flow);
        REQUIRE( ( pkt != nullptr ) );

        SECTION("rst_sent")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            client_tracker->set_tcp_event(TcpStreamTracker::TCP_RST_SENT_EVENT);
            tsh->eval(*tsd, *client_tracker);
            CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
            delete tsd;
        }

        SECTION("rst_recv")
        {
            TcpSegmentDescriptor* tsd = new TcpSegmentDescriptor(flow, pkt, tel);
            REQUIRE( ( tsd != nullptr ) );
            server_tracker->set_tcp_event(TcpStreamTracker::TCP_RST_RECV_EVENT);
            tsh->eval(*tsd, *server_tracker);
            CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
            delete tsd;
        }

        delete pkt;
    }

    delete flow;
    delete tsh;
    delete client_tracker;
    delete server_tracker;
}

#endif

