//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <iostream>
using namespace std;

#include "tcp_state_handler.h"

#include "main/snort_debug.h"

#ifdef UNIT_TEST
#include "test/catch.hpp"
#include "stream_tcp_unit_test.h"
#endif


TcpStateHandler::TcpStateHandler() :
		tcp_event( TcpStreamTracker::TCP_MAX_EVENTS )
{
    // TODO Auto-generated constructor stub

}

TcpStateHandler::~TcpStateHandler()
{
    // TODO Auto-generated destructor stub

}

void TcpStateHandler::eval( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
    switch( tcp_event = tracker.get_tcp_event() )
    {
    case TcpStreamTracker::TCP_SYN_SENT_EVENT:
        syn_sent( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_SYN_RECV_EVENT:
        syn_recv( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_SYN_ACK_SENT_EVENT:
        syn_ack_sent( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_SYN_ACK_RECV_EVENT:
        syn_ack_recv( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_ACK_SENT_EVENT:
        ack_sent( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_ACK_RECV_EVENT:
        ack_recv( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_DATA_SEG_SENT_EVENT:
        data_seg_sent( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_DATA_SEG_RECV_EVENT:
        data_seg_recv( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_FIN_SENT_EVENT:
        fin_sent( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_FIN_RECV_EVENT:
        fin_recv( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_RST_SENT_EVENT:
        rst_sent( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_RST_RECV_EVENT:
        rst_recv( tcp_seg, tracker );
        break;

    case TcpStreamTracker::TCP_MAX_EVENTS:
    default:
        cout << "Invalid Tcp Event " << tracker.get_tcp_event() << endl;
        break;

    }
}

void TcpStateHandler::default_state_action(
    TcpSegmentDescriptor* tcp_seg, TcpStreamTracker* tracker, const char* func_name )
{
#ifdef DEBUG_MSGS
    DebugFormat(DEBUG_STREAM_STATE, "Default Implementation of: %s tcp_seg: %p tracker: %p\n",
        func_name, tcp_seg, tracker );
#else
    UNUSED(tcp_seg);
    UNUSED(func_name);
#endif

    tcp_event = tracker->get_tcp_event();
}

void TcpStateHandler::syn_sent( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::syn_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::syn_ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::syn_ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::data_seg_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::data_seg_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::fin_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::fin_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::rst_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::rst_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

#ifdef UNIT_TEST

SCENARIO("TCP State Handler Base Class", "[state_handlers][stream_tcp]")
{
     // initialization code here
	 Flow* flow = new Flow;
	 TcpStateHandler* tsh = new TcpStateHandler;
     TcpStreamTracker* client_tracker = new TcpStreamTracker( true );
     TcpStreamTracker* server_tracker = new TcpStreamTracker( false );

     GIVEN("a SYN Packet")
     {
       	 Packet* pkt = get_syn_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 WHEN("SYN is sent")
         {
             TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
             REQUIRE( ( tcp_seg != nullptr ) );
             client_tracker->set_tcp_event( TcpStreamTracker::TCP_SYN_SENT_EVENT );
             tsh->eval( *tcp_seg, *client_tracker );
             THEN("Event should be TCP_SYN_SENT_EVENT")
             {
                 CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
             }
             delete tcp_seg;
         }

         SECTION("SYN is received")
         {
              TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
              REQUIRE( ( tcp_seg != nullptr ) );
              server_tracker->set_tcp_event( TcpStreamTracker::TCP_SYN_RECV_EVENT );
              tsh->eval( *tcp_seg, *server_tracker );
              CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
              delete tcp_seg;
         }

         delete pkt;
     }

     SECTION("syn_ack_packet")
     {
       	 Packet* pkt = get_syn_ack_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("syn_ack_sent")
         {
             TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
             REQUIRE( ( tcp_seg != nullptr ) );
             client_tracker->set_tcp_event( TcpStreamTracker::TCP_SYN_ACK_SENT_EVENT );
             tsh->eval( *tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
             delete tcp_seg;
         }

         SECTION("syn_ack_recv")
         {
              TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
              REQUIRE( ( tcp_seg != nullptr ) );
              server_tracker->set_tcp_event( TcpStreamTracker::TCP_SYN_ACK_RECV_EVENT );
              tsh->eval( *tcp_seg, *server_tracker );
              CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
              delete tcp_seg;
         }

         delete pkt;
     }

     SECTION("ack_packet")
     {
       	 Packet* pkt = get_ack_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("ack_sent")
         {
             TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
             REQUIRE( ( tcp_seg != nullptr ) );
             client_tracker->set_tcp_event( TcpStreamTracker::TCP_ACK_SENT_EVENT );
             tsh->eval( *tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
             delete tcp_seg;
         }

         SECTION("ack_recv")
         {
              TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
              REQUIRE( ( tcp_seg != nullptr ) );
              server_tracker->set_tcp_event( TcpStreamTracker::TCP_ACK_RECV_EVENT );
              tsh->eval( *tcp_seg, *server_tracker );
              CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
              delete tcp_seg;
         }

         delete pkt;
     }

     SECTION("data_seg_packet")
     {
       	 Packet* pkt = get_data_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("data_seg_sent")
         {
             TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
             REQUIRE( ( tcp_seg != nullptr ) );
             client_tracker->set_tcp_event( TcpStreamTracker::TCP_DATA_SEG_SENT_EVENT );
             tsh->eval( *tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
             delete tcp_seg;
         }

         SECTION("data_seg_recv")
         {
              TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
              REQUIRE( ( tcp_seg != nullptr ) );
              server_tracker->set_tcp_event( TcpStreamTracker::TCP_DATA_SEG_RECV_EVENT );
              tsh->eval( *tcp_seg, *server_tracker );
              CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
              delete tcp_seg;
         }

         delete pkt;
     }

     SECTION("fin_packet")
      {
        	 Packet* pkt = get_fin_packet( flow );
        	 REQUIRE( ( pkt != nullptr ) );

        	 SECTION("fin_sent")
          {
              TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
              REQUIRE( ( tcp_seg != nullptr ) );
              client_tracker->set_tcp_event( TcpStreamTracker::TCP_FIN_SENT_EVENT );
              tsh->eval( *tcp_seg, *client_tracker );
              CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
              delete tcp_seg;
          }

          SECTION("fin_recv")
          {
               TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
               REQUIRE( ( tcp_seg != nullptr ) );
               server_tracker->set_tcp_event( TcpStreamTracker::TCP_FIN_RECV_EVENT );
               tsh->eval( *tcp_seg, *server_tracker );
               CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
               delete tcp_seg;
          }

          delete pkt;
      }

     SECTION("rst_packet")
     {
        	 Packet* pkt = get_rst_packet( flow );
        	 REQUIRE( ( pkt != nullptr ) );

        	 SECTION("rst_sent")
          {
              TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
              REQUIRE( ( tcp_seg != nullptr ) );
              client_tracker->set_tcp_event( TcpStreamTracker::TCP_RST_SENT_EVENT );
              tsh->eval( *tcp_seg, *client_tracker );
              CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
              delete tcp_seg;
          }

          SECTION("rst_recv")
          {
               TcpSegmentDescriptor* tcp_seg = new TcpSegmentDescriptor( flow, pkt );
               REQUIRE( ( tcp_seg != nullptr ) );
               server_tracker->set_tcp_event( TcpStreamTracker::TCP_RST_RECV_EVENT );
               tsh->eval( *tcp_seg, *server_tracker );
               CHECK( ( tsh->get_tcp_event() == server_tracker->get_tcp_event() ) );
               delete tcp_seg;
          }

          delete pkt;
     }

     delete flow;
     delete tsh;
     delete client_tracker;
     delete server_tracker;

}

#endif
