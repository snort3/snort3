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

// tcp_closed_state.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#include "tcp_closed_state.h"

#include "stream/stream.h"

#ifdef UNIT_TEST
#include "test/catch.hpp"
#include "stream/libtcp/stream_tcp_unit_test.h"
#endif

TcpClosedState::TcpClosedState()
{
    // TODO Auto-generated constructor stub

}

TcpClosedState::~TcpClosedState()
{
    // TODO Auto-generated destructor stub
}

void TcpClosedState::syn_sent( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
	tracker.set_iss( tcp_seg.get_seq() );
	tracker.set_snd_una( tcp_seg.get_seq() + 1 );
	tracker.set_snd_nxt( tcp_seg.get_end_seq() );
	tracker.set_snd_wnd( tcp_seg.get_win() );
	tracker.set_ts_last_packet( tcp_seg.get_pkt()->pkth->ts.tv_sec );

	tracker.set_tcp_state( TcpStreamTracker::TCP_SYN_SENT );
}

void TcpClosedState::syn_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::syn_ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::syn_ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::data_seg_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::data_seg_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::fin_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::fin_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::rst_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpClosedState::rst_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

#ifdef UNIT_TEST

TEST_CASE("TCP State Closed", "[tcp_closed_state][stream_tcp]")
{
     // initialization code here
	 Flow* flow = new Flow;
	 TcpStateHandler* tsh = new TcpClosedState;
     TcpStreamTracker* client_tracker = new TcpStreamTracker( true );

     SECTION("syn_packet")
     {
       	 Packet* pkt = get_syn_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("syn_sent")
         {
             flow->ssn_state.direction = FROM_CLIENT;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
             client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
             tsh->eval( tcp_seg, *client_tracker );
             CHECK( TcpStreamTracker::TCP_SYN_SENT_EVENT == client_tracker->get_tcp_event() );
             CHECK( ( client_tracker->get_iss() == 9050 ) );
             CHECK( ( client_tracker->get_snd_una() == 9051 ) );
             CHECK( ( client_tracker->get_snd_nxt() == 9050 ) );
             CHECK( ( client_tracker->get_snd_wnd() == 8192 ) );
         }

         SECTION("syn_recv")
         {
             flow->ssn_state.direction = FROM_SERVER;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
              client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
              tsh->eval( tcp_seg, *client_tracker );
              CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         delete pkt;
     }

     SECTION("syn_ack_packet")
     {
       	 Packet* pkt = get_syn_ack_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("syn_ack_sent")
         {
             flow->ssn_state.direction = FROM_CLIENT;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
             client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
             tsh->eval( tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         SECTION("syn_ack_recv")
         {
             flow->ssn_state.direction = FROM_SERVER;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
             client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
             tsh->eval( tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         delete pkt;
     }

     SECTION("ack_packet")
     {
       	 Packet* pkt = get_ack_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("ack_sent")
         {
             flow->ssn_state.direction = FROM_CLIENT;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
             client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
             tsh->eval( tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         SECTION("ack_recv")
         {
             flow->ssn_state.direction = FROM_SERVER;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
             client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
             tsh->eval( tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         delete pkt;
     }

     SECTION("data_seg_packet")
     {
       	 Packet* pkt = get_data_packet( flow );
       	 REQUIRE( ( pkt != nullptr ) );

       	 SECTION("data_seg_sent")
         {
             flow->ssn_state.direction = FROM_CLIENT;
             TcpSegmentDescriptor tcp_seg( flow, pkt );
             client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
             tsh->eval( tcp_seg, *client_tracker );
             CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         SECTION("data_seg_recv")
         {
             flow->ssn_state.direction = FROM_SERVER;
              TcpSegmentDescriptor tcp_seg( flow, pkt );
              client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
              tsh->eval( tcp_seg, *client_tracker );
              CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
         }

         delete pkt;
     }

     SECTION("fin_packet")
      {
        	 Packet* pkt = get_fin_packet( flow );
        	 REQUIRE( ( pkt != nullptr ) );

        	 SECTION("fin_sent")
          {
              flow->ssn_state.direction = FROM_CLIENT;
              TcpSegmentDescriptor tcp_seg( flow, pkt );
              client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
              tsh->eval( tcp_seg, *client_tracker );
              CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
          }

          SECTION("fin_recv")
          {
              flow->ssn_state.direction = FROM_SERVER;
               TcpSegmentDescriptor tcp_seg( flow, pkt );
               client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
               tsh->eval( tcp_seg, *client_tracker );
               CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
          }

          delete pkt;
      }

     SECTION("rst_packet")
     {
        	 Packet* pkt = get_rst_packet( flow );
        	 REQUIRE( ( pkt != nullptr  ));

        	 SECTION("rst_sent")
          {
        	  flow->ssn_state.direction = FROM_CLIENT;
              TcpSegmentDescriptor tcp_seg( flow, pkt );
              client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
              tsh->eval( tcp_seg, *client_tracker );
              CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ));
          }

          SECTION("rst_recv")
          {
              flow->ssn_state.direction = FROM_SERVER;
              TcpSegmentDescriptor tcp_seg( flow, pkt );
               client_tracker->set_tcp_event( tcp_seg, client_tracker->is_client_tracker( ) );
              tsh->eval( tcp_seg, *client_tracker );
               CHECK( ( tsh->get_tcp_event() == client_tracker->get_tcp_event() ) );
          }

          delete pkt;
     }

     delete flow;
     delete tsh;
     delete client_tracker;
}

#endif
