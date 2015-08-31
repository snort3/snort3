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

// tcp_stream_tracker.cpp author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jun 24, 2015

#include "tcp_stream_tracker.h"
#include "stream/stream.h"

TcpStreamTracker::TcpStreamTracker( bool client ) :
	client_tracker( client )
{
    tcp_state = ( client ) ? TCP_CLOSED : TCP_LISTEN;
    tcp_event = TCP_MAX_EVENTS;
}

TcpStreamTracker::~TcpStreamTracker()
{
    // TODO Auto-generated destructor stub
}

void TcpStreamTracker::set_tcp_event( TcpSegmentDescriptor &tcp_seg, bool client )
{
   bool talker;

    if( tcp_seg.get_direction( ) == FROM_CLIENT )
        talker = ( client ) ? true : false;
    else
        talker = ( client ) ? false : true;

    if( talker )
    {
        if( tcp_seg.get_tcph()->is_syn_only() )
            tcp_event = TCP_SYN_SENT_EVENT;
        else if( tcp_seg.get_tcph()->is_syn_ack() )
            tcp_event = TCP_SYN_ACK_SENT_EVENT;
        else if( tcp_seg.get_tcph()->is_ack() )
        {
            if( tcp_seg.get_data_len() > 0 )
                tcp_event = TCP_DATA_SEG_SENT_EVENT;
            else
                tcp_event = TCP_ACK_SENT_EVENT;
        }
        else if( tcp_seg.get_tcph()->is_rst() )
            tcp_event = TCP_RST_SENT_EVENT;
        else if( tcp_seg.get_tcph()->is_fin( ) )
            tcp_event = TCP_FIN_SENT_EVENT;
        else
            tcp_event = TCP_MAX_EVENTS;
    }
    else          // server is listening events
    {
        if( tcp_seg.get_tcph()->is_syn_only() )
             tcp_event = TCP_SYN_RECV_EVENT;
         else if( tcp_seg.get_tcph()->is_syn_ack() )
             tcp_event = TCP_SYN_ACK_RECV_EVENT;
         else if( tcp_seg.get_tcph()->is_ack() )
         {
             if( tcp_seg.get_data_len() > 0 )
                 tcp_event = TCP_DATA_SEG_RECV_EVENT;
             else
                 tcp_event = TCP_ACK_RECV_EVENT;
         }
         else if( tcp_seg.get_tcph()->is_rst() )
             tcp_event = TCP_RST_RECV_EVENT;
         else if( tcp_seg.get_tcph()->is_fin( ) )
             tcp_event = TCP_FIN_RECV_EVENT;
    }
}
