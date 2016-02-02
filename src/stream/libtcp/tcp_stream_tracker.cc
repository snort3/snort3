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

// tcp_stream_tracker.cpp author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jun 24, 2015

#include "protocols/tcp_options.h"
#include "protocols/tcp.h"
#include "protocols/eth.h"
#include "profiler/profiler.h"

#include "stream/stream.h"
#include "tcp_stream_tracker.h"

const char* tcp_state_names[] =
{ "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV", "TCP_ESTABLISHED","TCP_FIN_WAIT1",
  "TCP_FIN_WAIT2", "TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK",
  "TCP_TIME_WAIT", "TCP_CLOSED", "TCP_STATE_NONE",};

const char* tcp_event_names[] = { "TCP_SYN_SENT_EVENT", "TCP_SYN_RECV_EVENT",
                                  "TCP_SYN_ACK_SENT_EVENT", "TCP_SYN_ACK_RECV_EVENT",
                                  "TCP_ACK_SENT_EVENT",
                                  "TCP_ACK_RECV_EVENT", "TCP_DATA_SEG_SENT_EVENT",
                                  "TCP_DATA_SEG_RECV_EVENT",
                                  "TCP_FIN_SENT_EVENT", "TCP_FIN_RECV_EVENT", "TCP_RST_SENT_EVENT",
                                  "TCP_RST_RECV_EVENT" };

TcpStreamTracker::TcpStreamTracker(bool client) :
    client_tracker(client), require_3whs(false), snd_una(0), snd_nxt(0), snd_wnd(0), snd_up(0),
    snd_wl1(0), snd_wl2(0), iss(0), rcv_nxt(0), rcv_wnd(0), rcv_up(0), irs(0),
    ts_last_packet(0), ts_last(0), wscale(0), mss(0), flags(0)
{
    memset(mac_addr, '0', sizeof(mac_addr));
    tcp_state =  TCP_STATE_NONE;
    tcp_event = TCP_MAX_EVENTS;
}

TcpStreamTracker::~TcpStreamTracker()
{
    // TODO Auto-generated destructor stub
}

void TcpStreamTracker::set_tcp_event(TcpSegmentDescriptor& tsd)
{
    bool talker;
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    if ( tsd.get_pkt()->packet_flags & PKT_FROM_CLIENT )
        talker = ( client_tracker ) ? true : false;
    else
        talker = ( client_tracker ) ? false : true;

    if ( talker )
    {
        if ( tcph->is_syn_only() )
            tcp_event = TCP_SYN_SENT_EVENT;
        else if ( tcph->is_syn_ack() )
            tcp_event = TCP_SYN_ACK_SENT_EVENT;
        else if ( tcph->is_ack() || tcph->is_psh() )
        {
            if ( tsd.get_data_len() > 0 )
                tcp_event = TCP_DATA_SEG_SENT_EVENT;
            else
                tcp_event = TCP_ACK_SENT_EVENT;
        }
        else if ( tcph->is_rst() )
            tcp_event = TCP_RST_SENT_EVENT;
        else if ( tcph->is_fin( ) )
            tcp_event = TCP_FIN_SENT_EVENT;
//        else if( tsd.get_data_len() > 0 )   // FIXIT - No flags set, how do we handle this?
//            tcp_event = TCP_DATA_SEG_SENT_EVENT;
        else
            tcp_event = TCP_ACK_SENT_EVENT;
    }
    else          // server is listening events
    {
        if ( tcph->is_syn_only() )
            tcp_event = TCP_SYN_RECV_EVENT;
        else if ( tcph->is_syn_ack() )
            tcp_event = TCP_SYN_ACK_RECV_EVENT;
        else if ( tcph->is_ack() || tcph->is_psh() )
        {
            if ( tsd.get_data_len() > 0 )
                tcp_event = TCP_DATA_SEG_RECV_EVENT;
            else
                tcp_event = TCP_ACK_RECV_EVENT;
        }
        else if ( tcph->is_rst() )
            tcp_event = TCP_RST_RECV_EVENT;
        else if ( tcph->is_fin( ) )
            tcp_event = TCP_FIN_RECV_EVENT;
//         else if( tsd.get_data_len() > 0 )    // FIXIT - No flags set, how do we handle this?
//             tcp_event = TCP_DATA_SEG_RECV_EVENT;
        else
            tcp_event = TCP_ACK_RECV_EVENT;
    }
}

// Use a for loop and byte comparison, which has proven to be faster on pipelined architectures
// compared to a memcmp (setup for memcmp is slow).  Not using a 4 byte and 2 byte long because
// there is no guarantee of memory alignment (and thus performance issues similar to memcmp).
bool TcpStreamTracker::compare_mac_addresses(const uint8_t eth_addr[])
{
    for ( int i = 0; i < 6; ++i )
        if ( mac_addr[i] != eth_addr[i] )
            return false;

    return true;
}

void TcpStreamTracker::cache_mac_address(TcpSegmentDescriptor& tsd, uint8_t direction)
{
    int i;

    /* Not Ethernet based, nothing to do */
    if ( !( tsd.get_pkt()->proto_bits & PROTO_BIT__ETH ) )
        return;

    // if flag is set, guaranteed to have an eth layer
    const eth::EtherHdr* eh = layer::get_eth_layer(tsd.get_pkt() );

    if ( direction == FROM_CLIENT )
    {
        if ( client_tracker )
            for ( i = 0; i < 6; i++ )
                mac_addr[i] = eh->ether_src[i];
        else
            for ( i = 0; i < 6; i++ )
                mac_addr[i] = eh->ether_dst[i];
    }
    else
    {
        if ( client_tracker )
            for ( i = 0; i < 6; i++ )
                mac_addr[i] = eh->ether_dst[i];
        else
            for ( i = 0; i < 6; i++ )
                mac_addr[i] = eh->ether_src[i];
    }
}

