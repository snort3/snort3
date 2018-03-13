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

// stream_libtcp_unit_test.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#include "stream_tcp_unit_test.h"

#ifndef STREAM_LIBTCP_UNIT_TEST
#define STREAM_LIBTCP_UNIT_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_tcp_unit_test.h"

#include "detection/ips_context.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "stream/tcp/tcp_session.h"

using namespace snort;

// SYN PACKET
// IP 192.168.0.89.9012 > p3nlh044.shr.prod.phx3.secureserver.net.http: Flags [S], seq 9050, win
// 8192, length 0
uint8_t cooked_syn[] =
    "\x00\x21\x91\x01\xb2\x48\xaa\x00\x04\x00\x0a\x04\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x88\x96\xc0\xa8\x00\x59\x48\xa7\xe8\x90\x23\x34\x00\x50\x00\x00\x23\x5a\x00\x00\x00\x00\x50\x02\x20\x00\x56\xcb\x00\x00";

// SYN-ACK PACKET
// IP p3nlh044.shr.prod.phx3.secureserver.net.http > 192.168.0.89.9012: Flags [S.], seq 9025, ack
// 9051, win 8192, length 0
uint8_t cooked_syn_ack[] =
    "\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x88\x96\x48\xa7\xe8\x90\xc0\xa8\x00\x59\x00\x50\x23\x34\x00\x00\x23\x41\x00\x00\x23\x5b\x50\x12\x20\x00\x33\x79\x00\x00";

// ACK PACKET
// IP 192.168.0.89.9012 > p3nlh044.shr.prod.phx3.secureserver.net.http: Flags [.], ack 1, win 8192,
// length 0
uint8_t cooked_ack[] =
    "\x00\x21\x91\x01\xb2\x48\xaa\x00\x04\x00\x0a\x04\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x88\x96\xc0\xa8\x00\x59\x48\xa7\xe8\x90\x23\x34\x00\x50\x00\x00\x23\x5b\x00\x00\x23\x42\x50\x10\x20\x00\x33\x7a\x00\x00";

// FIXIT-H this is not a FIN PACKET yet...
// IP 192.168.0.89.9012 > p3nlh044.shr.prod.phx3.secureserver.net.http: Flags [.], ack 1, win 8192,
// length 0
uint8_t cooked_fin[] =
    "\x00\x21\x91\x01\xb2\x48\xaa\x00\x04\x00\x0a\x04\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x88\x96\xc0\xa8\x00\x59\x48\xa7\xe8\x90\x23\x34\x00\x50\x00\x00\x23\x5b\x00\x00\x23\x42\x50\x10\x20\x00\x33\x7a\x00\x00";

// FIXIT-H this is not a RST PACKET yet...
// IP 192.168.0.89.9012 > p3nlh044.shr.prod.phx3.secureserver.net.http: Flags [.], ack 1, win 8192,
// length 0
uint8_t cooked_rst[] =
    "\x00\x21\x91\x01\xb2\x48\xaa\x00\x04\x00\x0a\x04\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x88\x96\xc0\xa8\x00\x59\x48\xa7\xe8\x90\x23\x34\x00\x50\x00\x00\x23\x5b\x00\x00\x23\x42\x50\x10\x20\x00\x33\x7a\x00\x00";

// DATA PACKET
// IP 192.168.0.89.9012 > p3nlh044.shr.prod.phx3.secureserver.net.http: Flags [P.], seq 1:43, ack
// 1, win 8192, length 42
uint8_t cooked_data[] =
    "\x00\x21\x91\x01\xb2\x48\xaa\x00\x04\x00\x0a\x04\x08\x00\x45\x00\x00\x52\x00\x01\x00\x00\x40\x06\x88\x6c\xc0\xa8\x00\x59\x48\xa7\xe8\x90\x23\x34\x00\x50\x00\x00\x23\x5b\x00\x00\x23\x42\x50\x18\x20\x00\x14\x83\x00\x00\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x77\x77\x77\x2e\x6d\x61\x6c\x66\x6f\x72\x67\x65\x2e\x63\x6f\x6d\x0d\x0a\x0d\x0a";

DAQ_PktHdr_t daqHdr;

static DAQ_PktHdr_t* initDaqHdr( )
{
    gettimeofday(&daqHdr.ts, nullptr);
    return &daqHdr;
}

static Packet* init_packet(Flow* flow, uint32_t talker)
{
    Packet* pkt = new Packet(false);

    pkt->flow = flow;
    pkt->packet_flags = talker;
    pkt->proto_bits &= ~PROTO_BIT__ETH;
    pkt->pkth = initDaqHdr();
    pkt->dsize = 0;

    pkt->context = new IpsContext(1);
    pkt->flow->session = new TcpSession(flow);

    return pkt;
}

void release_packet(Packet* p)
{
    delete p->flow->session;
    delete p->context;
    delete p;
}

Packet* get_syn_packet(Flow* flow)
{
    Packet* pkt = init_packet(flow, PKT_FROM_CLIENT);

    pkt->pkt = cooked_syn;
    pkt->ptrs.tcph = ( tcp::TCPHdr* )( cooked_syn + 34 );

    return pkt;
}

Packet* get_syn_ack_packet(Flow* flow)
{
    Packet* pkt = init_packet(flow, PKT_FROM_SERVER);

    pkt->pkt = cooked_syn_ack;
    pkt->ptrs.tcph = ( tcp::TCPHdr* )( cooked_syn_ack + 34 );

    return pkt;
}

Packet* get_ack_packet(Flow* flow)
{
    Packet* pkt = init_packet(flow, PKT_FROM_CLIENT);

    pkt->pkt = cooked_ack;
    pkt->ptrs.tcph = ( tcp::TCPHdr* )( cooked_ack + 34 );

    return pkt;
}

Packet* get_fin_packet(Flow* flow)
{
    Packet* pkt = init_packet(flow, PKT_FROM_CLIENT);

    pkt->pkt = cooked_fin;
    pkt->ptrs.tcph = ( tcp::TCPHdr* )( cooked_fin + 34 );

    return pkt;
}

Packet* get_rst_packet(Flow* flow)
{
    Packet* pkt = init_packet(flow, PKT_FROM_CLIENT);

    pkt->pkt = cooked_rst;
    pkt->ptrs.tcph = ( tcp::TCPHdr* )( cooked_rst + 34 );

    return pkt;
}

Packet* get_data_packet(Flow* flow)
{
    Packet* pkt = init_packet(flow, PKT_FROM_CLIENT);

    pkt->pkt = cooked_data;
    pkt->ptrs.tcph = ( tcp::TCPHdr* )( cooked_data + 34 );
    pkt->dsize = 42;

    return pkt;
}

#endif

