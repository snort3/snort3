//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// u2_packet.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "u2_packet.h"

#include <cassert>

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "protocols/packet.h"
#include "protocols/protocol_ids.h"
#include "utils/util.h"

using namespace snort;

static const uint8_t u2_ttl = 64;

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

U2PseudoHeader::U2PseudoHeader(const Packet* p)
{
    assert(p->flow);

    if ( p->flow->key->version == 0x4 )
    {
        cook_eth(p, u.v4.eth);
        cook_ip4(p, u.v4.ip4);
        cook_tcp(p, u.v4.tcp);
        size = sizeof(u.v4) - offset;
    }
    else if ( p->flow->key->version == 0x6 )
    {
        cook_eth(p, u.v6.eth);
        cook_ip6(p, u.v6.ip6);
        cook_tcp(p, u.v6.tcp);
        size = sizeof(u.v6) - offset;
    }
    else size = 0;
}

uint8_t* U2PseudoHeader::get_data()
{ return size ? u.buf + offset : nullptr; }

uint16_t U2PseudoHeader::get_size()
{ return size; }

uint16_t U2PseudoHeader::get_dsize()
{ return dsize; }

//--------------------------------------------------------------------------
// private methods
//--------------------------------------------------------------------------

void U2PseudoHeader::cook_eth(const Packet* p, eth::EtherHdr& h)
{
    const unsigned sz = sizeof(h.ether_src);

    const uint8_t src[sz] = { 0xFF, 0x01, 0x02, 0x0A, 0x0B, 0x0C };
    const uint8_t dst[sz] = { 0xFF, 0x02, 0x01, 0x0A, 0x0B, 0x0C };

    for ( unsigned i = 0; i < sz; i++ )
    {
        h.ether_src[i] = src[i];
        h.ether_dst[i] = dst[i];
    }

    if ( p->flow->key->version == 0x4 )
        h.ether_type = htons(to_utype(ProtocolId::ETHERTYPE_IPV4));
    else
        h.ether_type = htons(to_utype(ProtocolId::ETHERTYPE_IPV6));
}

// there is no length restriction on reassembled PDU buffers so
// we must ensure that we don't produce a bogus datagram length.

void U2PseudoHeader::cook_ip4(const Packet* p, ip::IP4Hdr& h)
{
    const uint16_t overhead = sizeof(h) + sizeof(tcp::TCPHdr);
    const uint16_t max_data = IP_MAXPACKET - overhead;
    dsize = p->dsize;

    if ( dsize > max_data )
        dsize = max_data;

    h.ip_verhl = 0x45;
    h.ip_len = htons(overhead + dsize);
    h.ip_proto = IpProtocol::TCP;
    h.ip_ttl = u2_ttl;

    if (p->is_from_client())
    {
        h.ip_src = p->flow->client_ip.get_ip4_value();
        h.ip_dst = p->flow->server_ip.get_ip4_value();
    }
    else
    {
        h.ip_src = p->flow->server_ip.get_ip4_value();
        h.ip_dst = p->flow->client_ip.get_ip4_value();
    }

    h.ip_tos = 0;
    h.ip_id = 0;
    h.ip_off = 0;
    h.ip_csum = 0;
}

void U2PseudoHeader::cook_ip6(const Packet* p, ip::IP6Hdr& h)
{
    const uint16_t overhead = sizeof(tcp::TCPHdr);
    const uint16_t max_data = IP_MAXPACKET - overhead;
    dsize = p->dsize;

    if ( dsize > max_data )
        dsize = max_data;

    h.ip6_vtf = htonl(0x60 << 24);
    h.ip6_payload_len = htons(overhead + dsize);
    h.ip6_next = IpProtocol::TCP;
    h.ip6_hoplim = u2_ttl;

    if (p->is_from_client())
    {
        COPY4(h.ip6_src.u6_addr32, p->flow->client_ip.get_ip6_ptr());
        COPY4(h.ip6_dst.u6_addr32, p->flow->server_ip.get_ip6_ptr());
    }
    else
    {
        COPY4(h.ip6_src.u6_addr32, p->flow->server_ip.get_ip6_ptr());
        COPY4(h.ip6_dst.u6_addr32, p->flow->client_ip.get_ip6_ptr());
    }
}

void U2PseudoHeader::cook_tcp(const Packet* p, tcp::TCPHdr& h)
{
    h.th_sport = htons(p->ptrs.sp);
    h.th_dport = htons(p->ptrs.dp);

    h.th_offx2 = 0x50;   // these are required
    h.th_flags = TH_ACK;

    h.th_seq = htonl(1); // just to make wireshark happy
    h.th_ack = h.th_seq;
    h.th_win = htons(8192);

    h.th_sum = 0;
    h.th_urp = 0;
}

