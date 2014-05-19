/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// binder.cc author Russ Combs <rucombs@cisco.com>

#include "binder.h"

#include "flow/flow.h"
#include "managers/inspector_manager.h"

class Inspector;

// FIXIT these will move into bindings lookup structures
// these are for defaults but lookups will support default
// and non-defaults
static Inspector* tcp_hand;
static Inspector* udp_hand;
static Inspector* icmp_hand;
static Inspector* ip_hand;

void Binder::init()
{
    // FIXIT this is backwards; InspectorManager must call
    // binder to set the various default inspectors since
    // binder doesn't know what inspectors are available
    tcp_hand = InspectorManager::get_inspector("stream_tcp");
    udp_hand = InspectorManager::get_inspector("stream_udp");
    ip_hand = InspectorManager::get_inspector("stream_ip");
    icmp_hand = InspectorManager::get_inspector("stream_icmp");

    if ( !icmp_hand )
        icmp_hand = ip_hand;

    assert(tcp_hand);
    assert(udp_hand);
    assert(ip_hand);
    assert(icmp_hand);
}

void Binder::init_flow(Flow* flow)
{
    switch ( flow->protocol )
    {
    case IPPROTO_TCP:
        flow->client = tcp_hand;
        flow->server = tcp_hand;
        break;

    case IPPROTO_UDP:
        flow->client = udp_hand;
        flow->server = udp_hand;
        break;

    case IPPROTO_ICMP:
        flow->client = icmp_hand;
        flow->server = icmp_hand;
        break;

    case IPPROTO_IP:
        flow->client = ip_hand;
        flow->server = ip_hand;
        break;
    }
    if ( flow->client )
        flow->client->add_ref();

    if ( flow->server )
        flow->server->add_ref();
}

