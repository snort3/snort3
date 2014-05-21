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
#include "framework/inspector.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"

// FIXIT these will move into bindings lookup structures
// these are for defaults but lookups will support default
// and non-defaults (and client and server may differ)
static Inspector* pin_tcp = nullptr;
static Inspector* pin_udp = nullptr;
static Inspector* pin_icmp = nullptr;
static Inspector* pin_ip = nullptr;

void Binder::set(Inspector* pin, unsigned proto)
{
    switch ( proto )
    {
    case PROTO_BIT__TCP: pin_tcp = pin; break;
    case PROTO_BIT__UDP: pin_udp = pin; break;
    case PROTO_BIT__ICMP: pin_icmp = pin; break;
    case PROTO_BIT__IP: pin_ip = pin; break;
    }
}

void Binder::init()
{
    if ( !pin_icmp )
        pin_icmp = pin_ip;
}

void Binder::init_flow(Flow* flow)
{
    switch ( flow->protocol )
    {
    case IPPROTO_TCP:
        flow->set_client(pin_tcp);
        flow->set_server(pin_tcp);
        break;

    case IPPROTO_UDP:
        flow->set_client(pin_udp);
        flow->set_server(pin_udp);
        break;

    case IPPROTO_ICMP:
        flow->set_client(pin_icmp);
        flow->set_server(pin_icmp);
        break;

    case IPPROTO_IP:
        flow->set_client(pin_ip);
        flow->set_server(pin_ip);
        break;
    }
}

