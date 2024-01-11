//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// stream_event_ids.h author Russ Combs <rucombs@cisco.com>

#ifndef STREAM_EVENT_IDS_H
#define STREAM_EVENT_IDS_H

#include "framework/data_bus.h"

struct StreamEventIds
{ enum : unsigned {

    IP_NEW_FLOW,
    IP_BIDIRECTIONAL,

    ICMP_NEW_FLOW,
    ICMP_BIDIRECTIONAL,

    TCP_SYN,
    TCP_SYN_ACK,
    TCP_MIDSTREAM,
    TCP_ESTABLISHED,

    UDP_NEW_FLOW,
    UDP_BIDIRECTIONAL,

    HA_NEW_FLOW,

    num_ids
}; };

const snort::PubKey stream_pub_key { "stream", StreamEventIds::num_ids };

#endif
