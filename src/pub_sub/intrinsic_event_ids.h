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
// intrinsic_event_ids.h author Russ Combs <rucombs@cisco.com>

#ifndef INTRINSIC_EVENT_IDS_H
#define INTRINSIC_EVENT_IDS_H

// Common core functionality data events

#include "framework/data_bus.h"

namespace snort
{

struct IntrinsicEventIds
{ enum : unsigned {

    DAQ_SOF_MSG,
    DAQ_EOF_MSG,
    DAQ_OTHER_MSG,

    ALT_PACKET,
    PKT_WITHOUT_FLOW,
    DETAINED_PACKET,
    FINALIZE_PACKET,
    RETRY_PACKET,

    THREAD_IDLE,
    THREAD_ROTATE,

    SSL_SEARCH_ABANDONED,
    OPPORTUNISTIC_TLS,

    FLOW_STATE_CHANGE,
    FLOW_SERVICE_CHANGE,
    SERVICE_INSPECTOR_CHANGE,

    FLOW_NO_SERVICE,
    FLOW_STATE_SETUP,
    FLOW_STATE_RELOADED,
    FLOW_ASSISTANT_GADGET,
    FLOW_END,

    EXPECT_HANDLE_FLOWS,
    EXPECT_EARLY_SESSION,
    AUXILIARY_IP,
    FILE_VERDICT,

    num_ids
}; };

const PubKey intrinsic_pub_key { "snort", IntrinsicEventIds::num_ids };

const unsigned intrinsic_pub_id = 1;
}
#endif

