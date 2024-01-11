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

// appid_event_ids.h author Russ Combs <rucombs@cisco.com>

#ifndef APPID_EVENT_IDS_H
#define APPID_EVENT_IDS_H

#include "framework/data_bus.h"

namespace snort
{

struct AppIdEventIds
{ enum : unsigned {

    ANY_CHANGE,
    DEBUG_LOG,
    DHCP_DATA,
    DHCP_INFO,
    FP_SMB_DATA,

    num_ids
}; };

const PubKey appid_pub_key { "appid", AppIdEventIds::num_ids };

}
#endif

