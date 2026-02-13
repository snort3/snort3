//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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

// file_event_ids.h author Shilpa Nagpal <shinagpa@cisco.com>

// File events published by File Service for MP snort and advanced logging support.

#ifndef FILE_EVENTS_IDS_H
#define FILE_EVENTS_IDS_H

#include "framework/mp_data_bus.h"
#include "framework/data_bus.h"

namespace snort
{

struct FileMPEvents
{
    enum : unsigned {
        FILE_SHARE = 0,
        FILE_SHARE_SYNC,
        num_ids
    };
};

struct FileEventIds
{
    enum : unsigned {
        FILE_COMPLETE = 0,
        num_ids
    };
};

const PubKey file_mp_pub_key { "file_mp_events", FileMPEvents::num_ids };
const PubKey file_adv_pub_key { "file_adv_events", FileEventIds::num_ids };

}
#endif

