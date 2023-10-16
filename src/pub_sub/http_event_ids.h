//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// http_event_ids.h author Russ Combs <rucombs@cisco.com>

// Inspection events published by the Http Inspector. Modules can subscribe
// to receive the events.

#ifndef HTTP_EVENT_IDS_H
#define HTTP_EVENT_IDS_H

#include "framework/data_bus.h"

namespace snort
{
// These are common values between the HTTP inspector and the subscribers.
struct HttpEventIds
{ enum : unsigned {

    REQUEST_HEADER,
    RESPONSE_HEADER,
    REQUEST_BODY,

    num_ids
}; };

const PubKey http_pub_key { "http_inspect", HttpEventIds::num_ids };

}
#endif

