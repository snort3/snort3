//---------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
//---------------------------------------------------------------------------
// http_event_reason.h Juan David Martin Castillo <jmartinc@cisco.com>

#ifndef HTTP_EVENT_REASON_H
#define HTTP_EVENT_REASON_H


#include "http_enum.h"

const char* get_http_event_reason_msg(HttpEnums::GenericEventReasonCode event);
const char* get_detail_301_reason(HttpEnums::Detail301ReasonCode code);

#endif
