//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
//
// mms_decode.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_decode.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_decode.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef MMS_DECODE_H
#define MMS_DECODE_H

// MMS Decode provides the final processing to determine whether or not the
// message being processed is of a known type

#include "framework/cursor.h"

namespace snort
{
struct Packet;
}

class MmsFlowData;

/* Need at least 3 bytes to cover one TLV group */
#define MMS_MIN_LEN    3

bool mms_decode(snort::Packet*, MmsFlowData* mmsfd);

#endif

