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
// iec104_decode.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_decode.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_decode.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef IEC104_DECODE_H
#define IEC104_DECODE_H

namespace snort
{
struct Packet;
}

class Iec104FlowData;

/* IEC104 defines */
#define IEC104_START_ID 0x68

/* Need 6 bytes for Start, Length, and 4 control field octets */
#define IEC104_MIN_LEN 6

bool Iec104Decode(snort::Packet*, Iec104FlowData* iec104fd);

#endif

