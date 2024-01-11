//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// tpkt_decode.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef TPKT_DECODE_H
#define TPKT_DECODE_H

// TPKT Decode provides an interface for TPKT message identification
// and parsing.
// It is intended to be used through `util_tpkt`, not directly

#include "../util_tpkt.h"

namespace snort
{
struct Packet;
}

// set a minimum length for TPKT to ensure it only gets processed
// when it makes sense
// 0x03 bytes for TPKT
// 0x04 bytes for COTP
// 0x02 bytes for the smallest MMS message
#define TPKT_MIN_LEN    0x09

// defined as the maximum in the spec
#define TPKT_MAX_LEN    0xFFFB

struct TpktHdr
{
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
};

TpktAppliSearchStateType tpkt_internal_search_from_tpkt_layer(Cursor*);

#endif

