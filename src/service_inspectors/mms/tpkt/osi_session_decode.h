//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// osi_session_decode.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OSI_SESSION_DECODE__H
#define OSI_SESSION_DECODE__H

// OSI Session Decode provides an interface for Session message
// identification and parsing.
// It is intended to be used through `util_tpkt`, not directly

#include "../util_tpkt.h"

#include "cotp_decode.h"

enum OsiSessionSpduParameterType
{
    OSI_SESSION_SPDU_PARAM__CN_ACCEPT_ITEM           = 0x05,
    OSI_SESSION_SPDU_PARAM__PROTOCOL_OPTIONS         = 0x13,
    OSI_SESSION_SPDU_PARAM__SESSION_REQUIREMENT      = 0x14,
    OSI_SESSION_SPDU_PARAM__VERSION_NUMBER           = 0x16,
    OSI_SESSION_SPDU_PARAM__CALLING_SESSION_SELECTOR = 0x33,
    OSI_SESSION_SPDU_PARAM__CALLED_SESSION_SELECTOR  = 0x34,
    OSI_SESSION_SPDU_PARAM__SESSION_USER_DATA        = 0xC1,
};

struct OsiSessionHdr
{
    uint8_t spdu_type;
    uint8_t length;
};

struct OsiSessionSpduParameterHdr
{
    uint8_t type;
    uint8_t length;
};

TpktAppliSearchStateType tpkt_internal_search_from_osi_session_layer(Cursor*, bool);
uint32_t get_max_loops(Cursor*);

uint32_t get_max_pos(uint32_t, uint32_t);

#endif

