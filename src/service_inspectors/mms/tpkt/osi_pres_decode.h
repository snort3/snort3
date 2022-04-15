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

// osi_pres_decode.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OSI_PRES_DECODE__H
#define OSI_PRES_DECODE__H

// OSI PRES Decode provides an interface for PRES message identification
// and parsing.
// It is intended to be used through `util_tpkt`, not directly

#include "../util_tpkt.h"

// named identifiers for ber tag processing
enum BerTagProcessType
{
    BER_TAG__ADD_NONE               = 0x00,
    BER_TAG__ADD_HEADER_ONLY        = 0x01,
    BER_TAG__ADD_HEADER_AND_PAYLOAD = 0x02,
};

// OSI Session SPDU Types
enum OsiPresPpduModeSelectorType
{
    OSI_PRES_MODE__INVALID = 0x00,
    OSI_PRES_MODE__NORMAL  = 0x01,
};

// OSI Presentation Context Identifiers
enum OsiPresContextIdentifierType
{
    OSI_PRES_CONTEXT_ID__NULL = 0x00,
    OSI_PRES_CONTEXT_ID__ACSE = 0x01,
    OSI_PRES_CONTEXT_ID__MMS  = 0x03,
};

TpktAppliSearchStateType tpkt_internal_search_from_osi_pres_layer(Cursor*);

bool process_next_ber_tag(snort::BerReader*, snort::BerElement*, Cursor*, BerTagProcessType);

#endif

