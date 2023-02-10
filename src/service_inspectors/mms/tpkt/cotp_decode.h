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

// cotp_decode.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef COTP_DECODE__H
#define COTP_DECODE__H

// COTP Decode provides an interface for COTP message identification
// and parsing.
// It is intended to be used through `util_tpkt`, not directly

#include "../util_tpkt.h"

// COTP PDU Types
// other types exist, but at this time DT_DATA is the only one in use
enum CotpPduType
{
    COTP_PDU_TYPE_DT_DATA = 0x0F,
};

struct CotpHdr
{
    uint8_t length;
    uint8_t dest_ref       : 4;
    uint8_t pdu_type       : 4;
    uint8_t tpdu_num       : 7;
    uint8_t last_data_unit : 1;
}
__attribute__((packed));

TpktAppliSearchStateType tpkt_internal_search_from_cotp_layer(Cursor*);

#endif

