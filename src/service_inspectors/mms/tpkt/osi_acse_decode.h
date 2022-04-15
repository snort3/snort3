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

// osi_acse_decode.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OSI_ACSE_DECODE__H
#define OSI_ACSE_DECODE__H

// OSI ACSE Decode provides an interface for ACSE message identification
// and parsing.
// It is intended to be used through `util_tpkt`, not directly

#include "../util_tpkt.h"

enum
{
    OSI_ACSE_AARQ = 0x60,
    OSI_ACSE_AARE = 0x61,
};

// function stubs
TpktAppliSearchStateType tpkt_internal_search_from_osi_acse_layer(Cursor*);

#endif

