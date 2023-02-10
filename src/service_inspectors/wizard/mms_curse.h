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
// mms_curse.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef MMS_CURSE_H
#define MMS_CURSE_H

// MMS curse provides the ability to determine if the traffic being processed
// conforms to the Manufacturing Message Specification (MMS) traffic defined 
// within the IEC-61850 family of protocols

#include "curses.h"

enum MMS_State
{
    MMS_STATE__TPKT_VER = 0,
    MMS_STATE__TPKT_RES,
    MMS_STATE__TPKT_LEN1,
    MMS_STATE__TPKT_LEN2,
    MMS_STATE__COTP_LEN,
    MMS_STATE__COTP_PDU,
    MMS_STATE__COTP_TPDU_NUM,
    MMS_STATE__OSI_SESSION_SPDU,
    MMS_STATE__MMS,
    MMS_STATE__FOUND,
    MMS_STATE__SEARCH,
    MMS_STATE__NOT_FOUND,
};

#endif

