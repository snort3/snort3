//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
    MMS_STATE__OSI_SESSION_SPDU_GT_LEN,
    MMS_STATE__OSI_SESSION_SPDU_DT,
    MMS_STATE__OSI_SESSION_SPDU_DT_LEN,
    MMS_STATE__OSI_SESSION_SPDU_CN_LEN,
    MMS_STATE__OSI_SESSION_SPDU_AC_LEN,
    MMS_STATE__OSI_SESSION_SPDU_PARAMS,
    MMS_STATE__OSI_SESSION_SPDU_USER_DATA_LEN,
    MMS_STATE__OSI_PRES_CP_CPA,
    MMS_STATE__OSI_PRES_CP_CPA_USER_DATA_ACSE_LOCATE,
    MMS_STATE__OSI_PRES_USER_DATA,
    MMS_STATE__OSI_ACSE,
    MMS_STATE__OSI_ACSE_TYPE,
    MMS_STATE__OSI_ACSE_DATA,
    MMS_STATE__MMS,
    MMS_STATE__MMS_CONFIRMED_REQUEST,
    MMS_STATE__FOUND,
    MMS_STATE__SEARCH,
    MMS_STATE__NOT_FOUND,
};

// define all known MMS tags to check for
enum
{
    MMS_CONFIRMED_REQUEST_TAG    = 0xA0,
    MMS_CONFIRMED_RESPONSE_TAG   = 0xA1,
    MMS_CONFIRMED_ERROR_TAG      = 0xA2,
    MMS_UNCONFIRMED_TAG          = 0xA3,
    MMS_REJECT_TAG               = 0xA4,
    MMS_CANCEL_REQUEST_TAG       = 0x85,
    MMS_CANCEL_RESPONSE_TAG      = 0x86,
    MMS_CANCEL_ERROR_TAG         = 0xA7,
    MMS_INITIATE_REQUEST_TAG     = 0xA8,
    MMS_INITIATE_RESPONSE_TAG    = 0xA9,
    MMS_INITIATE_ERROR_TAG       = 0xAA,
    MMS_CONCLUDE_REQUEST_TAG     = 0x8B,
    MMS_CONCLUDE_RESPONSE_TAG    = 0x8C,
    MMS_CONCLUDE_ERROR_TAG       = 0xAD,
};

// define all applicable OSI Session layer SPDU tags to check
enum
{
    MMS_OSI_SESSION_SPDU_GT_DT = 0x01,
    MMS_OSI_SESSION_SPDU_CN = 0x0D,
    MMS_OSI_SESSION_SPDU_AC = 0x0E,
};

class MmsTracker
{
public:
    MMS_State state = MMS_State::MMS_STATE__TPKT_VER;
    MMS_State last_state = MMS_State::MMS_STATE__TPKT_VER;
    bool connect_accept_item_likely = false;
    bool session_requirement_likely = false;
};

#endif

