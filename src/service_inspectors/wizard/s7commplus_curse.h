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
// s7commplus_curse.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef S7COMMPLUS_CURSE_H
#define S7COMMPLUS_CURSE_H

// s7commplus_curse provides the ability to determine if the traffic being processed
// conforms to the S7CommPlus protocol used in select Siemens devices

#include <cstdint>

enum S7commplus_State
{
    S7COMMPLUS_STATE__TPKT_VER = 0,
    S7COMMPLUS_STATE__TPKT_RES,
    S7COMMPLUS_STATE__TPKT_LEN1,
    S7COMMPLUS_STATE__TPKT_LEN2,
    S7COMMPLUS_STATE__COTP_LEN,
    S7COMMPLUS_STATE__COTP_PDU,
    S7COMMPLUS_STATE__COTP_TPDU_NUM,
    S7COMMPLUS_STATE__PROTO_ID,
    S7COMMPLUS_STATE__PDU_TYPE,
    S7COMMPLUS_STATE__DATALENGTH_1,
    S7COMMPLUS_STATE__DATALENGTH_2,
    S7COMMPLUS_STATE__OPCODE,
    S7COMMPLUS_STATE__RES_1,
    S7COMMPLUS_STATE__RES_2,
    S7COMMPLUS_STATE__FUNCTION_1,
    S7COMMPLUS_STATE__FUNCTION_2,
    S7COMMPLUS_STATE__FOUND,
    S7COMMPLUS_STATE__SEARCH,
    S7COMMPLUS_STATE__NOT_FOUND,
};

class S7commplusTracker
{
public:
    S7commplus_State state = S7commplus_State::S7COMMPLUS_STATE__TPKT_VER;
    S7commplus_State last_state = S7commplus_State::S7COMMPLUS_STATE__TPKT_VER;
    uint16_t func = 0;
};

#endif

