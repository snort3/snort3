//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// s7comm_curse.h author [Your Name] <your.email@example.com>

#ifndef S7COMM_CURSE_H
#define S7COMM_CURSE_H

#include <cstdint>

// S7comm_curse provides the ability to determine if the traffic being processed
// conforms to the S7Comm protocol used in Siemens devices

enum S7comm_State
{
    S7COMM_STATE__TPKT_VER = 0,
    S7COMM_STATE__TPKT_RES,
    S7COMM_STATE__TPKT_LEN1,
    S7COMM_STATE__TPKT_LEN2,
    S7COMM_STATE__COTP_LEN,
    S7COMM_STATE__COTP_PDU,
    S7COMM_STATE__COTP_TPDU_NUM,
    S7COMM_STATE__PROTO_ID,
    S7COMM_STATE__MESSAGE_TYPE,
    S7COMM_STATE__RESERVED_1,
    S7COMM_STATE__RESERVED_2,
    S7COMM_STATE__PDU_REFERENCE_1,
    S7COMM_STATE__PDU_REFERENCE_2,
    S7COMM_STATE__PARAMETER_LENGTH_1,
    S7COMM_STATE__PARAMETER_LENGTH_2,
    S7COMM_STATE__DATA_LENGTH_1,
    S7COMM_STATE__DATA_LENGTH_2,
    S7COMM_STATE__OPTIONAL_ERROR_CLASS,
    S7COMM_STATE__OPTIONAL_ERROR_CODE,
    S7COMM_STATE__FOUND,
    S7COMM_STATE__SEARCH,
    S7COMM_STATE__NOT_FOUND,
};

class S7commTracker
{
public:
    S7comm_State state = S7comm_State::S7COMM_STATE__TPKT_VER;
    S7comm_State last_state = S7comm_State::S7COMM_STATE__TPKT_VER;
    uint16_t func = 0;
};

#endif // S7COMM_CURSE_H
