//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "curses.h"

enum S7commplus_Protocol_Identifier
{
    S7COMMPLUS_PROTOCOL_IDENTIFIER__S7COMM     = 0x32,
    S7COMMPLUS_PROTOCOL_IDENTIFIER__S7COMMPLUS = 0x72,
};


enum S7commplus_Pdu_Type
{
    S7COMMPLUS_PDU_TYPE__CONNECT           = 0x01,
    S7COMMPLUS_PDU_TYPE__DATA              = 0x02,
    S7COMMPLUS_PDU_TYPE__DATA2             = 0x03,
    S7COMMPLUS_PDU_TYPE__KEEPALIVE         = 0xFF,
};


enum S7commplus_Opcode
{
    S7COMMPLUS_OPCODE__REQ                 = 0x31,
    S7COMMPLUS_OPCODE__RES                 = 0x32,
    S7COMMPLUS_OPCODE__NOTIFICATION        = 0x33,
    S7COMMPLUS_OPCODE__RES2                = 0x02,
};


enum S7commplus_Function
{
    S7COMMPLUS_FUNCTION__EXPLORE           = 0x04BB,
    S7COMMPLUS_FUNCTION__CREATEOBJECT      = 0x04CA,
    S7COMMPLUS_FUNCTION__DELETEOBJECT      = 0x04D4,
    S7COMMPLUS_FUNCTION__SETVARIABLE       = 0x04F2,
    S7COMMPLUS_FUNCTION__GETLINK           = 0x0524,
    S7COMMPLUS_FUNCTION__SETMULTIVAR       = 0x0542,
    S7COMMPLUS_FUNCTION__GETMULTIVAR       = 0x054C,
    S7COMMPLUS_FUNCTION__BEGINSEQUENCE     = 0x0556,
    S7COMMPLUS_FUNCTION__ENDSEQUENCE       = 0x0560,
    S7COMMPLUS_FUNCTION__INVOKE            = 0x056B,
    S7COMMPLUS_FUNCTION__GETVARSUBSTR      = 0x0586,
};


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

#endif

