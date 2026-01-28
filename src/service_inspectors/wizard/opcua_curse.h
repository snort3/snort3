//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// opcua_curse.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OPCUA_CURSE_H
#define OPCUA_CURSE_H

// OPC-UA curse provides the ability to determine if the traffic being processed
// conforms to the OPC Unified Architecture protocol traffic

enum OPCUA_State
{
    OPCUA_STATE__MSG_TYPE_1,
    OPCUA_STATE__MSG_TYPE_2,
    OPCUA_STATE__MSG_TYPE_3,
    OPCUA_STATE__IS_FINAL,
    OPCUA_STATE__MSG_SIZE_1,
    OPCUA_STATE__MSG_SIZE_2,
    OPCUA_STATE__MSG_SIZE_3,
    OPCUA_STATE__MSG_SIZE_4,
    OPCUA_STATE__CONN_PROTO_HEL,
    OPCUA_STATE__CONN_PROTO_ACK,
    OPCUA_STATE__CONN_PROTO_ERR,
    OPCUA_STATE__CONN_PROTO_RHE,
    OPCUA_STATE__SECURE_CHANNEL_ID_1,
    OPCUA_STATE__SECURE_CHANNEL_ID_2,
    OPCUA_STATE__SECURE_CHANNEL_ID_3,
    OPCUA_STATE__SECURE_CHANNEL_ID_4,
    OPCUA_STATE__SECURE_CONV_OPN,
    OPCUA_STATE__SECURE_CONV_MSG,
    OPCUA_STATE__SECURE_CONV_CLO,
    OPCUA_STATE__FOUND,
    OPCUA_STATE__SEARCH,
    OPCUA_STATE__NOT_FOUND,
};

enum OpcuaMsgType
{
    OPCUA_MSG__UNDEFINED,
    OPCUA_MSG__HEL,
    OPCUA_MSG__ACK,
    OPCUA_MSG__ERR,
    OPCUA_MSG__RHE,
    OPCUA_MSG__OPN,
    OPCUA_MSG__MSG,
    OPCUA_MSG__CLO,
};

// Protocol message minimum size constants
#define CONN_PROTO_HEL_MIN_SIZE 24
#define CONN_PROTO_ACK_MIN_SIZE 20
#define CONN_PROTO_ERR_MIN_SIZE 8
#define CONN_PROTO_RHE_MIN_SIZE 8

// Secure conversation constants  
#define SECURE_CONV_SECURITY_HDR_OPN_MIN_SIZE 12
#define SECURE_CONV_SECURITY_HDR_MSG_MIN_SIZE 4
#define SECURE_CONV_SEQUENCE_HDR_MIN_SIZE 8
#define MESSAGE_TYPE_ID_MIN_SIZE 4

class OpcuaTracker
{
public:
    void reset();
    
    OPCUA_State state = OPCUA_State::OPCUA_STATE__MSG_TYPE_1;
    OPCUA_State last_state = OPCUA_State::OPCUA_STATE__MSG_TYPE_1;
    char raw_msg_type[3] = {'_', '_', '_'};
    char is_final = '_';
    OpcuaMsgType msg_type = OPCUA_MSG__UNDEFINED;
};

#endif

