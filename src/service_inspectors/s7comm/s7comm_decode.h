//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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
//
// s7comm_decode.h author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifndef S7COMM_DECODE_H
#define S7COMM_DECODE_H
#include <cstdint>

namespace snort
{
struct Packet;
}

class S7commFlowData;

/* S7comm defines */


#define COTP_HDR_LEN_FOR_S7COMM 2
#define COTP_HDR_PDU_TYPE_DATA  0xF0

// Message Types
#define JOB_REQUEST 0x01
#define ACK 0x02
#define ACK_DATA 0x03
#define USERDATA 0x07

// Header Error Class
#define NO_ERROR 0x00
#define APPLICATION_RELATIONSHIP_ERROR 0x81
#define OBJECT_DEFINITION_ERROR 0x82
#define NO_RESOURCES_AVAILABLE_ERROR 0x83
#define SERVICE_PROCESSING_ERROR 0x84
#define SUPPLIES_ERROR 0x85
#define ACCESS_ERROR 0x87

// Parameter Error Codes
#define PARAM_NO_ERROR 0x0000
#define PARAM_INVALID_BLOCK_TYPE_NUMBER 0x0110
#define PARAM_INVALID_PARAMETER 0x0112
#define PARAM_PG_RESOURCE_ERROR 0x011A
#define PARAM_PLC_RESOURCE_ERROR 0x011B
#define PARAM_PROTOCOL_ERROR 0x011C
#define PARAM_USER_BUFFER_TOO_SHORT 0x011F
#define PARAM_REQUEST_ERROR 0x0141
#define PARAM_VERSION_MISMATCH 0x01C0
#define PARAM_NOT_IMPLEMENTED 0x01F0
#define PARAM_L7_INVALID_CPU_STATE 0x8001
#define PARAM_L7_PDU_SIZE_ERROR 0x8500
#define PARAM_L7_INVALID_SZL_ID 0xD401
#define PARAM_L7_INVALID_INDEX 0xD402
#define PARAM_L7_DGS_CONNECTION_ALREADY_ANNOUNCED 0xD403
#define PARAM_L7_MAX_USER_NB 0xD404
#define PARAM_L7_DGS_FUNCTION_PARAMETER_SYNTAX_ERROR 0xD405
#define PARAM_L7_NO_INFO 0xD406
#define PARAM_L7_PRT_FUNCTION_PARAMETER_SYNTAX_ERROR 0xD601
#define PARAM_L7_INVALID_VARIABLE_ADDRESS 0xD801
#define PARAM_L7_UNKNOWN_REQUEST 0xD802
#define PARAM_L7_INVALID_REQUEST_STATUS 0xD803

#define S7COMM_PROTOCOL_ID      0x32
#define S7COMMPLUS_PROTOCOL_ID 0x72

#define TPKT_MIN_HDR_LEN 7     /* length field in TPKT header for S7comm */
#define TPKT_MAX_HDR_LEN       /* Undecided */
#define S7COMM_MIN_HDR_LEN 10

/* Need 8 bytes for MBAP Header + Function Code */
#define S7COMM_MIN_LEN 8       this value needs to be decided

/* GIDs, SIDs, and Strings */
#define GENERATOR_SPP_S7COMM 149   /* matches generators.h */

#define S7COMM_BAD_LENGTH 1
#define S7COMM_BAD_PROTO_ID 2
#define S7COMM_RESERVED_FUNCTION 3

#define S7COMM_BAD_LENGTH_STR \
    "(spp_s7comm): Length in S7comm header does not match the length needed for the given S7comm function."
#define S7COMM_BAD_PROTO_ID_STR "(spp_s7comm): S7comm protocol ID is non-zero."
#define S7COMM_RESERVED_FUNCTION_STR \
    "(spp_s7comm): Reserved S7comm function code in use."

struct S7commHeader
{
    uint8_t proto_id;
    uint8_t message_type;
    uint16_t reserved;
    uint16_t pdu_reference;
    uint16_t parameter_length;
    uint16_t data_length;
    // Optional fields for Ack-Data messages
    uint8_t error_class; // Present only in Ack-Data messages
    uint8_t error_code;  // Present only in Ack-Data messages
};

struct S7commParameterHeader
{
    uint8_t function_code;
    uint8_t item_count;
};





bool S7commDecode(snort::Packet*, S7commFlowData* mfd);

#endif

