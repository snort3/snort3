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
//
// opcua_decode.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OPCUA_DECODE_H
#define OPCUA_DECODE_H

#include "framework/cursor.h"

namespace snort
{
struct Packet;
}

class OpcuaFlowData;

// OpcUA constants
#define OPCUA_NULL_STRING_SIZE 0xFFFFFFFF
#define OPCUA_PROTOCOL_VERSION_STANDARD 0x00
#define OPCUA_DEFAULT_NAMESPACE_INDEX 0

// Alert and field configuration flags
#define OPCUA_TRIGGER_NULL_STR_SIZE_ALERT true
#define OPCUA_NO_ALERT false
#define OPCUA_LAST_FIELD true
#define OPCUA_NOT_LAST_FIELD false

// Message type minimum sizes
#define OPCUA_HEADER_MIN_SIZE 8
#define OPCUA_HEL_MIN_SIZE 32
#define OPCUA_ACK_MIN_SIZE 28
#define OPCUA_ERR_MIN_SIZE 16
#define OPCUA_RHE_MIN_SIZE 18
#define OPCUA_OPN_MIN_SIZE 32
#define OPCUA_MSG_MIN_SIZE 26
#define OPCUA_CLO_MIN_SIZE 24

// String and field size limits
#define OPCUA_HEL_ENDPOINT_URL_MAX_SIZE 4096
#define OPCUA_ERR_REASON_MAX_SIZE 4096
#define OPCUA_SERVER_URI_MAX_SIZE 4096
#define OPCUA_RHE_ENDPOINT_URL_MAX_SIZE 4096
#define OPCUA_SECURITY_POLICY_URI_MAX_SIZE 255
#define OPCUA_OPN_RECEIVER_CERT_THUMBPRINT_SIZE 20
#define OPCUA_CHUNK_DATA_BUF_SIZE 32767

// Field and size constants
#define OPCUA_MSG_HDR_LEN 24
#define OPCUA_ENDPOINT_URL_SIZE_SIZE 4
#define OPCUA_SENDER_CERT_SIZE_SIZE 4
#define OPCUA_RECEIVER_CERT_THUMBPRINT_SIZE_SIZE 4
#define OPCUA_MINIMUM_BODY_SIZE 1

// TypeID field sizes
#define OPCUA_TYPEID_ENCODING_MASK_SIZE 1
#define OPCUA_TYPEID_NAMESPACE_INDEX_SIZE 1
#define OPCUA_TYPEID_NODE_ID_SIZE 2

enum OpcuaMsgType
{
    OPCUA_MSG_UNDEFINED,
    OPCUA_MSG_HEL,
    OPCUA_MSG_ACK,
    OPCUA_MSG_ERR,
    OPCUA_MSG_RHE,
    OPCUA_MSG_OPN,
    OPCUA_MSG_MSG,
    OPCUA_MSG_CLO,
};

enum OpcuaIsFinalType
{
    OPCUA_IS_FINAL_UNDEFINED,
    OPCUA_IS_FINAL_FINAL = 'F',
    OPCUA_IS_FINAL_INTERMEDIATE = 'C',
    OPCUA_IS_FINAL_ABORTED = 'A',
};

enum OpcuaTypeIdEncodingMaskType
{
    OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC = 1,
};

struct OpcuaHeader
{
    char msg_type[3];
    uint8_t is_final;
    uint32_t msg_size; // little endian
};

struct OpcuaSecureConversationHeader
{
    OpcuaHeader hdr;
    uint32_t secure_channel_id;
};

struct OpcuaSequenceHeader
{
    uint32_t sequence_number;
    uint32_t request_id;
};

struct OpcuaMsgTypeHel
{
    OpcuaHeader hdr;
    uint32_t protocol_version;
    uint32_t recv_buf_size;
    uint32_t send_buf_size;
    uint32_t max_msg_size;
    uint32_t max_chunk_count;
    uint32_t raw_endpoint_url_size;
};

struct OpcuaMsgTypeErr
{
    OpcuaHeader hdr;
    uint32_t error;
    uint32_t raw_reason_size;
};

struct OpcuaMsgTypeRhe
{
    OpcuaHeader hdr;
    uint32_t raw_server_uri_size;
};

struct OpcuaMsgTypeOpn
{
    OpcuaHeader hdr;
    uint32_t secure_channel_id;
    uint32_t raw_sec_policy_uri_size;
};

struct OpcuaStringAnalysisData
{
    uint32_t* string_size;
    uint32_t string_offset;
    uint32_t max_string_size;
    bool alert_on_null_string;
    bool is_last_field;
};

static inline constexpr uint32_t make_opcua_msg_key(char c1, char c2, char c3, char c4 = '\0')
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(c1)) << 24) | 
           (static_cast<uint32_t>(static_cast<uint8_t>(c2)) << 16) | 
           (static_cast<uint32_t>(static_cast<uint8_t>(c3)) << 8) | 
           static_cast<uint32_t>(static_cast<uint8_t>(c4));
}

bool opcua_decode(snort::Packet*, OpcuaFlowData* opcuafd);

#endif

