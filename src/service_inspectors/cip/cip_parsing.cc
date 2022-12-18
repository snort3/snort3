//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// cip_parsing.cc author RA/Cisco

/* Description: Data parsing for EtherNet/IP and CIP formats.
   Note: No pointer parameters to these functions can be passed as null. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cip_parsing.h"

#include "framework/data_bus.h"
#include "utils/endian.h"

#include "cip.h"
#include "cip_session.h"  // For CIP connection tracking

using namespace snort;

/// EtherNet/IP Parsing Constants

// Common Packet Format Item IDs.
enum CpfItemId
{
    CPF_NULL_ADDRESS_ITEM_ID = 0x0000,
    CPF_LIST_IDENTITY_ITEM_ID = 0x000C,
    CPF_CONNECTED_ADDRESS_ITEM_ID = 0x00A1,
    CPF_CONNECTED_DATA_ITEM_ID = 0x00B1,
    CPF_UNCONNECTED_DATA_ITEM_ID = 0x00B2,
    CPF_LIST_SERVICES_ITEM_ID = 0x0100,
    CPF_SOCKADDR_INFO_OT_ITEM_ID = 0x8000,
    CPF_SOCKADDR_INFO_TO_ITEM_ID = 0x8001,
    CPF_SEQUENCED_ADDRESS_ITEM_ID = 0x8002
};

#define CPF_ADDRESS_ITEM_SLOT 0
#define CPF_DATA_ITEM_SLOT 1
#define CPF_LIST_REPLY_SLOT 0

// Some ENIP command ranges are reserved for future range.
#define ENIP_COMMAND_RESERVED1_START 0x0006
#define ENIP_COMMAND_RESERVED1_END 0x0062
#define ENIP_COMMAND_RESERVED2_START 0x00C8

// Some CPF Item IDs are reserved for future range.
#define ENIP_CPF_ITEM_RESERVED1_START 0x0086
#define ENIP_CPF_ITEM_RESERVED1_END 0x0090
#define ENIP_CPF_ITEM_RESERVED2_START 0x0092
#define ENIP_CPF_ITEM_RESERVED2_END 0x00A0
#define ENIP_CPF_ITEM_RESERVED3_START 0x00A5
#define ENIP_CPF_ITEM_RESERVED3_END 0x00B0
#define ENIP_CPF_ITEM_RESERVED4_START 0x00B3
#define ENIP_CPF_ITEM_RESERVED4_END 0x00FF
#define ENIP_CPF_ITEM_RESERVED5_START 0x0110
#define ENIP_CPF_ITEM_RESERVED5_END 0x7FFF
#define ENIP_CPF_ITEM_RESERVED6_START 0x8004

#define REGISTER_SESSION_DATA_SIZE 4

/// CIP Layer Parsing Constants
const size_t CIP_PATH_SEGMENT_MIN_SIZE_BYTES = sizeof(uint16_t);

// Typical payload size offset in CIP segment
#define CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET 1

// Offset to Segment Type/Format byte
#define CIP_PATH_TYPE_OFFSET 0

// Logical segment format mask and types.
#define CIP_PATH_LOGICAL_FORMAT_MASK 0x03

enum LogicalValueType
{
    CIP_PATH_LOGICAL_8_BIT = 0x00,
    CIP_PATH_LOGICAL_16_BIT = 0x01,
    CIP_PATH_LOGICAL_32_BIT = 0x02
};

// Logical segment types
enum LogicalSegmentType
{
    CIP_PATH_LOGICAL_CLASS = 0x00,
    CIP_PATH_LOGICAL_INSTANCE = 0x04,
    CIP_PATH_LOGICAL_MEMBER = 0x08,
    CIP_PATH_LOGICAL_CONN_POINT = 0x0c,
    CIP_PATH_LOGICAL_ATTRIBUTE = 0x10,
    CIP_PATH_LOGICAL_SPECIAL = 0x14,
    CIP_PATH_LOGICAL_SERVICE_ID = 0x18,
    CIP_PATH_LOGICAL_EXTENDED = 0x1C
};

enum SegmentType
{
    CIP_PATH_SEGMENT_PORT = 0x00,
    CIP_PATH_SEGMENT_LOGICAL = 0x20,
    CIP_PATH_SEGMENT_NETWORK = 0x40,
    CIP_PATH_SEGMENT_SYMBOLIC = 0x60,
    CIP_PATH_SEGMENT_DATA = 0x80
};

enum ExtendedStringType
{
    EXTENDED_STRING_DOUBLE = 0x20,
    EXTENDED_STRING_TRIPLE = 0x40,
    EXTENDED_STRING_NUMERIC = 0xC0
};

#define MESSAGE_ROUTER_RESPONSE_MASK 0x80

#define CIP_STATUS_MIN_SIZE 2

/// Prototypes
static bool parse_logical_address_format(const uint8_t* data,
    size_t data_length,
    bool logical_extended,
    CipSegment* segment);

static bool parse_message_router_request(const uint8_t* data,
    size_t data_length,
    CipRequest* cip_request,
    CipGlobalSessionData* global_data);

/// Functions
static bool enip_command_valid(uint16_t command)
{
    if ((ENIP_COMMAND_RESERVED1_START <= command && command <= ENIP_COMMAND_RESERVED1_END)
        || (ENIP_COMMAND_RESERVED2_START <= command))
    {
        return false;
    }

    return true;
}

static bool enip_command_tcp_only(uint16_t command)
{
    // Allocated command codes.
    if (command == ENIP_COMMAND_NOP
        || command == ENIP_COMMAND_REGISTER_SESSION
        || command == ENIP_COMMAND_UNREGISTER_SESSION
        || command == ENIP_COMMAND_SEND_RR_DATA
        || command == ENIP_COMMAND_SEND_UNIT_DATA)
    {
        return true;
    }

    return false;
}

static bool parse_enip_header(const uint8_t* data,
    size_t data_length,
    EnipSessionData* enip_session)
{
    EnipHeader* enip_header = &enip_session->enip_header;

    if (data_length < ENIP_HEADER_SIZE)
    {
        return false;
    }

    #define ENIP_HEADER_OFFSET_COMMAND 0
    #define ENIP_HEADER_OFFSET_LENGTH 2
    #define ENIP_HEADER_OFFSET_HANDLE 4
    #define ENIP_HEADER_OFFSET_STATUS 8
    #define ENIP_HEADER_OFFSET_CONTEXT 12
    #define ENIP_HEADER_OFFSET_OPTIONS 20

    enip_header->command = LETOHS(&data[ENIP_HEADER_OFFSET_COMMAND]);
    enip_header->length = LETOHS(&data[ENIP_HEADER_OFFSET_LENGTH]);
    enip_header->session_handle = LETOHL(&data[ENIP_HEADER_OFFSET_HANDLE]);
    enip_header->status = LETOHL(&data[ENIP_HEADER_OFFSET_STATUS]);
    memcpy(&enip_header->sender_context,
        &data[ENIP_HEADER_OFFSET_CONTEXT],
        sizeof(enip_header->sender_context));
    enip_header->options = LETOHL(&data[ENIP_HEADER_OFFSET_OPTIONS]);

    if (!enip_command_valid(enip_header->command))
    {
        enip_session->enip_invalid_nonfatal |= ENIP_INVALID_COMMAND;
    }

    return true;
}

static bool cpf_item_id_valid(uint16_t item_id)
{
    if ((ENIP_CPF_ITEM_RESERVED1_START <= item_id && item_id <= ENIP_CPF_ITEM_RESERVED1_END)
        || (ENIP_CPF_ITEM_RESERVED2_START <= item_id && item_id <= ENIP_CPF_ITEM_RESERVED2_END)
        || (ENIP_CPF_ITEM_RESERVED3_START <= item_id && item_id <= ENIP_CPF_ITEM_RESERVED3_END)
        || (ENIP_CPF_ITEM_RESERVED4_START <= item_id && item_id <= ENIP_CPF_ITEM_RESERVED4_END)
        || (ENIP_CPF_ITEM_RESERVED5_START <= item_id && item_id <= ENIP_CPF_ITEM_RESERVED5_END)
        || (ENIP_CPF_ITEM_RESERVED6_START <= item_id))
    {
        return false;
    }

    return true;
}

static bool cpf_item_length_valid(uint16_t item_id, size_t item_length)
{
    #define NULL_ADDRESS_ITEM_DATA_SIZE 0
    #define CONNECTED_ADDRESS_ITEM_DATA_SIZE 4
    #define SOCKADDR_INFO_ITEM_DATA_SIZE 16
    #define SEQUENCED_ADDRESS_ITEM_DATA_SIZE 8

    // Minimum data size for Connected and Unconnected Data Items when used with
    //  CIP Class 3 / Explicit data.
    #define MIN_CPF_CIP_DATA_SIZE 2

    bool valid = true;

    switch (item_id)
    {
    case CPF_NULL_ADDRESS_ITEM_ID:
        if (item_length != NULL_ADDRESS_ITEM_DATA_SIZE)
        {
            valid = false;
        }
        break;
    case CPF_CONNECTED_ADDRESS_ITEM_ID:
        if (item_length != CONNECTED_ADDRESS_ITEM_DATA_SIZE)
        {
            valid = false;
        }
        break;
    case CPF_CONNECTED_DATA_ITEM_ID:
        if (item_length < MIN_CPF_CIP_DATA_SIZE)
        {
            valid = false;
        }
        break;
    case CPF_UNCONNECTED_DATA_ITEM_ID:
        if (item_length < MIN_CPF_CIP_DATA_SIZE)
        {
            valid = false;
        }
        break;
    case CPF_SOCKADDR_INFO_OT_ITEM_ID:
    case CPF_SOCKADDR_INFO_TO_ITEM_ID:
        if (item_length != SOCKADDR_INFO_ITEM_DATA_SIZE)
        {
            valid = false;
        }
        break;
    case CPF_SEQUENCED_ADDRESS_ITEM_ID:
        if (item_length != SEQUENCED_ADDRESS_ITEM_DATA_SIZE)
        {
            valid = false;
        }
        break;
    case CPF_LIST_IDENTITY_ITEM_ID:
    case CPF_LIST_SERVICES_ITEM_ID:
    default:
        // No length checks for anything else.
        break;
    }

    return valid;
}

static bool enip_command_cpf_valid(uint16_t command, const EnipCpf* enip_cpf)
{
    #define MIN_CPF_ITEMS_CIP_MESSAGE 2
    #define MIN_CPF_ITEMS_LIST_REPLY 1

    bool valid = true;

    switch (command)
    {
    case ENIP_COMMAND_SEND_RR_DATA:
        if (enip_cpf->item_count < MIN_CPF_ITEMS_CIP_MESSAGE
            || enip_cpf->item_list[CPF_ADDRESS_ITEM_SLOT].type != CPF_NULL_ADDRESS_ITEM_ID
            || enip_cpf->item_list[CPF_DATA_ITEM_SLOT].type != CPF_UNCONNECTED_DATA_ITEM_ID)
        {
            valid = false;
        }
        break;
    case ENIP_COMMAND_SEND_UNIT_DATA:
        if (enip_cpf->item_count != MIN_CPF_ITEMS_CIP_MESSAGE
            || enip_cpf->item_list[CPF_ADDRESS_ITEM_SLOT].type != CPF_CONNECTED_ADDRESS_ITEM_ID
            || enip_cpf->item_list[CPF_DATA_ITEM_SLOT].type != CPF_CONNECTED_DATA_ITEM_ID)
        {
            valid = false;
        }
        break;
    case ENIP_COMMAND_LIST_SERVICES:
        // Used in Reply only.
        if (enip_cpf->item_count < MIN_CPF_ITEMS_LIST_REPLY
            || enip_cpf->item_list[CPF_LIST_REPLY_SLOT].type != CPF_LIST_SERVICES_ITEM_ID)
        {
            valid = false;
        }
        break;
    case ENIP_COMMAND_LIST_IDENTITY:
        // Used in Reply only.
        if (enip_cpf->item_count < MIN_CPF_ITEMS_LIST_REPLY
            || enip_cpf->item_list[CPF_LIST_REPLY_SLOT].type != CPF_LIST_IDENTITY_ITEM_ID)
        {
            valid = false;
        }
        break;
    default:
        // Ignore commands without defined CPF items.
        break;
    }

    return valid;
}

// Returns the CIP message type based on packet and session data. The data must already:
//  1. Be ENIP_COMMAND_SEND_UNIT_DATA or ENIP_COMMAND_SEND_RR_DATA
//  2. Have the required CPF items for that ENIP command.
// This also saves connection related data for the given packet and updates connection timestamps.
static CipMessageType get_cip_message_type(CipCurrentData* current_data,
    CipGlobalSessionData* global_data)
{
    CipMessageType cip_message_type = CipMessageTypeUnknown;

    if (current_data->enip_data.enip_header.command == ENIP_COMMAND_SEND_RR_DATA)
    {
        cip_message_type = CipMessageTypeExplicit;
    }
    else  // ENIP_COMMAND_SEND_UNIT_DATA
    {
        const EnipCpf* enip_cpf = &current_data->enip_data.enip_cpf;

        if (enip_cpf->item_list[CPF_ADDRESS_ITEM_SLOT].length > 0)
        {
            uint32_t connection_id = LETOHL(enip_cpf->item_list[CPF_ADDRESS_ITEM_SLOT].data);

            // Validate connected messages against CIP Connection List.
            CipConnection* connection = cip_find_connection_by_id(
                &global_data->connection_list,
                current_data->direction,
                connection_id,
                true);
            if (connection)
            {
                if (current_data->direction == CIP_FROM_CLIENT)
                {
                    connection->ot_timestamp = global_data->snort_packet->pkth->ts;
                }
                else
                {
                    connection->to_timestamp = global_data->snort_packet->pkth->ts;
                }

                current_data->enip_data.connection_class_id = connection->class_id;

                if (connection->class_id == MESSAGE_ROUTER_CLASS_ID)
                {
                    cip_message_type = CipMessageTypeExplicit;
                }
                else
                {
                    cip_message_type = CipMessageTypeImplicit;
                }
            }
            else
            {
                current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_CONNECTION_ID;
                cip_message_type = CipMessageTypeUnknown;
            }
        }
    }

    return cip_message_type;
}

static bool parse_common_packet_format(const uint8_t* data,
    size_t data_length,
    EnipCpf* enip_cpf,
    CipCurrentData* current_data)
{
    // The total item count is always first.
    #define CPF_ITEM_COUNT_SIZE 2
    if (data_length < CPF_ITEM_COUNT_SIZE)
    {
        return false;
    }

    #define CPF_OFFSET_ITEM_COUNT 0
    #define CPF_ITEM_OFFSET_TYPE 0
    #define CPF_ITEM_OFFSET_LENGTH 2
    #define CPF_ITEM_OFFSET_DATA 4

    enip_cpf->item_count = LETOHS(&data[CPF_OFFSET_ITEM_COUNT]);
    data_length -= CPF_ITEM_COUNT_SIZE;

    bool valid = true;

    size_t current_item_offset = CPF_ITEM_COUNT_SIZE;

    int i;
    for (i = 0; i < enip_cpf->item_count; ++i)
    {
        uint16_t item_type;
        uint16_t item_length;
        const uint8_t* item_data;
        /* This contains Type ID and Length. */
        #define CPF_ITEM_HEADER_SIZE 4
        if (data_length < CPF_ITEM_HEADER_SIZE)
        {
            valid = false;
            break;
        }

        item_type = LETOHS(&data[current_item_offset + CPF_ITEM_OFFSET_TYPE]);
        item_length = LETOHS(&data[current_item_offset + CPF_ITEM_OFFSET_LENGTH]);
        item_data = nullptr;
        if (item_length > 0)
        {
            item_data = &data[current_item_offset + CPF_ITEM_OFFSET_DATA];
        }

        data_length -= CPF_ITEM_HEADER_SIZE;

        if (!cpf_item_id_valid(item_type))
        {
            current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_RESERVED_FUTURE_CPF_TYPE;
        }

        if (!cpf_item_length_valid(item_type, item_length))
        {
            valid = false;
            break;
        }

        // Check that there is enough data left for the Item Length.
        if (data_length < item_length)
        {
            valid = false;
            break;
        }

        // Validate every CPF item, but only store data for a set amount.
        if (i < MAX_NUM_CPF_ITEMS)
        {
            enip_cpf->item_list[i].type = item_type;
            enip_cpf->item_list[i].length = item_length;
            enip_cpf->item_list[i].data = item_data;
        }

        // Get data for the next item.
        current_item_offset = current_item_offset + CPF_ITEM_HEADER_SIZE + item_length;
        data_length -= item_length;
    }

    if (valid)
    {
        current_data->enip_data.required_cpf_items_present
            = enip_command_cpf_valid(current_data->enip_data.enip_header.command, enip_cpf);
        if (!current_data->enip_data.required_cpf_items_present)
        {
            current_data->enip_data.enip_invalid_nonfatal |=
                ENIP_INVALID_ENIP_COMMAND_CPF_MISMATCH;
        }
    }

    return valid;
}

// If there in an unknown segment type, then just set this segment to include
//  all of the data left.
static void set_unknown_segment_type(size_t data_length,
    CipSegment* segment)
{
    segment->type = CipSegment_Type_UNKNOWN;
    segment->size = data_length;
}

// Return the timeout, in milliseconds, based on the priority/time_tick and time-out_ticks fields
//  that are common to: Unconnected Send, Forward Open, Forward Close.
//  This requires that enough data is available to read 2 bytes.
static uint32_t get_unconnected_timeout(const uint8_t* data)
{
    #define UNCONNECTED_OFFSET_PRIORITY_TIME_TICK 0
    #define UNCONNECTED_OFFSET_TIMEOUT_TICKS 1
    #define TICK_TIME_MASK 0xF

    uint8_t tick_time = data[UNCONNECTED_OFFSET_PRIORITY_TIME_TICK] & TICK_TIME_MASK;
    uint8_t timeout_ticks = data[UNCONNECTED_OFFSET_TIMEOUT_TICKS];

    return (1 << tick_time) * timeout_ticks;
}

// Parses RPI and Network Connection Parameters from a Forward Open Request.
// Note: Assumes there is enough data to parse the RPI and Network Connection Parameters.
static void parse_connection_parameters(const uint8_t* data,
    bool large_forward_open,
    CipConnectionParameters* connection_parameters)
{
    #define NULL_CONNECTION_TYPE_MASK 0x6000
    static const uint32_t LARGE_NULL_CONNECTION_TYPE_MASK = 0x60000000;

    // Offsets to the RPI and Network Connection Parameters data, from the RPI data.
    #define OFFSET_RPI 0
    #define OFFSET_NETWORK_PARAMETERS 4

    connection_parameters->rpi = LETOHL_UNALIGNED(&data[OFFSET_RPI]);

    if (!large_forward_open)
    {
        uint16_t network_connection_parameters = LETOHS(&data[OFFSET_NETWORK_PARAMETERS]);
        connection_parameters->network_connection_parameters = network_connection_parameters;

        if ((network_connection_parameters & NULL_CONNECTION_TYPE_MASK) == 0)
        {
            connection_parameters->is_null_connection = true;
        }
    }
    else  // SERVICE_LARGE_FORWARD_OPEN
    {
        uint32_t network_connection_parameters = LETOHL(&data[OFFSET_NETWORK_PARAMETERS]);
        connection_parameters->network_connection_parameters = network_connection_parameters;

        if ((network_connection_parameters & LARGE_NULL_CONNECTION_TYPE_MASK) == 0)
        {
            connection_parameters->is_null_connection = true;
        }
    }
}

// Note: Assumes there is enough data for a full Connection Signature.
static void parse_connection_signature(const uint8_t* data,
    CipConnectionSignature* connection_signature)
{
    #define OFFSET_CONNECTION_SERIAL 0
    #define OFFSET_VENDOR 2
    #define OFFSET_ORIGINATOR_SERIAL 4

    connection_signature->connection_serial_number = LETOHS(&data[OFFSET_CONNECTION_SERIAL]);
    connection_signature->vendor_id = LETOHS(&data[OFFSET_VENDOR]);
    connection_signature->originator_serial_number = LETOHL(&data[OFFSET_ORIGINATOR_SERIAL]);
}

static bool parse_segment_electronic_key(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    #define ELECTRONIC_KEY_FORMAT_TABLE 0x04
    #define  ELECTRONIC_KEY_FORMAT_TABLE_SIZE 10

    // Check that there is enough size for the Key Format Table.
    if (ELECTRONIC_KEY_FORMAT_TABLE_SIZE > data_length)
    {
        return false;
    }

    // Currently, the only supported Key Format is the Key Format Table.
    #define ELECTRONIC_KEY_OFFSET_FORMAT_TABLE 1
    if (data[ELECTRONIC_KEY_OFFSET_FORMAT_TABLE] != ELECTRONIC_KEY_FORMAT_TABLE)
    {
        return false;
    }

    segment->type = CipSegment_Type_LOGICAL_ELECTRONIC_KEY;
    segment->size = ELECTRONIC_KEY_FORMAT_TABLE_SIZE;

    return true;
}

static bool parse_segment_extended_symbol(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    size_t symbol_size_bytes;
    size_t segment_size_bytes;
    symbol_size_bytes = data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET];

    // calculate expected size
    segment_size_bytes = CIP_PATH_SEGMENT_MIN_SIZE_BYTES + symbol_size_bytes;

    // add padding
    segment_size_bytes += segment_size_bytes % 2;

    // Exit early, if we know we won't fit.
    if (segment_size_bytes > data_length)
    {
        return false;
    }

    segment->type = CipSegment_Type_DATA_EXT_SYMBOL;
    segment->data = &data[CIP_PATH_SEGMENT_MIN_SIZE_BYTES];
    segment->data_size = symbol_size_bytes;
    segment->size = segment_size_bytes;

    return true;
}

static bool parse_segment_logical(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    uint8_t segment_type = data[CIP_PATH_TYPE_OFFSET];

    // parse particular logical type
    bool valid = true;
    #define CIP_PATH_LOGICAL_TYPE_MASK 0x1C
    switch (segment_type & CIP_PATH_LOGICAL_TYPE_MASK)
    {
    case CIP_PATH_LOGICAL_CLASS:
        segment->type = CipSegment_Type_LOGICAL_CLASS;
        valid = parse_logical_address_format(data, data_length, false, segment);
        break;
    case CIP_PATH_LOGICAL_INSTANCE:
        segment->type = CipSegment_Type_LOGICAL_INSTANCE;
        valid = parse_logical_address_format(data, data_length, false, segment);
        break;
    case CIP_PATH_LOGICAL_MEMBER:
        segment->type = CipSegment_Type_LOGICAL_MEMBER;
        valid = parse_logical_address_format(data, data_length, false, segment);
        break;
    case CIP_PATH_LOGICAL_CONN_POINT:
        segment->type = CipSegment_Type_LOGICAL_CONN_POINT;
        valid = parse_logical_address_format(data, data_length, false, segment);
        break;
    case CIP_PATH_LOGICAL_ATTRIBUTE:
        segment->type = CipSegment_Type_LOGICAL_ATTRIBUTE;
        valid = parse_logical_address_format(data, data_length, false, segment);
        break;
    case CIP_PATH_LOGICAL_EXTENDED:
        segment->type = CipSegment_Type_LOGICAL_EXTENDED;
        valid = parse_logical_address_format(data, data_length, true, segment);
        break;
    case CIP_PATH_LOGICAL_SPECIAL:
    {
        // Logical Segment Electronic Key Logical Format.
        #define CIP_PATH_SEGMENT_ELECTRONIC_KEY 0x34

        if (segment_type == CIP_PATH_SEGMENT_ELECTRONIC_KEY)
        {
            valid = parse_segment_electronic_key(data,
                data_length,
                segment);
        }
        else
        {
            set_unknown_segment_type(data_length, segment);
        }

        break;
    }
    case CIP_PATH_LOGICAL_SERVICE_ID:
    {
        #define CIP_PATH_SEGMENT_SERVICE_ID 0x38
        if (segment_type == CIP_PATH_SEGMENT_SERVICE_ID)
        {
            segment->type = CipSegment_Type_LOGICAL_SERVICE_ID;
            valid = parse_logical_address_format(data, data_length, false, segment);
        }
        else
        {
            set_unknown_segment_type(data_length, segment);
        }

        break;
    }
    default:
        // Can't happen.
        set_unknown_segment_type(data_length, segment);
        break;
    }

    return valid;
}

static bool parse_segment_network(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    #define CIP_PATH_NETWORK_FORMAT_MASK 0xF0
    #define CIP_PATH_NETWORK_ONE_BYTE 0x40

    size_t segment_size_bytes = 0;

    uint8_t segment_type = data[CIP_PATH_TYPE_OFFSET];
    uint8_t network_segment_type = segment_type & CIP_PATH_NETWORK_FORMAT_MASK;
    if (network_segment_type == CIP_PATH_NETWORK_ONE_BYTE)
    {
        segment_size_bytes = CIP_PATH_SEGMENT_MIN_SIZE_BYTES;
    }
    else  // Variable length network segment (0x50)
    {
        size_t data_size_bytes = data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET] * CIP_WORD_TO_BYTES;
        segment_size_bytes = CIP_PATH_SEGMENT_MIN_SIZE_BYTES + data_size_bytes;
        if (segment_size_bytes > data_length)
        {
            return false;
        }
    }

    segment->type = CipSegment_Type_NETWORK;
    segment->size = segment_size_bytes;

    return true;
}

static bool parse_segment_port(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    uint8_t segment_type = data[CIP_PATH_TYPE_OFFSET];

    // set minimal expected segment size
    size_t segment_size_bytes = CIP_PATH_SEGMENT_MIN_SIZE_BYTES;

    // port segment extended port threshold
    #define CIP_PATH_PORT_EXTENDED 0x0F

    // calculate simple port (extended port is also a mask)
    uint16_t port_number = segment_type & CIP_PATH_PORT_EXTENDED;

    bool is_port_extended = port_number == CIP_PATH_PORT_EXTENDED;

    #define CIP_PATH_PORT_EXTENDED_LINK_ADDRESS_MASK 0x10
    bool is_long_address = (segment_type & CIP_PATH_PORT_EXTENDED_LINK_ADDRESS_MASK) != 0;

    if (is_long_address)
    {
        // add length of address
        segment_size_bytes += data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET];

        // add padding
        segment_size_bytes += segment_size_bytes % 2;
    }

    if (is_port_extended)
    {
        // add length of extended port
        segment_size_bytes += sizeof(uint16_t);
    }

    // Exit early, if we know we won't fit.
    if (segment_size_bytes > data_length)
    {
        return false;
    }

    if (is_port_extended)
    {
        size_t extended_port_offset = CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET;

        if (is_long_address)
        {
            extended_port_offset += sizeof(uint8_t);
        }

        port_number = LETOHS(&data[extended_port_offset]);
    }

    segment->port_id = port_number;

    if (!is_long_address)
    {
        size_t link_address_offset = CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET;

        if (is_port_extended)
        {
            link_address_offset += sizeof(uint16_t);
        }

        segment->type = CipSegment_Type_PORT_LINK_ADDRESS;
        segment->link_address = data[link_address_offset];
    }
    else
    {
        size_t link_address_offset = CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET + sizeof(uint8_t);

        if (is_port_extended)
        {
            link_address_offset += sizeof(uint16_t);
        }

        segment->type = CipSegment_Type_PORT_LINK_ADDRESS_EXTENDED;
        segment->data = &data[link_address_offset];
        segment->data_size = data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET];
    }

    segment->size = segment_size_bytes;

    return true;
}

static bool parse_segment_simple_data(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    size_t data_size_bytes
        = data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET] * CIP_WORD_TO_BYTES;

    // calculate expected size
    size_t segment_size_bytes = CIP_PATH_SEGMENT_MIN_SIZE_BYTES + data_size_bytes;

    // Exit early, if we know we won't fit.
    if (segment_size_bytes > data_length)
    {
        return false;
    }

    segment->type = CipSegment_Type_DATA_SIMPLE;
    segment->data = &data[CIP_PATH_SEGMENT_MIN_SIZE_BYTES];
    segment->data_size = data_size_bytes;
    segment->size = segment_size_bytes;

    return true;
}

static bool parse_segment_symbolic_extended_string(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    #define EXTENDED_STRING_SIZE_MASK 0x1F
    #define EXTENDED_STRING_FORMAT_MASK 0xE0

    #define NUMERIC_SYMBOL_USINT 6
    #define NUMERIC_SYMBOL_UINT 7
    #define NUMERIC_SYMBOL_UDINT 8

    #define DOUBLE_BYTE 2
    #define TRIPLE_BYTE 3

    uint8_t extended_format_byte = data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET];
    uint8_t extended_format_size = extended_format_byte & EXTENDED_STRING_SIZE_MASK;

    bool valid = true;
    size_t data_size = 0;
    switch (extended_format_byte & EXTENDED_STRING_FORMAT_MASK)
    {
    case EXTENDED_STRING_DOUBLE:
        data_size = extended_format_size * DOUBLE_BYTE;
        break;
    case EXTENDED_STRING_TRIPLE:
        data_size = extended_format_size * TRIPLE_BYTE;
        break;
    case EXTENDED_STRING_NUMERIC:
        if (extended_format_size == NUMERIC_SYMBOL_USINT)
        {
            data_size = sizeof(uint8_t);
        }
        else if (extended_format_size == NUMERIC_SYMBOL_UINT)
        {
            data_size = sizeof(uint16_t);
        }
        else if (extended_format_size == NUMERIC_SYMBOL_UDINT)
        {
            data_size = sizeof(uint32_t);
        }
        else
        {
            valid = false;
        }
        break;
    default:
        valid = false;
        break;
    }

    size_t segment_size_bytes = CIP_PATH_SEGMENT_MIN_SIZE_BYTES + data_size;

    // Add padding.
    segment_size_bytes += segment_size_bytes % 2;

    if (data_length < segment_size_bytes)
    {
        return false;
    }

    segment->type = CipSegment_Type_SYMBOLIC;
    segment->data = &data[CIP_PATH_SEGMENT_MIN_SIZE_BYTES];
    segment->data_size = data_size;
    segment->size = segment_size_bytes;

    return valid;
}

static bool parse_segment_symbolic(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    #define CIP_PATH_SYMBOLIC_SIZE_MASK 0x1F

    bool valid = true;

    uint8_t symbol_size_bytes = data[CIP_PATH_TYPE_OFFSET] & CIP_PATH_SYMBOLIC_SIZE_MASK;
    if (symbol_size_bytes == 0)
    {
        valid = parse_segment_symbolic_extended_string(data, data_length, segment);
    }
    else  // Size 1 - 31.
    {
        size_t expected_segment_size = CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET + symbol_size_bytes;

        // Add padding
        expected_segment_size += expected_segment_size % 2;

        if (expected_segment_size > data_length)
        {
            valid = false;
        }
        else
        {
            segment->type = CipSegment_Type_SYMBOLIC;
            segment->data = &data[CIP_PATH_SEGMENT_PAYLOAD_SIZE_OFFSET];
            segment->data_size = symbol_size_bytes;
            segment->size = expected_segment_size;
        }
    }

    return valid;
}

static bool parse_cip_segment(const uint8_t* data,
    size_t data_length,
    CipSegment* segment)
{
    bool valid = true;

    #define CIP_PATH_SEGMENT_TYPE_MASK 0xE0

    uint8_t segment_type = data[CIP_PATH_TYPE_OFFSET];
    switch (segment_type & CIP_PATH_SEGMENT_TYPE_MASK)
    {
    case CIP_PATH_SEGMENT_PORT:
        valid = parse_segment_port(
            data,
            data_length,
            segment);
        break;
    case CIP_PATH_SEGMENT_LOGICAL:
        valid = parse_segment_logical(
            data,
            data_length,
            segment);
        break;
    case CIP_PATH_SEGMENT_DATA:
    {
        #define CIP_PATH_SEGMENT_SIMPLE_DATA 0x80
        #define CIP_PATH_SEGMENT_EXT_SYMBOL 0x91

        if (segment_type == CIP_PATH_SEGMENT_EXT_SYMBOL)
        {
            valid = parse_segment_extended_symbol(
                data,
                data_length,
                segment);
        }
        else if (segment_type == CIP_PATH_SEGMENT_SIMPLE_DATA)
        {
            valid = parse_segment_simple_data(
                data,
                data_length,
                segment);
        }
        else
        {
            set_unknown_segment_type(data_length, segment);
        }
        break;
    }
    case CIP_PATH_SEGMENT_NETWORK:
        valid = parse_segment_network(data, data_length, segment);
        break;
    case CIP_PATH_SEGMENT_SYMBOLIC:
        valid = parse_segment_symbolic(data, data_length, segment);
        break;
    default:
        set_unknown_segment_type(data_length, segment);
        break;
    }

    return valid;
}

static bool parse_cip_segments(const uint8_t* data,
    size_t data_length,
    CipPath* path)
{
    bool valid = true;

    // Parse all CIP segments.
    while (data_length > 0)
    {
        CipSegment segment;
        /* Check that there is enough data to start. */
        if (data_length < CIP_PATH_SEGMENT_MIN_SIZE_BYTES)
        {
            valid = false;
            break;
        }

        memset(&segment, 0, sizeof(segment));
        if (!parse_cip_segment(data, data_length, &segment))
        {
            valid = false;
            break;
        }

        // Save off key data in this segment for later use.
        if (segment.type == CipSegment_Type_LOGICAL_CLASS)
        {
            path->has_class_id = true;
            path->class_id = segment.logical_value;

            path->primary_segment_type = CipSegment_Type_LOGICAL_CLASS;
        }
        else if (segment.type == CipSegment_Type_DATA_EXT_SYMBOL)
        {
            path->primary_segment_type = CipSegment_Type_DATA_EXT_SYMBOL;
        }
        else if (segment.type == CipSegment_Type_LOGICAL_INSTANCE)
        {
            path->has_instance_id = true;
            path->instance_id = segment.logical_value;
        }
        else if (segment.type == CipSegment_Type_LOGICAL_ATTRIBUTE)
        {
            path->has_attribute_id = true;
            path->attribute_id = segment.logical_value;
        }
        else if (segment.type == CipSegment_Type_UNKNOWN)
        {
            path->has_unknown_segment = true;
        }

        // Move to the next segment.
        data_length -= segment.size;
        data += segment.size;
    }

    return valid;
}

static bool parse_cip_epath(const uint8_t* data,
    size_t data_length,
    bool path_contains_reserved_byte,
    CipPath* path)
{
    #define PATH_SIZE_FIELD_BYTES 1
    #define PATH_SIZE_OFFSET 0
    size_t path_size_bytes;
    size_t path_header_size;

    // There is a size byte and optionally a padding byte before the actual path data.
    path_header_size = PATH_SIZE_FIELD_BYTES;
    if (path_contains_reserved_byte)
    {
        path_header_size++;
    }

    // Validate/Get the Path Size.
    if (data_length < path_header_size)
    {
        return false;
    }

    path_size_bytes = data[PATH_SIZE_OFFSET] * CIP_WORD_TO_BYTES;
    if (data_length - path_header_size < path_size_bytes)
    {
        return false;
    }

    if (!parse_cip_segments(data + path_header_size, path_size_bytes, path))
    {
        return false;
    }

    path->full_path_size = path_header_size + path_size_bytes;
    path->decoded = true;

    return true;
}

// Parse the logical addressing format which is common to all logical segment
//  types, except Special and Service ID.
static bool parse_logical_address_format(const uint8_t* data,
    size_t data_length,
    bool logical_extended,
    CipSegment* segment)
{
    #define LOGICAL_8_BIT_SIZE 2
    #define LOGICAL_8_BIT_EXTENDED_SIZE 4
    #define LOGICAL_16_BIT_SIZE 4
    #define LOGICAL_32_BIT_SIZE 6
    #define LOGICAL_DEFAULT_DATA_OFFSET 2
    #define LOGICAL_8_BIT_DATA_OFFSET 1

    uint32_t logical_value;
    bool valid = true;

    uint8_t segment_type = data[CIP_PATH_TYPE_OFFSET];

    // Get the expected segment size and data offset.
    size_t segment_size = 0;
    size_t data_offset = LOGICAL_DEFAULT_DATA_OFFSET;
    switch (segment_type & CIP_PATH_LOGICAL_FORMAT_MASK)
    {
    case CIP_PATH_LOGICAL_32_BIT:
        segment_size = LOGICAL_32_BIT_SIZE;
        break;
    case CIP_PATH_LOGICAL_16_BIT:
        segment_size = LOGICAL_16_BIT_SIZE;
        break;
    case CIP_PATH_LOGICAL_8_BIT:
        if (logical_extended)
        {
            segment_size = LOGICAL_8_BIT_EXTENDED_SIZE;
        }
        else
        {
            segment_size = LOGICAL_8_BIT_SIZE;
            data_offset = LOGICAL_8_BIT_DATA_OFFSET;
        }
        break;
    default:
        valid = false;
        break;
    }

    // Exit early, if we know we won't fit.
    if (segment_size > data_length)
    {
        return false;
    }

    // Get the logical value.
    logical_value = 0;
    switch (segment_type & CIP_PATH_LOGICAL_FORMAT_MASK)
    {
    case CIP_PATH_LOGICAL_32_BIT:
        logical_value = LETOHL(&data[data_offset]);
        break;
    case CIP_PATH_LOGICAL_16_BIT:
        logical_value = LETOHS(&data[data_offset]);
        break;
    case CIP_PATH_LOGICAL_8_BIT:
        logical_value = data[data_offset];
        break;
    default:
        valid = false;
        break;
    }

    segment->logical_value = logical_value;
    segment->size = segment_size;

    return valid;
}

static bool parse_cip_status(const uint8_t* data,
    size_t data_length,
    CipStatus* status)
{
    if (data_length < CIP_STATUS_MIN_SIZE)
    {
        return false;
    }

    #define CIP_STATUS_OFFSET_GEN_STATUS 0
    status->general_status = data[CIP_STATUS_OFFSET_GEN_STATUS];

    #define CIP_STATUS_OFFSET_EXT_STATUS_SIZE 1
    status->extended_status_size = data[CIP_STATUS_OFFSET_EXT_STATUS_SIZE] * CIP_WORD_TO_BYTES;

    // extended status size does not fit the response
    if (data_length < (CIP_STATUS_MIN_SIZE + status->extended_status_size))
    {
        return false;
    }

    return true;
}

/// Forward Open/Close parsing.
static bool parse_forward_open_request(const uint8_t* data,
    size_t data_length,
    bool large_forward_open,
    CipForwardOpenRequest* forward_open_request,
    CipRequest* cip_request)
{
    // This includes all data up to, but not including, the Connection Path Size.
    #define CIP_FORWARD_OPEN_PREFIX_SIZE 35
    #define CIP_LARGE_FORWARD_OPEN_PREFIX_SIZE 39
    #define FWD_OPEN_OFFSET_CONN_SIGNATURE 10
    #define DEFAULT_CONNECTION_TIMEOUT (10 * USEC_PER_SEC)
    size_t forward_open_prefix_size;

    // Size of the common connection-related parameters fields. This includes
    //  the RPI and the Network Connection Parameters.
    size_t connection_parameters_size;
    size_t offset_to_parameters;
    size_t offset_transport_type_trigger;
    size_t offset_connection_path_size;
    uint8_t connection_timeout_multiplier;
    const bool NO_PATH_RESERVED_BYTE = false;

    if (large_forward_open)
    {
        connection_parameters_size = sizeof(uint32_t) + sizeof(uint32_t);
        forward_open_prefix_size = CIP_LARGE_FORWARD_OPEN_PREFIX_SIZE;
    }
    else
    {
        connection_parameters_size = sizeof(uint32_t) + sizeof(uint16_t);
        forward_open_prefix_size = CIP_FORWARD_OPEN_PREFIX_SIZE;
    }

    // Ensure that there is enough data for the common part of a Forward Open.
    if (data_length < forward_open_prefix_size)
    {
        return false;
    }
    data_length -= forward_open_prefix_size;

    #define FWD_OPEN_OFFSET_TIMEOUT_MULTIPLIER 18
    #define FWD_OPEN_OFFSET_OT_RPI 22
    offset_to_parameters = FWD_OPEN_OFFSET_OT_RPI + connection_parameters_size;
    offset_transport_type_trigger = offset_to_parameters + connection_parameters_size;
    offset_connection_path_size = offset_transport_type_trigger + 1;

    forward_open_request->timeout_ms = get_unconnected_timeout(data);
    parse_connection_signature(&data[FWD_OPEN_OFFSET_CONN_SIGNATURE],
        &forward_open_request->connection_signature);
    parse_connection_parameters(&data[FWD_OPEN_OFFSET_OT_RPI],
        large_forward_open,
        &forward_open_request->ot_parameters);
    parse_connection_parameters(&data[offset_to_parameters],
        large_forward_open,
        &forward_open_request->to_parameters);

    // Get the overall connection timeouts.
    connection_timeout_multiplier = data[FWD_OPEN_OFFSET_TIMEOUT_MULTIPLIER];
    #define MULTIPLIER_DEFAULT 2
    #define MAX_TIMEOUT_MULTIPLIER 7
    if (connection_timeout_multiplier <= MAX_TIMEOUT_MULTIPLIER)
    {
        uint16_t actual_multiplier = 1 << (connection_timeout_multiplier + MULTIPLIER_DEFAULT);
        forward_open_request->ot_connection_timeout_us
            = forward_open_request->ot_parameters.rpi * actual_multiplier;
        forward_open_request->to_connection_timeout_us
            = forward_open_request->to_parameters.rpi * actual_multiplier;
    }
    else
    {
        cip_request->cip_req_invalid_nonfatal |= CIP_REQ_INVALID_TIMEOUT_MULTIPLIER;
        forward_open_request->ot_connection_timeout_us = DEFAULT_CONNECTION_TIMEOUT;
        forward_open_request->to_connection_timeout_us = DEFAULT_CONNECTION_TIMEOUT;
    }

    if (forward_open_request->ot_parameters.is_null_connection
        && forward_open_request->to_parameters.is_null_connection)
    {
        forward_open_request->is_null_forward_open = true;
    }

    uint8_t transport_type_trigger = data[offset_transport_type_trigger];
    forward_open_request->transport_class = transport_type_trigger & TRANSPORT_CLASS_MASK;

    // Parse out the Connection Path. This is a variable length section.
    bool valid = parse_cip_epath(&data[offset_connection_path_size],
        data_length,
        NO_PATH_RESERVED_BYTE,
        &forward_open_request->connection_path);

    return valid;
}

static bool parse_forward_open_response_success(const uint8_t* data,
    size_t data_length,
    CipForwardOpenResponse* forward_open_response)
{
    #define FWD_OPEN_OFFSET_CON_SIGNATURE 8
    #define CIP_FORWARD_OPEN_RESPONSE_PREFIX_SIZE 26
    if (data_length < CIP_FORWARD_OPEN_RESPONSE_PREFIX_SIZE)
    {
        return false;
    }

    #define FWD_OPEN_OFFSET_OT_CONNECTION 0
    #define FWD_OPEN_OFFSET_TO_CONNECTION 4
    #define FWD_OPEN_OFFSET_REPLY_SIZE 24

    forward_open_response->connection_pair.ot_connection_id
        = LETOHL(&data[FWD_OPEN_OFFSET_OT_CONNECTION]);
    forward_open_response->connection_pair.to_connection_id
        = LETOHL(&data[FWD_OPEN_OFFSET_TO_CONNECTION]);
    parse_connection_signature(&data[FWD_OPEN_OFFSET_CON_SIGNATURE],
        &forward_open_response->connection_signature);
    forward_open_response->application_reply_size
        = data[FWD_OPEN_OFFSET_REPLY_SIZE] * CIP_WORD_TO_BYTES;

    data_length -= CIP_FORWARD_OPEN_RESPONSE_PREFIX_SIZE;
    if (data_length < forward_open_response->application_reply_size)
    {
        return false;
    }

    forward_open_response->success = true;

    return true;
}

static bool parse_forward_open_response_fail(const uint8_t* data,
    size_t data_length,
    CipForwardOpenResponse* forward_open_response)
{
    #define CIP_FORWARD_OPEN_RESPONSE_FAIL_SIZE 10
    if (data_length < CIP_FORWARD_OPEN_RESPONSE_FAIL_SIZE)
    {
        return false;
    }

    parse_connection_signature(data, &forward_open_response->connection_signature);

    forward_open_response->success = false;

    return true;
}

static bool parse_forward_open_response(const uint8_t* data,
    size_t data_length,
    uint8_t response_status,
    CipForwardOpenResponse* forward_open_response)
{
    bool valid = true;

    // Forward Open Success and Failure cases have different formats.
    if (response_status == CIP_STATUS_SUCCESS)
    {
        valid = parse_forward_open_response_success(data, data_length, forward_open_response);
    }
    else
    {
        valid = parse_forward_open_response_fail(data, data_length, forward_open_response);
    }

    return valid;
}

static bool parse_forward_close_request(const uint8_t* data,
    size_t data_length,
    CipForwardCloseRequest* forward_close_request)
{
    bool valid;
    const bool PATH_RESERVED_BYTE = true;
    #define CIP_FORWARD_CLOSE_PREFIX_SIZE 10
    if (data_length < CIP_FORWARD_CLOSE_PREFIX_SIZE)
    {
        return false;
    }

    #define FWD_CLOSE_OFFSET_CONNECTION_SIGNATURE 2

    forward_close_request->timeout_ms = get_unconnected_timeout(data);
    parse_connection_signature(&data[FWD_CLOSE_OFFSET_CONNECTION_SIGNATURE],
        &forward_close_request->connection_signature);

    // Parse out the Connection Path. This is a variable length section.
    valid = parse_cip_epath(data + CIP_FORWARD_CLOSE_PREFIX_SIZE,
        data_length - CIP_FORWARD_CLOSE_PREFIX_SIZE,
        PATH_RESERVED_BYTE,
        &forward_close_request->connection_path);

    return valid;
}

// Returns size of the CIP Request Header that was parsed.
static bool parse_cip_request_header(const uint8_t* data,
    size_t data_length,
    size_t* header_size,
    CipRequest* cip_request)
{
    bool valid;
    CipPath* path;
    const bool NO_PATH_RESERVED_BYTE = false;
    #define CIP_SERVICE_SIZE 1
    if (data_length < CIP_SERVICE_SIZE)
    {
        return false;
    }

    #define CIP_SERVICE_OFFSET 0
    cip_request->service = data[CIP_SERVICE_OFFSET];

    // Reset all path information.
    memset(&cip_request->request_path, 0, sizeof(cip_request->request_path));
    path = &cip_request->request_path;

    valid = parse_cip_epath(data + CIP_SERVICE_SIZE,
        data_length - CIP_SERVICE_SIZE,
        NO_PATH_RESERVED_BYTE,
        path);
    if (!valid)
    {
        return false;
    }

    if (path->has_unknown_segment)
    {
        cip_request->cip_req_invalid_nonfatal |= CIP_REQ_INVALID_UNKNOWN_SEGMENT;
    }

    *header_size = CIP_SERVICE_SIZE + path->full_path_size;

    return true;
}

static size_t cip_status_size(const CipStatus* status)
{
    return CIP_STATUS_MIN_SIZE + status->extended_status_size;
}

static bool parse_multiple_service_packet(const uint8_t* data,
    size_t data_length,
    CipRequest* cip_request,
    CipGlobalSessionData* global_data)
{
    // Save the original data length for use in handling the offsets of embedded services.
    uint16_t number_services;
    size_t total_offset_size;
    size_t data_offset;
    size_t first_offset;
    bool valid;
    uint16_t i;
    size_t original_data_length = data_length;

    // Check that the number of services will fit.
    #define CIP_MSP_NUMBER_SERVICES_FIELD_SIZE 2
    if (data_length < CIP_MSP_NUMBER_SERVICES_FIELD_SIZE)
    {
        return false;
    }

    #define CIP_MSP_OFFSET_NUMBER_SERVICES 0
    number_services = data[CIP_MSP_OFFSET_NUMBER_SERVICES];
    data_length -= CIP_MSP_NUMBER_SERVICES_FIELD_SIZE;

    // Check that the offsets will fit.
    #define CIP_MSP_OFFSET_FIELD_SIZE 2
    total_offset_size = number_services * CIP_MSP_OFFSET_FIELD_SIZE;
    if (data_length < total_offset_size)
    {
        return false;
    }

    // Length of actual data left after the offsets.
    data_length -= total_offset_size;

    // Check that offset data starts after the last offset.
    data_offset = CIP_MSP_NUMBER_SERVICES_FIELD_SIZE + total_offset_size;
    first_offset = LETOHS(&data[CIP_MSP_NUMBER_SERVICES_FIELD_SIZE]);
    if (first_offset < data_offset)
    {
        return false;
    }

    valid = true;

    // Process each embedded service.
    for (i = 1; i <= number_services; ++i)
    {
        size_t msp_length;
        CipRequest embedded_request;
        CipEventData cip_event_data;
        CipEvent cip_event(global_data->snort_packet, &cip_event_data);

        /* This if the offset from the Number of Services field, to the Offset field. */
        uint16_t buffer_offset = i * CIP_MSP_OFFSET_FIELD_SIZE;

        /* This if the offset from the Number of Services field to the data. */
        size_t msp_offset = LETOHS(&data[buffer_offset]);

        /* There is no end offset specified, so the next offset needs checked
           to find the length of the current service. For the last packet,
           this needs to use the total length of the Multiple Service Packet. */
        size_t msp_offset_end = 0;
        if (i == number_services)
        {
            msp_offset_end = original_data_length;
        }
        else
        {
            uint16_t next_buffer_offset = buffer_offset + CIP_MSP_OFFSET_FIELD_SIZE;
            msp_offset_end = LETOHS(&data[next_buffer_offset]);
        }

        // Check that offsets are increasing.
        if (msp_offset >= msp_offset_end)
        {
            valid = false;
            break;
        }

        // Check embedded length against the data size left.
        msp_length = msp_offset_end - msp_offset;
        if (data_length < msp_length)
        {
            valid = false;
            break;
        }

        data_length -= msp_length;

        memset(&embedded_request, 0, sizeof(embedded_request));
        if (!parse_message_router_request(data + msp_offset,
            msp_length,
            &embedded_request,
            global_data))
        {
            valid = false;
            break;
        }

        // Store embedded packet errors in the parent request.
        cip_request->cip_req_invalid_nonfatal |= embedded_request.cip_req_invalid_nonfatal;

        // Publish embedded CIP data to appid.
        memset(&cip_event_data, 0, sizeof(cip_event_data));

        pack_cip_request_event(&embedded_request, &cip_event_data);

        DataBus::publish(CipEventData::pub_id, CipEventIds::DATA, cip_event, global_data->snort_packet->flow);
    }

    return valid;
}

static bool parse_unconnected_send_request(const uint8_t* data,
    size_t data_length,
    CipRequest* cip_request,
    CipGlobalSessionData* global_data)
{
    bool valid;
    uint16_t message_request_size;
    const bool PATH_RESERVED_BYTE = true;
    // This includes: Timeout data, embedded message size.
    #define UNCONNECTED_SEND_HEADER_SIZE 4
    if (data_length < UNCONNECTED_SEND_HEADER_SIZE)
    {
        return false;
    }

    cip_request->timeout_ms = get_unconnected_timeout(data);
    cip_request->has_timeout = true;

    #define UNCONNECTED_SEND_OFFSET_MESSAGE_SIZE 2
    message_request_size = LETOHS(&data[UNCONNECTED_SEND_OFFSET_MESSAGE_SIZE]);

    data += UNCONNECTED_SEND_HEADER_SIZE;
    data_length -= UNCONNECTED_SEND_HEADER_SIZE;

    // Verify that expected length of embedded request will fit in actual data.
    if (message_request_size > data_length)
    {
        return false;
    }

    if (!parse_message_router_request(data, message_request_size, cip_request, global_data))
    {
        return false;
    }

    // Parse the Route Path.
    valid = parse_cip_epath(data + message_request_size,
        data_length - message_request_size,
        PATH_RESERVED_BYTE,
        &cip_request->route_path);

    return valid;
}

static bool parse_cip_command_specific_data_request(const uint8_t* data,
    size_t data_length,
    CipRequest* cip_request,
    CipGlobalSessionData* global_data)
{
    const CipProtoConf* config;
    /* If the request path doesn't have a Class ID, then we don't know how to
       parse the response.*/
    if (!cip_request->request_path.has_class_id)
    {
        cip_request->request_type = CipRequestTypeOther;
        return true;
    }

    bool valid = true;

    uint8_t service = cip_request->service;
    uint32_t class_id = cip_request->request_path.class_id;
    if (service == SERVICE_MULTIPLE_SERVICE_PACKET)
    {
        valid = parse_multiple_service_packet(data, data_length, cip_request, global_data);
        cip_request->request_type = CipRequestTypeMultipleServiceRequest;
    }
    else if (class_id == CONNECTION_MANAGER_CLASS_ID
        && service == CONNECTION_MANAGER_UNCONNECTED_SEND)
    {
        valid = parse_unconnected_send_request(data,
            data_length,
            cip_request,
            global_data);
        cip_request->request_type = CipRequestTypeUnconnectedSend;
    }
    else if (class_id == CONNECTION_MANAGER_CLASS_ID
        && (service == CONNECTION_MANAGER_FORWARD_OPEN
        || service == CONNECTION_MANAGER_LARGE_FORWARD_OPEN))
    {
        CipForwardOpenRequest forward_open_request;
        memset(&forward_open_request, 0, sizeof(forward_open_request));

        bool large_forward_open = (service == CONNECTION_MANAGER_LARGE_FORWARD_OPEN);
        valid = parse_forward_open_request(data,
            data_length,
            large_forward_open,
            &forward_open_request,
            cip_request);
        forward_open_request.timestamp = global_data->snort_packet->pkth->ts;

        if (valid)
        {
            // Only store connection information for Class 3, Non-Null connections.
            if (!forward_open_request.is_null_forward_open
                && forward_open_request.transport_class == 3)
            {
                if (!cip_add_connection_to_pending(&global_data->connection_list,
                    &forward_open_request))
                {
                    // Error if the connection couldn't be added to the list.
                    cip_request->cip_req_invalid_nonfatal |= CIP_REQ_INVALID_CONNECTION_ADD_FAILED;
                }
            }

            cip_request->is_forward_open_request = true;
            cip_request->connection_path_class_id = forward_open_request.connection_path.class_id;
            cip_request->timeout_ms = forward_open_request.timeout_ms;
            cip_request->has_timeout = true;
        }

        cip_request->request_type = CipRequestTypeForwardOpen;
    }
    else if (class_id == CONNECTION_MANAGER_CLASS_ID
        && service == CONNECTION_MANAGER_FORWARD_CLOSE)
    {
        CipForwardCloseRequest forward_close_request;
        memset(&forward_close_request, 0, sizeof(forward_close_request));

        valid = parse_forward_close_request(data,
            data_length,
            &forward_close_request);

        if (valid)
        {
            const bool connection_established = true;
            cip_remove_connection(&global_data->connection_list,
                &forward_close_request.connection_signature,
                connection_established);

            cip_request->timeout_ms = forward_close_request.timeout_ms;
            cip_request->has_timeout = true;
        }

        cip_request->request_type = CipRequestTypeForwardClose;
    }
    else
    {
        // This is a regular CIP request. No need to parse data.
        cip_request->request_type = CipRequestTypeOther;
    }

    // Parse any embedded CIP packet that is configured.
    config = global_data->config;
    if (config->embedded_cip_enabled
        && class_id == config->embedded_cip_class_id
        && service == config->embedded_cip_service_id)
    {
        valid = parse_message_router_request(data, data_length, cip_request, global_data);
    }

    return valid;
}

static bool parse_cip_command_specific_data_response(const CipStatus* status,
    const uint8_t* data,
    size_t data_length,
    CipRequestType request_type,
    CipGlobalSessionData* global_data)
{
    bool valid = true;

    if (request_type == CipRequestTypeForwardOpen)
    {
        CipForwardOpenResponse forward_open_response;
        memset(&forward_open_response, 0, sizeof(forward_open_response));

        valid = parse_forward_open_response(data,
            data_length,
            status->general_status,
            &forward_open_response);
        forward_open_response.timestamp = global_data->snort_packet->pkth->ts;

        if (forward_open_response.success)
        {
            cip_add_connection_to_active(&global_data->connection_list, &forward_open_response);
        }
        else
        {
            const bool connection_established = false;
            cip_remove_connection(&global_data->connection_list,
                &forward_open_response.connection_signature,
                connection_established);
        }
    }

    return valid;
}


static bool parse_message_router_request(const uint8_t* data,
    size_t data_length,
    CipRequest* cip_request,
    CipGlobalSessionData* global_data)
{
    size_t header_size = 0;
    if (!parse_cip_request_header(data,
        data_length,
        &header_size,
        cip_request))
    {
        return false;
    }

    cip_request->cip_data = data + header_size;
    cip_request->cip_data_size = data_length - header_size;

    bool valid = parse_cip_command_specific_data_request(data + header_size,
        data_length - header_size,
        cip_request,
        global_data);

    return valid;
}

static bool parse_message_router_response(const uint8_t* data,
    size_t data_length,
    CipRequestType request_type,
    CipResponse* cip_response,
    CipGlobalSessionData* global_data)
{
    bool valid;
    size_t response_header_size;
    size_t status_size;
    #define MESSAGE_ROUTER_RESPONSE_MIN_SIZE 4
    if (data_length < MESSAGE_ROUTER_RESPONSE_MIN_SIZE)
    {
        return false;
    }

    #define CIP_SERVICE_OFFSET 0
    #define CIP_STATUS_OFFSET 2

    cip_response->service = data[CIP_SERVICE_OFFSET] & ~MESSAGE_ROUTER_RESPONSE_MASK;

    if (!parse_cip_status(data + CIP_STATUS_OFFSET,
        data_length - CIP_STATUS_OFFSET,
        &cip_response->status))
    {
        return false;
    }

    status_size = cip_status_size(&cip_response->status);

    // This includes: Service, reserved field, total status data.
    response_header_size = CIP_STATUS_OFFSET + status_size;

    valid = true;
    // Don't attempt to decode the command specific response if there wasn't a
    //  match to an existing request.
    if (request_type != CipRequestTypeNoMatchFound)
    {
        valid = parse_cip_command_specific_data_response(&cip_response->status,
            data + response_header_size,
            data_length - response_header_size,
            request_type,
            global_data);
    }

    return valid;
}

// Returns true if the serviceId was a request service.
static bool is_service_request(uint8_t service_id)
{
    return (service_id & MESSAGE_ROUTER_RESPONSE_MASK) == 0;
}

static bool parse_message_router(const uint8_t* data,
    size_t data_length,
    CipCurrentData* current_data,
    CipGlobalSessionData* global_data)
{
    bool valid = true;

    CipMessage* cip_msg = &current_data->cip_msg;

    cip_msg->is_cip_request = is_service_request(*data);
    if (cip_msg->is_cip_request)
    {
        cip_msg->request.request_type = CipRequestTypeOther;
        valid = parse_message_router_request(data,
            data_length,
            &cip_msg->request,
            global_data);

        cip_request_add(&global_data->unconnected_list,
            &current_data->enip_data,
            &cip_msg->request,
            &global_data->snort_packet->pkth->ts);
    }
    else
    {
        CipRequestType request_type = CipRequestTypeNoMatchFound;
        cip_request_remove(&global_data->unconnected_list,
            &current_data->enip_data,
            &request_type);

        valid = parse_message_router_response(data,
            data_length,
            request_type,
            &cip_msg->response,
            global_data);
    }

    return valid;
}

// Returns true if this data contains valid CIP Explicit data. The data must already:
//  1. Be ENIP_COMMAND_SEND_UNIT_DATA or ENIP_COMMAND_SEND_RR_DATA
//  2. Have the required CPF items for that ENIP command.
static bool parse_cip_explicit_data(CipCurrentData* current_data, CipGlobalSessionData* global_data)
{
    // Assume that all data values/length inside the EnipCpf are valid.
    const EnipCpf* enip_cpf = &current_data->enip_data.enip_cpf;
    const EnipCpfItem* cpf_item = &enip_cpf->item_list[CPF_DATA_ITEM_SLOT];

    // Get the offset of the CIP Message Router data.
    size_t cpf_data_offset = 0;
    if (cpf_item->type == CPF_CONNECTED_DATA_ITEM_ID)
    {
        // For CIP Class 3 data, Connected Data contains: Sequence Count, then CIP Data.
        const size_t CPF_CONNECTED_DATA_SEQUENCE_COUNT_SIZE = sizeof(uint16_t);
        cpf_data_offset = CPF_CONNECTED_DATA_SEQUENCE_COUNT_SIZE;
    }
    else  // CPF_UNCONNECTED_DATA_ITEM_ID
    {
        cpf_data_offset = 0;
    }

    bool valid = false;
    if (cpf_item->length > cpf_data_offset)
    {
        const uint8_t* message_router_data = cpf_item->data + cpf_data_offset;
        size_t message_router_data_length = cpf_item->length - cpf_data_offset;

        valid = parse_message_router(message_router_data,
            message_router_data_length,
            current_data,
            global_data);
    }

    return valid;
}

// Used for parsing SendRRData and SendUnitData Command Specific Data.
static bool parse_enip_command_data(const uint8_t* data,
    size_t data_length,
    CipCurrentData* current_data,
    CipGlobalSessionData* global_data)
{
    uint32_t interface_handle;

    // This should always contain: Interface Handle, Timeout.
#define ENIP_COMMAND_HEADER_SIZE 6
    if (data_length < ENIP_COMMAND_HEADER_SIZE)
    {
        return false;
    }

    // Interface Handle
 #define ENIP_OFFSET_INTERFACE_HANDLE 0
    interface_handle = LETOHL(&data[ENIP_OFFSET_INTERFACE_HANDLE]);

#define CIP_INTERFACE_HANDLE 0
    if (interface_handle != CIP_INTERFACE_HANDLE)
    {
        current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_INTERFACE_HANDLE;
    }

    // Parse the Encapsulated Data as Common Packet Format.
    current_data->enip_data.cpf_decoded = parse_common_packet_format(data + ENIP_COMMAND_HEADER_SIZE,
        data_length - ENIP_COMMAND_HEADER_SIZE,
        &current_data->enip_data.enip_cpf,
        current_data);
    if (!current_data->enip_data.cpf_decoded)
    {
        return false;
    }

    // Exit early if CIP Explicit Data cannot be processed.
    if (!current_data->enip_data.required_cpf_items_present)
    {
        return true;
    }

    current_data->cip_message_type = get_cip_message_type(current_data, global_data);

    bool valid = true;
    if (current_data->cip_message_type == CipMessageTypeExplicit)
    {
        valid = parse_cip_explicit_data(current_data, global_data);
    }

    return valid;
}

bool parse_enip_layer(const uint8_t* data,
    size_t data_length,
    bool is_TCP,
    CipCurrentData* current_data,
    CipGlobalSessionData* global_data)
{
    const EnipHeader* enip_header;
    current_data->enip_data.enip_decoded = parse_enip_header(data,
        data_length,
        &current_data->enip_data);
    if (!current_data->enip_data.enip_decoded)
    {
        return false;
    }

    // Command Specific Data
    data += ENIP_HEADER_SIZE;
    data_length -= ENIP_HEADER_SIZE;

    // Verify that actual data matches data length field.
    enip_header  = &current_data->enip_data.enip_header;
    if (data_length < enip_header->length)
    {
        return false;
    }

    if (enip_command_tcp_only(enip_header->command) && !is_TCP)
    {
        // Flag as an error and exit early because there would be no way to tie this data
        //  to a particular TCP session.
        current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_ENIP_TCP_ONLY;

        return true;
    }

    if (enip_header->status != ENIP_STATUS_SUCCESS)
    {
        if (current_data->direction == CIP_FROM_CLIENT)
        {
            current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_STATUS;
        }
        else if (current_data->direction == CIP_FROM_SERVER)
        {
            // Remove any outstanding request.
            CipRequestType request_type = CipRequestTypeNoMatchFound;
            cip_request_remove(&global_data->unconnected_list,
                &current_data->enip_data,
                &request_type);
        }

        // No more processing after a non-success status.
        return true;
    }

    bool valid = true;

    switch (enip_header->command)
    {
    case ENIP_COMMAND_REGISTER_SESSION:
    {
        if (data_length < REGISTER_SESSION_DATA_SIZE)
        {
            valid = false;
            break;
        }

        // Check that there is no active ENIP session.
        if (current_data->direction == CIP_FROM_CLIENT)
        {
            if (global_data->enip_session.active)
            {
                current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_DUPLICATE_SESSION;
            }
        }

        // Add ENIP session to the current TCP session.
        if (current_data->direction == CIP_FROM_SERVER)
        {
            if (!enip_session_add(&global_data->enip_session,
                enip_header->session_handle))
            {
                current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_DUPLICATE_SESSION;
            }
        }
    }
    break;

    case ENIP_COMMAND_SEND_RR_DATA:
    case ENIP_COMMAND_SEND_UNIT_DATA:
        valid = parse_enip_command_data(data, data_length, current_data, global_data);

        // Check that the Session Handle matches the active ENIP session.
        if (!enip_session_handle_valid(&global_data->enip_session, enip_header->session_handle))
        {
            current_data->enip_data.enip_invalid_nonfatal |= ENIP_INVALID_SESSION_HANDLE;
        }
        break;
    case ENIP_COMMAND_NOP:
        break;
    case ENIP_COMMAND_LIST_SERVICES:
    case ENIP_COMMAND_LIST_IDENTITY:
    case ENIP_COMMAND_LIST_INTERFACES:
        if (current_data->direction == CIP_FROM_SERVER)
        {
            current_data->enip_data.cpf_decoded = parse_common_packet_format(data,
                data_length,
                &current_data->enip_data.enip_cpf,
                current_data);
            if (!current_data->enip_data.cpf_decoded)
            {
                valid = false;
            }
        }
        break;
    case ENIP_COMMAND_UNREGISTER_SESSION:
        // Remove ENIP session from the current TCP session.
        enip_session_remove(&global_data->enip_session, enip_header->session_handle);
        break;
    default:
        // Ignore legacy cases.
        break;
    }

    return valid;
}

void pack_cip_request_event(const CipRequest* request, CipEventData* cip_event_data)
{
    cip_event_data->service_id = request->service;

    if (request->is_forward_open_request)
    {
        cip_event_data->type = CIP_DATA_TYPE_CONNECTION;
        cip_event_data->class_id = request->connection_path_class_id;
    }
    else if (request->request_path.primary_segment_type == CipSegment_Type_LOGICAL_CLASS)
    {
        // Publish Set Attribute Single services separately than other requests.
        if (cip_event_data->service_id == SERVICE_SET_ATTRIBUTE_SINGLE
            && request->request_path.has_instance_id
            && request->request_path.has_attribute_id)
        {
            cip_event_data->instance_id = request->request_path.instance_id;
            cip_event_data->attribute_id = request->request_path.attribute_id;

            cip_event_data->type = CIP_DATA_TYPE_SET_ATTRIBUTE;
        }
        else
        {
            cip_event_data->type = CIP_DATA_TYPE_PATH_CLASS;
        }

        cip_event_data->class_id = request->request_path.class_id;
    }
    else if (request->request_path.primary_segment_type == CipSegment_Type_DATA_EXT_SYMBOL)
    {
        cip_event_data->type = CIP_DATA_TYPE_PATH_EXT_SYMBOL;
    }
    else
    {
        cip_event_data->type = CIP_DATA_TYPE_OTHER;
    }
}

