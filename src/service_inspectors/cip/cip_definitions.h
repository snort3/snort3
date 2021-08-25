//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

// cip_definitions.h author RA/Cisco

/* Description: Common types for the CIP inspector. */

#ifndef CIP_DEFINITIONS_H
#define CIP_DEFINITIONS_H

#include <sys/time.h>

namespace snort
{
struct Packet;
}

#define MSEC_PER_SEC (1000)
#define USEC_PER_SEC (1000000)

// CIP inspector configuration
struct CipProtoConf
{
    // Unconnected timeout, seconds.
    uint32_t unconnected_timeout;

    // Maximum number of unconnected requests per TCP connection.
    uint32_t max_unconnected_messages;

    // Maximum number of CIP connections per TCP connection.
    uint32_t max_cip_connections;

    // Custom embedded packet parameters.
    bool embedded_cip_enabled;
    uint32_t embedded_cip_class_id;
    uint8_t embedded_cip_service_id;
};

/// CIP Request/Response Management
enum CipRequestType
{
    CipRequestTypeOther = 0,
    CipRequestTypeForwardOpen,
    CipRequestTypeForwardClose,
    CipRequestTypeUnconnectedSend,
    CipRequestTypeMultipleServiceRequest,

    // Special case to represent when no request is found for a given response.
    CipRequestTypeNoMatchFound
};

struct CipStatus
{
    uint8_t general_status;
    size_t extended_status_size;
};

enum CipPacketDirection
{
    CIP_FROM_CLIENT,
    CIP_FROM_SERVER,
    CIP_FROM_UNKNOWN
};

/// EtherNet/IP encapsulation layer definitions.

// EtherNet/IP encapsulation header
struct EnipHeader
{
    uint16_t command;
    uint16_t length;
    uint32_t session_handle;
    uint32_t status;
    uint64_t sender_context;
    uint32_t options;
};

// This is an EtherNet/IP encapsulation layer common packet format item.
struct EnipCpfItem
{
    uint16_t type;
    uint16_t length;

    // Used if length > 0. Data starts after the Length field.
    const uint8_t* data;
};

// Largest number of allowed CPF items for standard EtherNet/IP commands.
#define MAX_NUM_CPF_ITEMS 4

// This is an EtherNet/IP encapsulation layer common packet format.
struct EnipCpf
{
    uint16_t item_count;

    // All CPF items in the list are valid up to and including array index item_count.
    EnipCpfItem item_list[MAX_NUM_CPF_ITEMS];
};

/// CIP layer definitions.
enum CipMessageType
{
    // Unknown CIP data type
    CipMessageTypeUnknown,

    // CIP Explicit Data
    CipMessageTypeExplicit,

    // CIP Implicit Data
    CipMessageTypeImplicit
};

enum CipSegmentType
{
    CipSegment_Type_PORT_LINK_ADDRESS,
    CipSegment_Type_PORT_LINK_ADDRESS_EXTENDED,

    CipSegment_Type_LOGICAL_CLASS,
    CipSegment_Type_LOGICAL_INSTANCE,
    CipSegment_Type_LOGICAL_MEMBER,
    CipSegment_Type_LOGICAL_CONN_POINT,
    CipSegment_Type_LOGICAL_ATTRIBUTE,
    CipSegment_Type_LOGICAL_ELECTRONIC_KEY,
    CipSegment_Type_LOGICAL_EXTENDED,
    CipSegment_Type_LOGICAL_SERVICE_ID,

    CipSegment_Type_NETWORK,

    CipSegment_Type_SYMBOLIC,

    CipSegment_Type_DATA_SIMPLE,
    CipSegment_Type_DATA_EXT_SYMBOL,

    CipSegment_Type_UNKNOWN
};

#define CIP_STATUS_SUCCESS 0
#define ENIP_STATUS_SUCCESS 0

// CIP Classes
#define MESSAGE_ROUTER_CLASS_ID 0x02
#define CONNECTION_MANAGER_CLASS_ID 0x06

// CIP Services
#define SERVICE_SET_ATTRIBUTE_SINGLE 0x10
#define SERVICE_MULTIPLE_SERVICE_PACKET 0x0A

// CIP Connection Manager Services
#define CONNECTION_MANAGER_UNCONNECTED_SEND 0x52
#define CONNECTION_MANAGER_FORWARD_OPEN 0x54
#define CONNECTION_MANAGER_LARGE_FORWARD_OPEN 0x5B
#define CONNECTION_MANAGER_FORWARD_CLOSE 0x4E

#define CIP_WORD_TO_BYTES 2

struct CipSegment
{
    CipSegmentType type;

    // Total size of this segment.
    size_t size;

    // When type = CipSegment_Type_PORT_LINK_ADDRESS
    // When type = CipSegment_Type_PORT_LINK_ADDRESS_EXTENDED
    uint16_t port_id;

    // When type = CipSegment_Type_PORT_LINK_ADDRESS
    uint8_t link_address;

    // When type = CipSegment_Type_LOGICAL_CLASS
    // When type = CipSegment_Type_LOGICAL_INSTANCE
    // When type = CipSegment_Type_LOGICAL_MEMBER
    // When type = CipSegment_Type_LOGICAL_CONN_POINT
    // When type = CipSegment_Type_LOGICAL_ATTRIBUTE
    uint32_t logical_value;

    // When type = CipSegment_Type_PORT_LINK_ADDRESS_EXTENDED, this is the link address.
    // When type = CipSegment_Type_DATA_EXT_SYMBOL, this is the symbol string.
    // When type = CipSegment_Type_DATA_SIMPLE, this is the start of the data words.
    // When type = CipSegment_Type_SYMBOLIC, this is the symbol string.
    const uint8_t* data;
    size_t data_size;
};

struct CipPath
{
    // Size of the entire path.
    size_t full_path_size;

    // True if path has been decoded successfully.
    bool decoded;

    // Main segment type for this path, which drives message target.
    CipSegmentType primary_segment_type;

    bool has_class_id;
    uint32_t class_id;

    bool has_instance_id;
    uint32_t instance_id;

    bool has_attribute_id;
    uint32_t attribute_id;

    bool has_unknown_segment;
};

// Matching pair of CIP Connection IDs.
struct ConnectionIdPair
{
    uint32_t ot_connection_id;
    uint32_t to_connection_id;
};

// RPI and Network Connection Parameters from a Forward Open Request.
struct CipConnectionParameters
{
    uint32_t rpi;
    uint32_t network_connection_parameters;
    bool is_null_connection;
};

// Unique Connection Signature. This is unique to each CIP connection. This
//  tuple is unique on a given EtherNet/IP session.
struct CipConnectionSignature
{
    uint16_t connection_serial_number;
    uint16_t vendor_id;
    uint32_t originator_serial_number;
};

#define TRANSPORT_CLASS_MASK 0x0F
struct CipForwardOpenRequest
{
    // Unconnected request timeout, milliseconds.
    uint32_t timeout_ms;

    // Connection timeouts, microseconds.
    uint64_t ot_connection_timeout_us;
    uint64_t to_connection_timeout_us;

    CipConnectionSignature connection_signature;

    CipConnectionParameters ot_parameters;
    CipConnectionParameters to_parameters;
    uint8_t transport_class;

    CipPath connection_path;

    bool is_null_forward_open;

    // Timestamp for message request.
    struct timeval timestamp;
};

struct CipForwardOpenResponse
{
    // True if this was a successful Forward Open Response.
    bool success;

    // Properties for Success or Fail.
    CipConnectionSignature connection_signature;

    // Properties for a Forward Open Response Success.
    ConnectionIdPair connection_pair;

    size_t application_reply_size;

    // Timestamp for message response.
    struct timeval timestamp;
};

struct CipForwardCloseRequest
{
    // Unconnected request timeout, milliseconds.
    uint32_t timeout_ms;

    CipConnectionSignature connection_signature;

    CipPath connection_path;
};

// Used to set error flags in enip_invalid_nonfatal.
#define ENIP_INVALID_COMMAND (1 << 0)
#define ENIP_INVALID_DUPLICATE_SESSION (1 << 1)
#define ENIP_INVALID_SESSION_HANDLE (1 << 2)
#define ENIP_INVALID_INTERFACE_HANDLE (1 << 3)
#define ENIP_INVALID_CONNECTION_ID (1 << 4)
#define ENIP_INVALID_PAYLOAD_SIZE (1 << 5)
#define ENIP_INVALID_ENIP_COMMAND_CPF_MISMATCH (1 << 6)
#define ENIP_INVALID_RESERVED_FUTURE_CPF_TYPE (1 << 7)
#define ENIP_INVALID_STATUS (1 << 8)
#define ENIP_INVALID_ENIP_TCP_ONLY (1 << 9)

struct EnipSessionData
{
    // True if the ENIP Header was parsed and is valid.
    bool enip_decoded;

    // Full ENIP header.
    EnipHeader enip_header;

    // Error states for non-fatal ENIP errors. Error conditions that could trigger this:
    //  - Command code was not valid according to CIP Volume 2, Section 2-3.2.
    //  - RegisterSession attempted when a session was already active.
    //  - Session Handle did not match an active session.
    //  - Interface Handle != 0
    //  - Connection ID does not match an active connection.
    //  - Larger amount of ENIP data than specific in ENIP length.
    //  - Invalid CPF data item for a particular ENIP command.
    //  - CPF Item Type ID was found in the Reserved for future expansion range.
    //  - ENIP Status != 0, for a Request.
    //  - Attempting to send an ENIP command that is TCP only on a UDP connection.
    uint32_t enip_invalid_nonfatal;

    // True if the Common Packet Format was parsed and is valid.
    bool cpf_decoded;

    // True if the required CPF items are present for this EtherNet/IP command.
    bool required_cpf_items_present;

    // Common Packet Format data.
    EnipCpf enip_cpf;

    // Connection Class from original connection request, for connected messages.
    uint32_t connection_class_id;
};

// Used to set error flags in cip_req_invalid_nonfatal.
#define CIP_REQ_INVALID_CONNECTION_ADD_FAILED (1 << 0)
#define CIP_REQ_INVALID_UNKNOWN_SEGMENT (1 << 1)
#define CIP_REQ_INVALID_TIMEOUT_MULTIPLIER (1 << 2)
struct CipRequest
{
    // CIP Service code.
    uint8_t service;

    CipPath request_path;

    CipRequestType request_type;

    // This is only valid for Unconnected Send messages.
    CipPath route_path;

    // CIP application payload data. This starts after the Request Path.
    const uint8_t* cip_data;
    size_t cip_data_size;

    // Unconnected request timeout, milliseconds.
    bool has_timeout;
    uint32_t timeout_ms;

    // True if this request was a Forward Open Request.
    bool is_forward_open_request;

    // Class ID in the Forward Open Request Connection Path.
    // Used only when is_forward_open_request is true.
    uint32_t connection_path_class_id;

    // Error states for non-fatal CIP errors. Error conditions that could trigger this:
    //  - Forward Open Request received but couldn't add the connection to the list because a
    //      connection already existed with that signature.
    //  - Unknown segment type in request path.
    //  - Forward Open Request contained invalid Connection Timeout Multiplier.
    uint32_t cip_req_invalid_nonfatal;
};

struct CipResponse
{
    // CIP Service code. This does not include the first bit set (0x80).
    uint8_t service;

    CipStatus status;
};

struct CipMessage
{
    // True if this is a CIP request (vs response).
    bool is_cip_request;

    // Used if is_cip_request is true.
    CipRequest request;

    // Used if is_cip_request is false.
    CipResponse response;
};

struct CipCurrentData
{
    CipPacketDirection direction;

    // ENIP layer data.
    EnipSessionData enip_data;

    // CIP layer data.
    CipMessageType cip_message_type;

    // Used if cip_message_type is CipMessageTypeExplicit
    CipMessage cip_msg;

    // True if the packet was not able to be fully parsed.
    bool invalid_fatal;
};

struct EnipSession
{
    // ENIP session handle.
    uint32_t session_handle;

    // True if this session is active.
    bool active;
};

// This represents an Unconnected message request.
//  Sender Context -> Request Type
struct CipUnconnectedMessage
{
    uint64_t sender_context;

    CipRequestType request_type;

    // Unconnected request timeout, milliseconds.
    uint32_t timeout_ms;

    // Timestamp for message request.
    struct timeval timestamp;

    // True if this entry is in use.
    bool slot_active;
};

struct CipUnconnectedMessageList
{
    CipUnconnectedMessage* list;
    uint32_t list_size;
    uint32_t count;

    // True if an active request was forced to be pruned.
    bool request_pruned;
};

// This represents a CIP connection.
// This is used to:
//  a) Get the connection IDs, during a Forward Close.
//  b) Get Class ID from the Connection Path.
struct CipConnection
{
    CipConnectionSignature signature;

    ConnectionIdPair connection_id_pair;

    // Class ID from the Connection Path
    uint32_t class_id;

    // True if the connection is fully established.
    bool established;

    // Connection timeouts, seconds.
    uint32_t ot_connection_timeout_sec;
    uint32_t to_connection_timeout_sec;

    // Timestamp for last time connection was active.
    struct timeval ot_timestamp;
    struct timeval to_timestamp;

    // True if this entry is in use.
    bool slot_active;
};

struct CipConnectionList
{
    CipConnection* list;
    uint32_t list_size;
    uint32_t count;

    // True if an active connection was forced to be pruned.
    bool connection_pruned;
};

struct CipGlobalSessionData
{
    // ENIP Session for this TCP connection.
    EnipSession enip_session;

    // List of CIP connections.
    CipConnectionList connection_list;

    // List of outstanding unconnected messages (SendRRData).
    CipUnconnectedMessageList unconnected_list;

    // Current configuration for use in lower-level parsing functions.
    const CipProtoConf* config;

    snort::Packet* snort_packet;
};

// This is the overall structure used by Snort to store current and global data
//  for a particular stream.
struct CipSessionData
{
    // Current data for this packet.
    CipCurrentData current_data;

    // Overall data for this session.
    CipGlobalSessionData global_data;
};

#endif  // CIP_DEFINITIONS_H

