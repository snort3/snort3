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

// s7comm_decode.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

/*
 * This is the encapsulation of S7comm/S7comm-plus protocol:
 *   Ethernet | IP | TCP (server port 102) | TPKT | COTP | S7comm or S7comm-plus
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s7comm_decode.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "protocols/packet.h"

#include "s7comm.h"
#include "s7comm_module.h"

#include <iostream> // For debug output
#include <iomanip> // For std::setw and std::setfill
#include <cmath>

#pragma pack(1)
/* TPKT header */
struct TpktHeader
{
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
};

/* COTP header */
struct CotpHeader
{
    uint8_t length;
    uint8_t pdu_type;
    uint8_t tpdu_num;
};


#pragma pack()

using namespace snort;

static bool DecodeJobReadVar(S7commSessionData* session, const uint8_t* data, int& offset)
{
    session->s7comm_item_count = *(data + offset + 1);
    offset += 2;

    for (int i = 0; i < session->s7comm_item_count; ++i) {
        S7commSessionData::RequestItem request_item;
        request_item.var_type = *(data + offset);
        request_item.var_length = *(data + offset + 1);
        request_item.syntax_id = *(data + offset + 2);
        request_item.transport_size = *(data + offset + 3);
        request_item.length = ntohs(*(uint16_t*)(data + offset + 4));
        request_item.db_number = ntohs(*(uint16_t*)(data + offset + 6));
        request_item.area = *(data + offset + 8);
        request_item.address = ntohl(*(uint32_t*)(data + offset + 9)) >> 8; // 3-byte address, adjusted for 4-byte field
        session->request_items.push_back(request_item);
        offset += 12; // Move to the next request item
    }

    return true;
}

static bool DecodeJobWriteVar(S7commSessionData* session, const uint8_t* data, int& offset)
{
    session->s7comm_item_count = *(data + offset + 1);
    offset += 2;

    std::cout << "Item count: " << static_cast<int>(session->s7comm_item_count) << std::endl;

    for (int i = 0; i < session->s7comm_item_count; ++i) {
        S7commSessionData::RequestItem request_item;
        request_item.var_type = *(data + offset);
        request_item.var_length = *(data + offset + 1);
        request_item.syntax_id = *(data + offset + 2);
        request_item.transport_size = *(data + offset + 3);
        request_item.length = ntohs(*(uint16_t*)(data + offset + 4));
        request_item.db_number = ntohs(*(uint16_t*)(data + offset + 6));
        request_item.area = *(data + offset + 8);
        request_item.address = ntohl(*(uint32_t*)(data + offset + 9)) >> 8; // 3-byte address, adjusted for 4-byte field
        session->request_items.push_back(request_item);
        offset += 12; // Move to the next request item

        std::cout << "Request item " << i << " added with DB number: " << request_item.db_number << std::endl;
    }

    for (int i = 0; i < session->s7comm_item_count; ++i) {
        std::cout << "Processing data item " << i << std::endl;

        S7commSessionData::DataItem data_item;
        data_item.error_code = *(data + offset);
        data_item.variable_type = *(data + offset + 1);
        data_item.length = ntohs(*(uint16_t*)(data + offset + 2));
        offset += 4; // Move to data

        std::cout << "Data item " << i << " with length: " << data_item.length << std::endl;

        if (data_item.length > 0) {
            data_item.data.assign(data + offset, data + offset + data_item.length);
            session->data_items.push_back(data_item);

            std::cout << "Data item " << i << " added with error code: " << static_cast<int>(data_item.error_code) << std::endl;
            std::cout << "Data item " << i << " values: ";
            for (const auto& byte : data_item.data) {
                std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte) << " ";
            }
            std::cout << std::dec << std::endl; // Switch back to decimal output

            offset += data_item.length; // Move to the next data item

            // Print the length of data_items vector
            std::cout << "Current length of data_items vector: " << session->data_items.size() << std::endl;
        }

        // Handle padding if length is odd and there's more data
        if (data_item.length % 2 != 0 && i < session->s7comm_item_count - 1) {
            offset += 1;
            std::cout << "Padding byte skipped" << std::endl;
        }
    }

    return true;
}



// Custom function to calculate length from two bytes
uint16_t calculate_custom_length(uint8_t byte1, uint8_t byte2) {
    uint8_t result= pow((byte1 & 0x0F) * 2, 3) 
    + pow(((byte1 & 0xF0) >> 4) * 2, 4) 
    + pow(((byte2 & 0xF0) >> 4) * 2, 1);
    uint8_t first_byte_num= (byte2 & 0x0F) ? 1: 0;
    return result+ first_byte_num;
}

static bool DecodeAckDataReadVar(S7commSessionData* session, const uint8_t* data, int& offset)
{
    session->s7comm_item_count = *(data + offset + 1);
    offset += 2;

    for (int i = 0; i < session->s7comm_item_count; ++i) {
        std::cout << "Processing data item " << i << std::endl;

        S7commSessionData::DataItem data_item;
        data_item.error_code = *(data + offset);
        data_item.variable_type = *(data + offset + 1);
        
        // Custom length calculation
        uint8_t byte1 = *(data + offset + 2);
        uint8_t byte2 = *(data + offset + 3);
        data_item.length = calculate_custom_length(byte1, byte2);

        std::cout << "Raw length bytes: " << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte1) << " " << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte2) << std::dec << std::endl;
        std::cout << "Interpreted length: " << data_item.length << std::endl;

        offset += 4; // Move to data

        std::cout << "Data item " << i << " with length: " << data_item.length << std::endl;

        if (data_item.length > 0) {
            data_item.data.assign(data + offset, data + offset + data_item.length);
            session->data_items.push_back(data_item);

            std::cout << "Data item " << i << " added with error code: " << static_cast<int>(data_item.error_code) << std::endl;
            std::cout << "Data item " << i << " values: ";
            for (const auto& byte : data_item.data) {
                std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte) << " ";
            }
            std::cout << std::dec << std::endl; // Switch back to decimal output

            offset += data_item.length; // Move to the next data item

            // Print the length of data_items vector
            std::cout << "Current length of data_items vector: " << session->data_items.size() << std::endl;
        }

        // Handle padding if length is odd and there's more data
        if (data_item.length % 2 != 0 && i < session->s7comm_item_count - 1) {
            offset += 1;
            std::cout << "Padding byte skipped" << std::endl;
        }
    }

    return true;
}

static bool DecodeAckDataWriteVar(S7commSessionData* session, const uint8_t* data, int& offset)
{
    session->s7comm_item_count = *(data + offset + 1);
    offset += 2;

    for (int i = 0; i < session->s7comm_item_count; ++i) {
        S7commSessionData::DataItem data_item;
        data_item.error_code = *(data + offset);
        session->data_items.push_back(data_item);
        offset += 1; // Move to the next data item
    }

    return true;
}

static bool S7commProtocolDecode(S7commSessionData* session, Packet* p)
{
    const S7commHeader* s7comm_header;
    int offset;

    if (p->dsize < (sizeof(TpktHeader) + sizeof(CotpHeader) + sizeof(S7commHeader) - 2)) // -2 for optional fields
        return false;

    offset = sizeof(TpktHeader) + sizeof(CotpHeader);

    s7comm_header = (const S7commHeader*)(p->data + offset);
    session->s7comm_proto_id = s7comm_header->proto_id;
    session->s7comm_message_type = s7comm_header->message_type;
    session->s7comm_reserved = ntohs(s7comm_header->reserved);
    session->s7comm_pdu_reference = ntohs(s7comm_header->pdu_reference);
    session->s7comm_parameter_length = ntohs(s7comm_header->parameter_length);
    session->s7comm_data_length = ntohs(s7comm_header->data_length);

    offset += sizeof(S7commHeader) - 2; // -2 for optional fields

    if (s7comm_header->message_type == ACK_DATA && p->dsize >= (offset + 2)) {
        session->s7comm_error_class = s7comm_header->error_class;
        session->s7comm_error_code = s7comm_header->error_code;
        offset += 2;
    }


    const S7commParameterHeader* s7comm_param_header;
    s7comm_param_header = (const S7commParameterHeader*)(p->data + offset);
    session->s7comm_function_code = s7comm_param_header->function_code;

    //reset previous request and data items
    session->request_items.clear();
    session->data_items.clear();

    switch (s7comm_header->message_type) {
        case JOB_REQUEST:
            if (session->s7comm_function_code == 0x04) {
                return DecodeJobReadVar(session, p->data, offset);
            } else if (session->s7comm_function_code == 0x05) {
                return DecodeJobWriteVar(session, p->data, offset);
            }
            break;
        case ACK_DATA:
            if (session->s7comm_function_code == 0x04) {
                return DecodeAckDataReadVar(session, p->data, offset);
            } else if (session->s7comm_function_code == 0x05) {
                return DecodeAckDataWriteVar(session, p->data, offset);
            }
            break;
        default:
            return false;
    }

    return false;
}


bool S7commDecode(Packet* p, S7commFlowData* mfd)
{
    const TpktHeader* tpkt_header;
    const CotpHeader* cotp_header;
    const S7commHeader* s7comm_header;
    uint16_t tpkt_length;

    if (p->dsize < TPKT_MIN_HDR_LEN)
        return false;

    tpkt_header = (const TpktHeader*)p->data;
    cotp_header = (const CotpHeader*)(p->data + sizeof(TpktHeader));
    tpkt_length = ntohs(tpkt_header->length);

    /* It might be a TPKT/COTP packet for other purpose, e.g. connect */
    if (cotp_header->length != COTP_HDR_LEN_FOR_S7COMM)
        return true;
    /* It might be COTP fragment data */
    if (tpkt_length == TPKT_MIN_HDR_LEN)
    {
        mfd->reset();
        return true;
    }

    s7comm_header = (const S7commHeader*)(p->data +
        sizeof(TpktHeader) + sizeof(CotpHeader));

    if (s7comm_header->proto_id == S7COMM_PROTOCOL_ID)
    {
        return (S7commProtocolDecode(&mfd->ssn_data, p));
    }
    else
    {
        DetectionEngine::queue_event(GID_S7COMM, S7COMM_BAD_PROTO_ID);
        return false;
    }
}
