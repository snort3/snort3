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

// s7comm.cc author Yarin Peretz <yarinp123@gmail.com>
// based on work by Jeffrey Gu <jgu@cisco.com>
// The s7comm service inspector is capable of decoding S7comm packets.
// It can detect and decode S7comm packets, and extract information from them.
// This service inspector has been created for item structures with any-type Addressing,
// and it can detect all header fields, fields for ROSCTR 1 and 3, and Function Code 4 and 5.


#ifndef S7COMM_H
#define S7COMM_H

#include "flow/flow.h"
#include "framework/counts.h"

struct S7commStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct S7commSessionData
{
    // Existing fields
    uint8_t s7comm_proto_id = 0;
    uint8_t s7comm_message_type = 0;
    uint16_t s7comm_reserved = 0;
    uint16_t s7comm_pdu_reference = 0;
    uint16_t s7comm_parameter_length = 0;
    uint16_t s7comm_data_length = 0;
    uint8_t s7comm_error_class = 0;
    uint8_t s7comm_error_code = 0;
    uint8_t s7comm_function_code = 0;
    uint8_t s7comm_item_count = -1;
    bool has_item_count = false; // the message is read var or write var
    uint8_t s7comm_function_group = 0; // for userdata messages

    // New fields for DB-type addressing mode (Request Items)
        struct RequestItem {
            uint8_t var_type;
            uint8_t var_length;
            uint8_t syntax_id;
            uint8_t transport_size;
            uint16_t length;
            uint16_t db_number;
            uint8_t area;
            uint32_t address; // 3 bytes, but stored in a 4-byte field

        // Default constructor
        RequestItem()
            : var_type(0), var_length(0), syntax_id(0), transport_size(0),
            length(0), db_number(0), area(0), address(0) {}
        };

    // New fields for DB-type addressing mode (Data Items)
    struct DataItem {
        uint8_t error_code;
        uint8_t variable_type;
        uint16_t length;
        std::vector<uint8_t> data;
        
        // Default constructor
        DataItem()
            : error_code(0), variable_type(0), length(0), data() {}
    };

    std::vector<RequestItem> request_items;
    std::vector<DataItem> data_items;

    void session_data_reset()
    {
        // Reset existing fields
        s7comm_proto_id = s7comm_message_type = s7comm_error_class = s7comm_error_code = 0;
        s7comm_function_code = s7comm_function_group = 0;
        s7comm_item_count = -1;
        s7comm_reserved = s7comm_pdu_reference = s7comm_parameter_length = s7comm_data_length = 0;
        has_item_count = false;

        // Reset new fields
        request_items.clear();
        data_items.clear();
    }
};


class S7commFlowData : public snort::FlowData
{
public:
    S7commFlowData();
    ~S7commFlowData() override;

    static void init();

    void reset()
    {
        ssn_data.session_data_reset();
    }

public:
    static unsigned inspector_id;
    S7commSessionData ssn_data;
};

int get_message_type(int version, const char* name);
int get_info_type(int version, const char* name);

extern THREAD_LOCAL S7commStats s7comm_stats;

#endif
