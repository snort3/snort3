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

// s7comm.h author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

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
    bool is_read_write_var; //the message is read var or write var


    void session_data_reset()
    {
        //resetting 1 byte fields 
        s7comm_proto_id = s7comm_message_type = s7comm_error_class = s7comm_error_code = 0;
        s7comm_function_code = s7comm_item_count = 0;

        //resetting 2 byte fields
        s7comm_reserved = s7comm_pdu_reference = s7comm_parameter_length = s7comm_data_length = 0;

        is_read_write_var=false;
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
