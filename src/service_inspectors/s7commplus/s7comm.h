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

struct S7commplusStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct S7commplusSessionData
{
    uint8_t s7commplus_proto_id = 0;
    uint8_t s7commplus_proto_version = 0;
    uint16_t s7commplus_data_len = 0;
    uint8_t s7commplus_opcode = 0;
    uint16_t s7commplus_reserved_1 = 0;
    uint16_t s7commplus_function = 0;
    uint16_t s7commplus_reserved_2 = 0;

    void session_data_reset()
    {
        s7commplus_proto_id = s7commplus_proto_version = s7commplus_opcode = 0;
        s7commplus_data_len = s7commplus_function = 0;
        s7commplus_reserved_1 = s7commplus_reserved_2 = 0;
    }
};

class S7commplusFlowData : public snort::FlowData
{
public:
    S7commplusFlowData();
    ~S7commplusFlowData() override;

    static void init();

    void reset()
    {
        ssn_data.session_data_reset();
    }

public:
    static unsigned inspector_id;
    S7commplusSessionData ssn_data;
};

int get_message_type(int version, const char* name);
int get_info_type(int version, const char* name);

extern THREAD_LOCAL S7commplusStats s7commplus_stats;

#endif

