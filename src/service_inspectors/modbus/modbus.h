//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// modbus.h author Russ Combs <rucombs@cisco.com>

#ifndef MODBUS_H
#define MODBUS_H

#include "flow/flow.h"
#include "framework/counts.h"

struct ModbusStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct modbus_session_data_t
{
    uint16_t flags;
    uint8_t func;
    uint8_t unit;
};

class ModbusFlowData : public snort::FlowData
{
public:
    ModbusFlowData();
    ~ModbusFlowData() override;

    static void init();

    void reset()
    {
        ssn_data.func = ssn_data.unit = 0;
        ssn_data.flags = 0;
    }

public:
    static unsigned inspector_id;
    modbus_session_data_t ssn_data;
};

int get_message_type(int version, const char* name);
int get_info_type(int version, const char* name);

extern THREAD_LOCAL ModbusStats modbus_stats;

#endif

