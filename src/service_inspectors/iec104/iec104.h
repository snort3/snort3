//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// iec104.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef IEC104_H
#define IEC104_H

#include "flow/flow.h"
#include "framework/counts.h"

#define IEC104_MIN_APCI_LEN 4        // Enough for the four control octets that are in every message

struct Iec104Stats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct Iec104SessionData
{
    uint8_t iec104_apci_type = -1;
    uint8_t iec104_asdu_func = 0;

    void session_data_reset()
    {
        iec104_apci_type = -1;
        iec104_asdu_func = 0;
    }
};

class Iec104FlowData: public snort::FlowData
{
public:
    Iec104FlowData();
    ~Iec104FlowData() override;

    static void init();

    void reset()
    { ssn_data.session_data_reset(); }

public:
    static unsigned inspector_id;
    Iec104SessionData ssn_data;
};

uint32_t get_message_type(uint32_t version, const char* name);
uint32_t get_info_type(uint32_t version, const char* name);

extern THREAD_LOCAL Iec104Stats iec104_stats;

#endif

