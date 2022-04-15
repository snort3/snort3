//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// mms.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef MMS_H
#define MMS_H

// MMS adds a new service inspector designed to process Manufacturing
// Message Specification (MMS) traffic defined within the IEC-61850 family
// of protocols

#include "flow/flow.h"
#include "framework/counts.h"

struct MmsStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

class MmsSessionData
{
public:
    uint32_t offset = 0;
    bool mms_found  = false;

    void session_data_reset()
    {
        offset    = 0;
        mms_found = false;
    }
};

class MmsFlowData : public snort::FlowData
{
public:
    MmsFlowData();
    ~MmsFlowData() override;

    static void init();

    void reset()
    {
        ssn_data.session_data_reset();
    }

    void set_mms_offset(uint32_t offset)
    {
        ssn_data.mms_found = true;
        ssn_data.offset    = offset;
    }

    uint32_t get_mms_offset()
    {
        return ssn_data.offset;
    }

    bool is_mms_found()
    {
        return ssn_data.mms_found;
    }

public:
    static unsigned inspector_id;
    MmsSessionData ssn_data;
};

uint32_t get_message_type(uint32_t version, const char* name);
uint32_t get_info_type(uint32_t version, const char* name);

enum MmsMsgType
{
    MMS_MSG__PDU_NOT_SET        = 0x00,
    MMS_MSG__CONFIRMED_REQUEST  = 0xA0,
    MMS_MSG__CONFIRMED_RESPONSE = 0xA1,
    MMS_MSG__CONFIRMED_ERROR    = 0xA2,
    MMS_MSG__UNCONFIRMED        = 0xA3,
    MMS_MSG__REJECT             = 0xA4,
    MMS_MSG__CANCEL_REQUEST     = 0x85,
    MMS_MSG__CANCEL_RESPONSE    = 0x86,
    MMS_MSG__CANCEL_ERROR       = 0xA7,
    MMS_MSG__INITIATE_REQUEST   = 0xA8,
    MMS_MSG__INITIATE_RESPONSE  = 0xA9,
    MMS_MSG__INITIATE_ERROR     = 0xAA,
    MMS_MSG__CONCLUDE_REQUEST   = 0x8B,
    MMS_MSG__CONCLUDE_RESPONSE  = 0x8C,
    MMS_MSG__CONCLUDE_ERROR     = 0xAD,
};

extern THREAD_LOCAL MmsStats mms_stats;

#endif

