//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SIP_H
#define SIP_H

// Implementation header with definitions, datatypes and flowdata class for SIP service inspector.

#include "flow/flow.h"
#include "framework/data_bus.h"

#include "sip_dialog.h"
#include "sip_parser.h"
#include "sip_roptions.h"

#define SIP_FLG_MISSED_PACKETS        (0x10000)

struct SIPData
{
    uint32_t state_flags;
    SIP_DialogList dialogs;
    SIP_Roptions ropts;
    SIP_PROTO_CONF *sip_config;
    bool sip_aborted;

    static unsigned pub_id;
};

class SipFlowData : public snort::FlowData
{
public:
    SipFlowData();
    ~SipFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    SIPData session;
};

SIPData* get_sip_session_data(const snort::Flow*);
SIPMethodNode* add_sip_method(const char*);

// Indices in the buffer array exposed by InspectApi
// Must remain synchronized with sip_bufs
enum SipBufId
{
    SIP_HEADER_ID = 1, SIP_BODY_ID
};

bool get_buf_sip(unsigned id, snort::Packet* p, snort::InspectionBuffer& b);

#endif
