//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
//

#ifndef SIP_H
#define SIP_H
// Implementation header with definitions, datatypes and flowdata class for SIP service inspector.

#include "protocols/packet.h"
#include "stream/stream_api.h"
#include "sip_config.h"
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
};

class SipFlowData : public FlowData
{
public:
    SipFlowData() : FlowData(flow_id)
    { memset(&session, 0, sizeof(session)); }

    ~SipFlowData();

    static void init()
    { flow_id = FlowData::get_flow_id(); }

public:
    static unsigned flow_id;
    SIPData session;
};
// API to get SIP flow data from the packet flow
SIPData* get_sip_session_data(Flow* flow);
// API to add SIP method
SIPMethodNode *add_sip_method(char *tok);

#endif
