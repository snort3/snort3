// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// opcua_mock.h author Daniil Kolomiiets <dkolomii@cisco.com>

#ifndef OPCUA_MOCK_H
#define OPCUA_MOCK_H

#include "src/protocols/packet.h"
#include "src/profiler/profiler_defs.h"
#include "detection/detection_engine.h"
#include "src/stream/stream_splitter.h"

#include "../opcua_module.h"
#include "../opcua_session.h"
#include "../opcua_decode.h"

static uint32_t event_sid = 0;
unsigned OpcuaFlowData::inspector_id = 0;

namespace snort
{
FlowData::FlowData(unsigned, Inspector*) : handler(nullptr), id(0) 
{ }
FlowData::~FlowData() = default;

int DetectionEngine::queue_event(unsigned int, unsigned int sid) 
{ 
    event_sid = sid;
    return 0; 
}

const StreamBuffer StreamSplitter::reassemble(snort::Flow*, unsigned int, unsigned int,
    unsigned char const*, unsigned int, unsigned int, unsigned int &) { return {}; }
unsigned StreamSplitter::max(snort::Flow *) { return 0; }

Packet::Packet(bool) { }
Packet::~Packet() = default;

Inspector::Inspector() = default;
Inspector::~Inspector() = default;
// LCOV_EXCL_START
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
// LCOV_EXCL_STOP
}


OpcuaFlowData::OpcuaFlowData() : 
    snort::FlowData(OpcuaFlowData::inspector_id, nullptr) { }

OpcuaFlowData::~OpcuaFlowData()
{
    reset();
    delete [] client_ssn_data.chunk_data;
    delete [] server_ssn_data.chunk_data;
}

void OpcuaFlowData::init() { }

#endif // OPCUA_MOCK_H