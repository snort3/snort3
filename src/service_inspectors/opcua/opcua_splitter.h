//--------------------------------------------------------------------------
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

// opcua_splitter.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OPCUA_SPLITTER_H
#define OPCUA_SPLITTER_H

#include "stream/stream_splitter.h"

#include "opcua_session.h"

#define OPCUA_LARGE_MSG_SIZE 4096

enum opcua_splitter_state_t
{
    OPCUA_SPLITTER_STATE_MSG_TYPE_1 = 0,
    OPCUA_SPLITTER_STATE_MSG_TYPE_2,
    OPCUA_SPLITTER_STATE_MSG_TYPE_3,
    OPCUA_SPLITTER_STATE_IS_FINAL,
    OPCUA_SPLITTER_STATE_MSG_SIZE_1,
    OPCUA_SPLITTER_STATE_MSG_SIZE_2,
    OPCUA_SPLITTER_STATE_MSG_SIZE_3,
    OPCUA_SPLITTER_STATE_MSG_SIZE_4,
    OPCUA_SPLITTER_STATE_FLUSH,
    OPCUA_SPLITTER_STATE_ABORT,
};

class OpcuaSplitterPduData
{
public:
    opcua_splitter_state_t state = OPCUA_SPLITTER_STATE_MSG_TYPE_1;
    char msg_type[3] = {'_', '_', '_'};
    char is_final = '_';
    uint32_t msg_size = 0;
    uint32_t unflushed_bytes = 0;

    void reset()
    {
        state = OPCUA_SPLITTER_STATE_MSG_TYPE_1;
        msg_type[0] = '_';
        msg_type[1] = '_';
        msg_type[2] = '_';
        is_final = '_';
        msg_size = 0;
        unflushed_bytes = 0;
    }
};

class OpcuaSplitter : public snort::StreamSplitter
{
public:
    OpcuaSplitter(bool b) : StreamSplitter(b) { }

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    OpcuaSplitterPduData from_client_pdu_data;
    OpcuaSplitterPduData from_server_pdu_data;
};

#endif

