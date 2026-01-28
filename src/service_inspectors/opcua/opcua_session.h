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

// opcua_session.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OPCUA_SESSION_H
#define OPCUA_SESSION_H

#include "flow/flow.h"
#include "opcua_msg_service.h"
#include "opcua_decode.h"

enum OpcuaPacketDataDirectionType
{
    OPCUA_PACKET_DATA_DIRECTION_SERVER,
    OPCUA_PACKET_DATA_DIRECTION_CLIENT,
};

class OpcuaSessionData
{
public:
    OpcuaMsgType msg_type            = OPCUA_MSG_UNDEFINED;
    uint8_t node_namespace_index     = 0;
    OpcuaMsgServiceType node_id      = OPCUA_MSG_SERVICE_UNDEFINED;

    OpcuaIsFinalType is_final        = OPCUA_IS_FINAL_UNDEFINED;
    bool is_chunked                  = false;
    bool is_complete_msg             = false;

    uint8_t* chunk_data              = nullptr;
    uint32_t chunk_data_len          = 0;

    void reset_chunk_data()
    {
        delete [] chunk_data;
        chunk_data = new uint8_t[OPCUA_CHUNK_DATA_BUF_SIZE];
        chunk_data_len = 0;
    }

    void reset()
    {
        msg_type = OPCUA_MSG_UNDEFINED;
        node_namespace_index = 0;
        node_id = OPCUA_MSG_SERVICE_UNDEFINED;

        is_final = OPCUA_IS_FINAL_UNDEFINED;
        is_chunked = false;
        is_complete_msg = false;

        reset_chunk_data();
    }
};

class OpcuaFlowData : public snort::FlowData
{
public:
    OpcuaFlowData();
    ~OpcuaFlowData() override;

    static void init();

    void reset()
    {
        reset_client_ssn_data();
        reset_server_ssn_data();
    }

    void reset_client_ssn_data()
    {
        client_ssn_data.reset();
    }

    void reset_server_ssn_data()
    {
        server_ssn_data.reset();
    }

    OpcuaSessionData* get_ssn_data_by_direction(OpcuaPacketDataDirectionType direction)
    {
        if ( direction == OPCUA_PACKET_DATA_DIRECTION_SERVER )
        {
            return &server_ssn_data;
        }
        else if ( direction == OPCUA_PACKET_DATA_DIRECTION_CLIENT )
        {
            return &client_ssn_data;
        }
        return nullptr;
    }

public:
    static unsigned inspector_id;
    OpcuaSessionData client_ssn_data;
    OpcuaSessionData server_ssn_data;
};

#endif

