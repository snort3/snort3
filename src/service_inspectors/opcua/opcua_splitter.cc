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

// opcua_splitter.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "opcua_splitter.h"

#include "detection/detection_engine.h"
#include "profiler/profiler.h"

#include "opcua_session.h"
#include "opcua_decode.h"
#include "opcua_module.h"

#include <assert.h>
#include <unordered_set>

using namespace snort;

static const std::unordered_set<uint32_t> opcua_known_msg_types = {
    make_opcua_msg_key('H','E','L'),
    make_opcua_msg_key('A','C','K'),
    make_opcua_msg_key('E','R','R'),
    make_opcua_msg_key('R','H','E'),
    make_opcua_msg_key('O','P','N'),
    make_opcua_msg_key('M','S','G'),
    make_opcua_msg_key('C','L','O')
};

static StreamSplitter::Status abort_search(OpcuaSplitterPduData*);

static bool verify_known_message(OpcuaSplitterPduData* cur_pdu_data)
{
    if ( cur_pdu_data->msg_size > OPCUA_LARGE_MSG_SIZE )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_MSG_SIZE);
    }

    uint32_t msg_key = make_opcua_msg_key(cur_pdu_data->msg_type[0], cur_pdu_data->msg_type[1], 
        cur_pdu_data->msg_type[2]);
    if ( opcua_known_msg_types.count(msg_key) )
    {
        return true;
    }
    
    DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_MSG_TYPE);
    return false;
}

static StreamSplitter::Status abort_search(OpcuaSplitterPduData* cur_pdu_data)
{
    opcua_stats.splitter_aborts++;
    cur_pdu_data->reset();
    return StreamSplitter::ABORT;
}

StreamSplitter::Status OpcuaSplitter::scan(Packet* p, const uint8_t* data, uint32_t len,
    uint32_t /*flags*/, uint32_t* fp)
{
    OpcuaSplitterPduData* cur_pdu_data;
    if ( p->is_from_client() )
    {
        cur_pdu_data = &from_client_pdu_data;
    }
    else if ( p->is_from_server() )
    {
        cur_pdu_data = &from_server_pdu_data;
    }
    else
    {
        opcua_stats.splitter_aborts++;
        return StreamSplitter::ABORT;
    }
    uint32_t bytes_processed = 0;
    while (bytes_processed < len)
    {
        switch (cur_pdu_data->state)
        {
        case OPCUA_SPLITTER_STATE_MSG_TYPE_1:
        {
            cur_pdu_data->msg_type[0] = data[bytes_processed];
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_MSG_TYPE_2;
            break;
        }
        case OPCUA_SPLITTER_STATE_MSG_TYPE_2:
        {
            cur_pdu_data->msg_type[1] = data[bytes_processed];
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_MSG_TYPE_3;
            break;
        }
        case OPCUA_SPLITTER_STATE_MSG_TYPE_3:
        {
            cur_pdu_data->msg_type[2] = data[bytes_processed];
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_IS_FINAL;
            break;
        }
        case OPCUA_SPLITTER_STATE_IS_FINAL:
        {
            cur_pdu_data->is_final = data[bytes_processed];
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_MSG_SIZE_1;
            break;
        }

        case OPCUA_SPLITTER_STATE_MSG_SIZE_1:
        {
            cur_pdu_data->msg_size |= data[bytes_processed];
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_MSG_SIZE_2;
            break;
        }
        case OPCUA_SPLITTER_STATE_MSG_SIZE_2:
        {
            cur_pdu_data->msg_size |= data[bytes_processed] << 8;
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_MSG_SIZE_3;
            break;
        }
        case OPCUA_SPLITTER_STATE_MSG_SIZE_3:
        {
            cur_pdu_data->msg_size |= data[bytes_processed] << 16;
            cur_pdu_data->state = OPCUA_SPLITTER_STATE_MSG_SIZE_4;
            break;
        }
        case OPCUA_SPLITTER_STATE_MSG_SIZE_4:
        {
            cur_pdu_data->msg_size |= data[bytes_processed] << 24;

            if ( !verify_known_message(cur_pdu_data) )
            {
                return abort_search(cur_pdu_data);
            }

            if ( cur_pdu_data->msg_size <= cur_pdu_data->unflushed_bytes )
            {
                return abort_search(cur_pdu_data);
            }

            cur_pdu_data->state = OPCUA_SPLITTER_STATE_FLUSH;
            break;
        }

        case OPCUA_SPLITTER_STATE_FLUSH:
        {
            if ( cur_pdu_data->unflushed_bytes != 0 || cur_pdu_data->msg_size > len )
            {
                opcua_stats.split_messages++;
                DetectionEngine::queue_event(GID_OPCUA, OPCUA_SPLIT_MSG);
            }

            if ( cur_pdu_data->msg_size < len )
            {
                opcua_stats.pipelined_messages++;
                DetectionEngine::queue_event(GID_OPCUA, OPCUA_PIPELINED_MSG);
            }

            *fp = cur_pdu_data->msg_size - cur_pdu_data->unflushed_bytes;
            cur_pdu_data->reset();
            return StreamSplitter::FLUSH;
        }

        default:
        {
            return abort_search(cur_pdu_data);
        }
        }

        bytes_processed++;
    }

    cur_pdu_data->unflushed_bytes += bytes_processed;
    return StreamSplitter::SEARCH;
}

