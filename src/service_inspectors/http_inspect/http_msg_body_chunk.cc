//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_body_chunk.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_body_chunk.h"
#include "http_common.h"

using namespace HttpCommon;

void HttpMsgBodyChunk::update_flow()
{
    session_data->body_octets[source_id] = body_octets;

    // Cutter was deleted by splitter when zero-length chunk received or at TCP close
    if (session_data->cutter[source_id] == nullptr)
    {
        session_data->trailer_prep(source_id);
        if (session_data->mime_state[source_id] != nullptr)
        {
            delete session_data->mime_state[source_id];
            session_data->mime_state[source_id] = nullptr;
        }

        if ((source_id == SRC_SERVER) && (session_data->utf_state[source_id] != nullptr))
        {
            delete session_data->utf_state[source_id];
            session_data->utf_state[source_id] = nullptr;
        }
    }
    else
    {
        update_depth();
    }
}

#ifdef REG_TEST
void HttpMsgBodyChunk::print_section(FILE* output)
{
    print_body_section(output, "chunked body");
}
#endif

