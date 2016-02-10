//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_msg_body_chunk.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "mime/file_mime_process.h"

#include "nhttp_enum.h"
#include "nhttp_msg_body_chunk.h"

using namespace NHttpEnums;

void NHttpMsgBodyChunk::update_flow()
{
    // Cutter deleted when zero-length chunk received
    if (session_data->cutter[source_id] == nullptr)
    {
        session_data->body_octets[source_id] = body_octets;
        session_data->trailer_prep(source_id);
        if ((source_id == SRC_CLIENT) && (session_data->mime_state != nullptr))
        {
            delete session_data->mime_state;
            session_data->mime_state = nullptr;
        }
    }
    else
    {
        session_data->body_octets[source_id] = body_octets;
        update_depth();
        session_data->infractions[source_id] = infractions;
        session_data->events[source_id] = events;
    }
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;
}

#ifdef REG_TEST
void NHttpMsgBodyChunk::print_section(FILE* output)
{
    NHttpMsgSection::print_section_title(output, "chunked body");
    fprintf(output, "Cumulative octets %" PRIi64 "\n", body_octets);
    print_body_section(output);
}
#endif

