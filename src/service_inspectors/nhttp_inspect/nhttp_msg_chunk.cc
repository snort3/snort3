//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_msg_chunk.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "main/snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_chunk.h"

using namespace NHttpEnums;

NHttpMsgChunk::NHttpMsgChunk(const uint8_t* buffer, const uint16_t buf_size,
    NHttpFlowData* session_data_, SourceId source_id_, bool buf_owner) :
    NHttpMsgBody(buffer, buf_size, session_data_, source_id_, buf_owner)
{
    transaction->set_body(this);
}

void NHttpMsgChunk::gen_events() { }

void NHttpMsgChunk::print_section(FILE* output)
{
    NHttpMsgSection::print_message_title(output, "chunk");
    fprintf(output, "Cumulative octets %" PRIi64 "\n", body_octets);
    data.print(output, "Data");
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgChunk::update_flow()
{
    if (tcp_close)
    {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->section_type[source_id] = SEC__NOTCOMPUTE;
        session_data->half_reset(source_id);
    }
    else
    {
        // Zero-length chunk is not visible here. StreamSplitter::reassemble() updates
        // type_expected to SEC_TRAILER.
        session_data->body_octets[source_id] = body_octets;
        session_data->infractions[source_id] = infractions;
        session_data->events[source_id] = events;
    }
}

