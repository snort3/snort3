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
// nhttp_msg_body.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "main/snort.h"
#include "detection/detection_util.h"

#include "nhttp_enum.h"
#include "nhttp_msg_body.h"

using namespace NHttpEnums;

NHttpMsgBody::NHttpMsgBody(const uint8_t* buffer, const uint16_t buf_size,
    NHttpFlowData* session_data_,
    SourceId source_id_, bool buf_owner) :
    NHttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner),
    data_length(session_data->data_length[source_id]), body_octets(
    session_data->body_octets[source_id])
{
    transaction->set_body(this);
}

void NHttpMsgBody::analyze()
{
    body_octets += msg_text.length;
    data.start = msg_text.start;
    data.length = msg_text.length;

    if (tcp_close && (body_octets < data_length))
        infractions += INF_TRUNCATED;
    // FIXIT-L try to find a more logical location for this
    set_file_data((uint8_t*)data.start, (unsigned)data.length);
}

void NHttpMsgBody::gen_events()
{
}

void NHttpMsgBody::print_section(FILE* output)
{
    NHttpMsgSection::print_message_title(output, "body");
    fprintf(output, "Expected data length %" PRIi64 ", octets seen %" PRIi64 "\n", data_length,
        body_octets);
    data.print(output, "Data");
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgBody::update_flow()
{
    if (tcp_close)
    {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->section_type[source_id] = SEC__NOTCOMPUTE;
        session_data->half_reset(source_id);
    }
    else if (body_octets < data_length)
    {
        // More body coming
        session_data->body_octets[source_id] = body_octets;
        session_data->infractions[source_id] = infractions;
        session_data->events[source_id] = events;
    }
    else
    {
        // End of message
        session_data->type_expected[source_id] = (source_id == SRC_CLIENT) ? SEC_REQUEST :
            SEC_STATUS;
        session_data->section_type[source_id] = SEC__NOTCOMPUTE;
        session_data->half_reset(source_id);
    }
}

