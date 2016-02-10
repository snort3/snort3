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
// nhttp_msg_body_cl.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "detection/detection_util.h"
#include "file_api/file_api.h"
#include "file_api/file_flows.h"
#include "mime/file_mime_process.h"

#include "nhttp_enum.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_body_cl.h"

using namespace NHttpEnums;

void NHttpMsgBodyCl::update_flow()
{
    if (session_data->cutter[source_id] != nullptr)
    {
        // More body coming
        session_data->body_octets[source_id] = body_octets;
        update_depth();
        session_data->infractions[source_id] = infractions;
        session_data->events[source_id] = events;
    }
    else
    {
        // End of message
        session_data->half_reset(source_id);
    }
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;
}

#ifdef REG_TEST
void NHttpMsgBodyCl::print_section(FILE* output)
{
    NHttpMsgSection::print_section_title(output, "Content-Length body");
    fprintf(output, "Content-Length %" PRIi64 ", octets seen %" PRIi64 "\n", data_length,
        body_octets);
    print_body_section(output);
}
#endif

