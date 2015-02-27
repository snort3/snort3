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
// nhttp_msg_status.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "main/snort.h"
#include "detection/detection_util.h"

#include "nhttp_enum.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"

using namespace NHttpEnums;

NHttpMsgStatus::NHttpMsgStatus(const uint8_t* buffer, const uint16_t buf_size,
    NHttpFlowData* session_data_,
    SourceId source_id_, bool buf_owner) :
    NHttpMsgStart(buffer, buf_size, session_data_, source_id_, buf_owner)
{
    transaction->set_status(this);
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgStatus::analyze()
{
    NHttpMsgStart::analyze();
    derive_status_code_num();
}

void NHttpMsgStatus::parse_start_line()
{
    // FIXIT-M need to be able to parse a truncated status line and extract version and status
    // code.

    // Eventually we may need to cater to certain format errors, but for now exact match or treat
    // as error.
    // HTTP/X.Y<SP>###<SP><text>
    if ((start_line.length < 13) || (start_line.start[8] != ' ') || (start_line.start[12] != ' '))
    {
        infractions += INF_BADSTATLINE;
        return;
    }
    version.start = start_line.start;
    version.length = 8;
    status_code.start = start_line.start + 9;
    status_code.length = 3;
    reason_phrase.start = start_line.start + 13;
    reason_phrase.length = start_line.length - 13;
    for (int32_t k = 0; k < reason_phrase.length; k++)
    {
        if ((reason_phrase.start[k] <= 31) || (reason_phrase.start[k] >= 127))
        {
            // Illegal character in reason phrase
            infractions += INF_BADPHRASE;
            break;
        }
    }
    assert (start_line.length == version.length + status_code.length + reason_phrase.length + 2);
}

void NHttpMsgStatus::derive_status_code_num()
{
    if (status_code.length <= 0)
    {
        status_code_num = STAT_NOSOURCE;
        return;
    }
    if (status_code.length != 3)
    {
        status_code_num = STAT_PROBLEMATIC;
        return;
    }

    if ((status_code.start[0] < '0') || (status_code.start[0] > '9') || (status_code.start[1] <
        '0') || (status_code.start[1] > '9') ||
        (status_code.start[2] < '0') || (status_code.start[2] > '9'))
    {
        infractions += INF_BADSTATCODE;
        status_code_num = STAT_PROBLEMATIC;
        return;
    }
    status_code_num = (status_code.start[0] - '0') * 100 + (status_code.start[1] - '0') * 10 +
        (status_code.start[2] - '0');
    if ((status_code_num < 100) || (status_code_num > 599))
    {
        infractions += INF_BADSTATCODE;
    }
}

void NHttpMsgStatus::gen_events() { }

void NHttpMsgStatus::print_section(FILE* output)
{
    NHttpMsgSection::print_message_title(output, "status line");
    fprintf(output, "Version Id: %d\n", version_id);
    fprintf(output, "Status Code Num: %d\n", status_code_num);
    reason_phrase.print(output, "Reason Phrase");
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgStatus::update_flow()
{
    const uint64_t disaster_mask = INF_BADSTATLINE;

    // The following logic to determine body type is by no means the last word on this topic.
    if (tcp_close)
    {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->half_reset(source_id);
    }
    else if (infractions && disaster_mask)
    {
        session_data->type_expected[source_id] = SEC_ABORT;
        session_data->half_reset(source_id);
    }
    else
    {
        session_data->type_expected[source_id] = SEC_HEADER;
        session_data->version_id[source_id] = version_id;
        session_data->status_code_num = status_code_num;
    }
    session_data->section_type[source_id] = SEC__NOTCOMPUTE;
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgStatus::legacy_clients()
{
    ClearHttpBuffers();
    legacy_request();
    legacy_status();
}

