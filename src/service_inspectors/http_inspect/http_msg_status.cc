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
// http_msg_status.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "detection/detection_util.h"

#include "http_enum.h"
#include "http_api.h"
#include "http_msg_status.h"
#include "http_msg_header.h"

using namespace HttpEnums;

HttpMsgStatus::HttpMsgStatus(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgStart(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_status(this);
}

void HttpMsgStatus::parse_start_line()
{
    // Splitter guarantees line begins with "HTTP/"

    if ((start_line.length < 12) || !is_sp_tab[start_line.start[8]])
    {
        infractions += INF_BAD_STAT_LINE;
        events.create_event(EVENT_MISFORMATTED_HTTP);
        return;
    }

    int32_t first_end; // last whitespace in first clump of whitespace
    for (first_end = 9; (first_end < start_line.length) && is_sp_tab[start_line.start[first_end]];
        first_end++);
    first_end--;

    if (start_line.length < first_end + 4)
    {
        infractions += INF_BAD_STAT_LINE;
        events.create_event(EVENT_MISFORMATTED_HTTP);
        return;
    }

    if ((start_line.length > first_end + 4) && !is_sp_tab[start_line.start[first_end + 4]])
    {
        // FIXIT-M This should not be fatal. HI supports something like "HTTP/1.1 200\\OK\r\n" as
        // seen in a status line test.
        infractions += INF_BAD_STAT_LINE;
        events.create_event(EVENT_MISFORMATTED_HTTP);
        return;
    }

    HttpModule::increment_peg_counts(PEG_RESPONSE);

    version.start = start_line.start;
    version.length = 8;
    derive_version_id();

    status_code.start = start_line.start + first_end + 1;
    status_code.length = 3;
    derive_status_code_num();

    if (start_line.length > first_end + 5)
    {
        reason_phrase.start = start_line.start + first_end + 5;
        reason_phrase.length = start_line.length - first_end - 5;
    }
}

void HttpMsgStatus::derive_status_code_num()
{
    if ((status_code.start[0] < '0') || (status_code.start[0] > '9') || (status_code.start[1] <
        '0') || (status_code.start[1] > '9') ||
        (status_code.start[2] < '0') || (status_code.start[2] > '9'))
    {
        infractions += INF_BAD_STAT_CODE;
        events.create_event(EVENT_INVALID_STATCODE);
        status_code_num = STAT_PROBLEMATIC;
        return;
    }
    status_code_num = (status_code.start[0] - '0') * 100 + (status_code.start[1] - '0') * 10 +
        (status_code.start[2] - '0');
    if ((status_code_num < 100) || (status_code_num > 599))
    {
        infractions += INF_BAD_STAT_CODE;
        events.create_event(EVENT_INVALID_STATCODE);
    }
}

void HttpMsgStatus::gen_events()
{
    if (infractions & INF_BAD_STAT_LINE)
        return;

    if (status_code.start > start_line.start + 9)
    {
        infractions += INF_STATUS_WS;
        events.create_event(EVENT_IMPROPER_WS);
    }

    for (int k = 8; k < status_code.start - start_line.start; k++)
    {
        if (start_line.start[k] == '\t')
        {
            infractions += INF_STATUS_TAB;
            events.create_event(EVENT_APACHE_WS);
        }
    }

    if (status_code.start - start_line.start + 3 < start_line.length)
    {
        if (status_code.start[3] == '\t')
        {
            infractions += INF_STATUS_TAB;
            events.create_event(EVENT_APACHE_WS);
        }
    }

    for (int k=0; k < reason_phrase.length; k++)
    {
        if ((reason_phrase.start[k] <= 31) || (reason_phrase.start[k] >= 127))
        {
            // Illegal character in reason phrase
            infractions += INF_BAD_PHRASE;
            events.create_event(EVENT_CTRL_IN_REASON);
            break;
        }
    }
}

void HttpMsgStatus::update_flow()
{
    if (infractions & INF_BAD_STAT_LINE)
    {
        session_data->half_reset(source_id);
        session_data->type_expected[source_id] = SEC_ABORT;
    }
    else
    {
        session_data->type_expected[source_id] = SEC_HEADER;
        session_data->version_id[source_id] = version_id;
        session_data->status_code_num = status_code_num;
        session_data->infractions[source_id].reset();
        session_data->events[source_id].reset();
        // 100 response means the next response message will be added to this transaction instead
        // of being part of another transaction. As implemented it is possible for multiple 100
        // responses to all be included in the same transaction. It's not obvious whether that is
        // the best way to handle what should be a highly abnormal situation.
        if (status_code_num == 100)
            transaction->second_response_coming();
    }
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;
}

#ifdef REG_TEST
void HttpMsgStatus::print_section(FILE* output)
{
    HttpMsgSection::print_section_title(output, "status line");
    fprintf(output, "Version Id: %d\n", version_id);
    fprintf(output, "Status Code Num: %d\n", status_code_num);
    reason_phrase.print(output, "Reason Phrase");
    get_classic_buffer(HTTP_BUFFER_STAT_CODE, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_STAT_CODE-1]);
    get_classic_buffer(HTTP_BUFFER_STAT_MSG, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_STAT_MSG-1]);
    get_classic_buffer(HTTP_BUFFER_VERSION, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_VERSION-1]);
    get_classic_buffer(HTTP_BUFFER_RAW_STATUS, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_STATUS-1]);
    HttpMsgSection::print_section_wrapup(output);
}
#endif

