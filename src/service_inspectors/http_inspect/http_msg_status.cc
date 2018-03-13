//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_status.h"

#include "http_api.h"
#include "http_msg_header.h"
#include "stream/stream.h"

using namespace HttpEnums;

HttpMsgStatus::HttpMsgStatus(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, snort::Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgStart(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_status(this);
}

void HttpMsgStatus::parse_start_line()
{
    // Splitter guarantees line begins with "HTTP/"

    if ((start_line.length() < 12) || !is_sp_tab[start_line.start()[8]])
    {
        add_infraction(INF_BAD_STAT_LINE);
        create_event(EVENT_MISFORMATTED_HTTP);
        return;
    }

    int32_t first_end; // last whitespace in first clump of whitespace
    for (first_end = 9; (first_end < start_line.length())
        && is_sp_tab[start_line.start()[first_end]]; first_end++);
    first_end--;

    if (start_line.length() < first_end + 4)
    {
        add_infraction(INF_BAD_STAT_LINE);
        create_event(EVENT_MISFORMATTED_HTTP);
        return;
    }

    if ((start_line.length() > first_end + 4) && !is_sp_tab[start_line.start()[first_end + 4]])
    {
        // FIXIT-M This should not be fatal. HI supports something like "HTTP/1.1 200\\OK\r\n" as
        // seen in a status line test.
        add_infraction(INF_BAD_STAT_LINE);
        create_event(EVENT_MISFORMATTED_HTTP);
        return;
    }

    HttpModule::increment_peg_counts(PEG_RESPONSE);

    version.set(8, start_line.start());
    derive_version_id();

    status_code.set(3, start_line.start() + first_end + 1);
    derive_status_code_num();

    if (start_line.length() > first_end + 5)
    {
        reason_phrase.set(start_line.length() - first_end - 5, start_line.start() + first_end + 5);
    }
}

void HttpMsgStatus::derive_status_code_num()
{
    if ((status_code.start()[0] < '0') || (status_code.start()[0] > '9') ||
        (status_code.start()[1] < '0') || (status_code.start()[1] > '9') ||
        (status_code.start()[2] < '0') || (status_code.start()[2] > '9'))
    {
        add_infraction(INF_BAD_STAT_CODE);
        create_event(EVENT_INVALID_STATCODE);
        status_code_num = STAT_PROBLEMATIC;
        return;
    }
    status_code_num = (status_code.start()[0] - '0') * 100 + (status_code.start()[1] - '0') * 10 +
        (status_code.start()[2] - '0');
    if ((status_code_num < 100) || (status_code_num > 599))
    {
        add_infraction(INF_BAD_STAT_CODE);
        create_event(EVENT_INVALID_STATCODE);
    }
    if ((status_code_num >= 102) && (status_code_num <= 199))
    {
        add_infraction(INF_UNKNOWN_1XX_STATUS);
        create_event(EVENT_UNKNOWN_1XX_STATUS);
    }
}

void HttpMsgStatus::gen_events()
{
    if (*transaction->get_infractions(source_id) & INF_BAD_STAT_LINE)
        return;

    if (status_code.start() > start_line.start() + 9)
    {
        add_infraction(INF_STATUS_WS);
        create_event(EVENT_IMPROPER_WS);
    }

    for (int k = 8; k < status_code.start() - start_line.start(); k++)
    {
        if (start_line.start()[k] == '\t')
        {
            add_infraction(INF_STATUS_TAB);
            create_event(EVENT_APACHE_WS);
        }
    }

    if (status_code.start() - start_line.start() + 3 < start_line.length())
    {
        if (status_code.start()[3] == '\t')
        {
            add_infraction(INF_STATUS_TAB);
            create_event(EVENT_APACHE_WS);
        }
    }

    for (int k=0; k < reason_phrase.length(); k++)
    {
        if ((reason_phrase.start()[k] <= 31) || (reason_phrase.start()[k] >= 127))
        {
            // Illegal character in reason phrase
            add_infraction(INF_BAD_PHRASE);
            create_event(EVENT_CTRL_IN_REASON);
            break;
        }
    }

    if (!transaction->get_request() && (trans_num == 1))
    {
        if (flow->is_pdu_inorder(SSN_DIR_FROM_SERVER))
        {
            // HTTP response without a request. Possible ssh tunneling
            add_infraction(INF_RESPONSE_WO_REQUEST);
            create_event(EVENT_RESPONSE_WO_REQUEST);
        }
    }

    if (status_code_num == 206)
    {
        // Verify that 206 Partial Content is in response to a Range request. Unsolicited 206
        // responses indicate content is being fragmented for no good reason.
        HttpMsgHeader* const req_header = transaction->get_header(SRC_CLIENT);
        if ((req_header != nullptr) && (req_header->get_header_count(HEAD_RANGE) == 0))
        {
            add_infraction(INF_206_WITHOUT_RANGE);
            create_event(EVENT_206_WITHOUT_RANGE);
        }
    }
}

void HttpMsgStatus::update_flow()
{
    if (*transaction->get_infractions(source_id) & INF_BAD_STAT_LINE)
    {
        session_data->half_reset(source_id);
        session_data->type_expected[source_id] = SEC_ABORT;
    }
    else
    {
        session_data->type_expected[source_id] = SEC_HEADER;
        session_data->version_id[source_id] = version_id;
        session_data->status_code_num = status_code_num;
        // 100 response means the next response message will be added to this transaction instead
        // of being part of another transaction. As implemented it is possible for multiple 100
        // responses to all be included in the same transaction. It's not obvious whether that is
        // the best way to handle what should be a highly abnormal situation.
        if (status_code_num == 100)
        {
            // Were we "Expect"-ing this?
            HttpMsgHeader* const req_header = transaction->get_header(SRC_CLIENT);
            if ((req_header != nullptr) && (req_header->get_header_count(HEAD_EXPECT) == 0))
            {
                add_infraction(INF_UNEXPECTED_100_RESPONSE);
                create_event(EVENT_UNEXPECTED_100_RESPONSE);
            }
            transaction->set_one_hundred_response();
        }
    }
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;
}

#ifdef REG_TEST
void HttpMsgStatus::print_section(FILE* output)
{
    HttpMsgSection::print_section_title(output, "status line");
    fprintf(output, "Version ID: %d\n", version_id);
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

