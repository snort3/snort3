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
// http_msg_head_shared.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_head_shared.h"

using namespace HttpEnums;

HttpMsgHeadShared::~HttpMsgHeadShared()
{
    delete[] header_line;
    delete[] header_name;
    delete[] header_name_id;
    delete[] header_value;
    NormalizedHeader* list_ptr = norm_heads;
    while (list_ptr != nullptr)
    {
        NormalizedHeader* temp_ptr = list_ptr;
        list_ptr = list_ptr->next;
        delete temp_ptr;
    }
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void HttpMsgHeadShared::analyze()
{
    parse_header_block();
    parse_header_lines();
    create_norm_head_list();
}

void HttpMsgHeadShared::create_norm_head_list()
{
    // This function does not do the actual JIT normalization of header values. It converts the
    // header names into numeric IDs and creates a linked list of all the different headers that
    // are present in the message along with the number of times each one appears.
    for (int j=0; j < num_headers; j++)
    {
        derive_header_name_id(j);
        if (header_name_id[j] > 0)
        {
            if (headers_present[header_name_id[j]])
            {
                NormalizedHeader* list_ptr;
                for (list_ptr = norm_heads; list_ptr->id != header_name_id[j];
                    list_ptr = list_ptr->next);
                list_ptr->count++;
            }
            else
            {
                headers_present[header_name_id[j]] = true;
                NormalizedHeader* tmp_ptr = norm_heads;
                norm_heads = new NormalizedHeader(header_name_id[j]);
                norm_heads->next = tmp_ptr;
                norm_heads->count = 1;
            }
        }
    }
}

// Divide up the block of header fields into individual header field lines.
void HttpMsgHeadShared::parse_header_block()
{
    int32_t bytes_used = 0;
    num_headers = 0;
    int32_t num_seps;
    // session_data->num_head_lines is computed without consideration of wrapping and may overstate
    // actual number of headers. Rely on num_headers which is calculated correctly.
    header_line = new Field[session_data->num_head_lines[source_id]];
    while (bytes_used < msg_text.length())
    {
        assert(num_headers < session_data->num_head_lines[source_id]);
        const int32_t header_length = find_next_header(msg_text.start() + bytes_used,
            msg_text.length() - bytes_used, num_seps);
        header_line[num_headers].set(header_length, msg_text.start() + bytes_used + num_seps);
        if (header_line[num_headers].length() > MAX_HEADER_LENGTH)
        {
            add_infraction(INF_TOO_LONG_HEADER);
            create_event(EVENT_LONG_HDR);
        }
        bytes_used += num_seps + header_line[num_headers].length();
        if (++num_headers >= MAX_HEADERS)
        {
            break;
        }
    }
    if (bytes_used < msg_text.length())
    {
        add_infraction(INF_TOO_MANY_HEADERS);
        create_event(EVENT_MAX_HEADERS);
    }
}

// The header section produced by the splitter is of the form:
//
// [CRs]<header 1><separators><header 2><separators> ... <header N>
//
// where separators are CRs or LFs. The CRs at the beginning are a pathological case that will
// virtually never happen. There are no separators after the final header.
//
// This function splits out the next header from the header block. The return value is the length
// of the header without any separators. num_seps is the number of separators to skip over before
// the header starts.
//
// Wrapping is fully supported by http_inspect. Wrapping is deprecated by the RFC and some major
// browsers don't support it. Wrapped headers are very dangerous and should be regarded with
// extreme suspicion.
//
// Except for wrapping, header lines may end with CRLF (correct), LF (incorrect but widely
// tolerated), and CR without LF (very incorrect). The latter is widely supported but some major
// browsers don't support it*. Bare CR separators are very dangerous and should be regarded with
// extreme suspicion. The splitter detects them which is why there is no event generated here.
// Bare LFs are probably not a big deal.
//
// * Not necessarily the same ones that don't support wrapping.

// FIXIT-M Need to generate EVENT_EXCEEDS_SPACES for excessive white space within a header.

int32_t HttpMsgHeadShared::find_next_header(const uint8_t* buffer, int32_t length,
    int32_t& num_seps)
{
    int32_t k = 0;
    // Splitter guarantees buffer will not end on CR or LF.
    for (; is_cr_lf[buffer[k]]; k++);
    num_seps = k;

    for (k++; k < length; k++)
    {
        if (is_cr_lf[buffer[k]])
        {
            // Check for wrapping
            if (((buffer[k] == '\r') && (buffer[k+1] == '\n') && !is_sp_tab[buffer[k+2]]) ||
                ((buffer[k] == '\n') && !is_sp_tab[buffer[k+1]]) ||
                ((buffer[k] == '\r') && !is_sp_tab_lf[buffer[k+1]]))
            {
                return k - num_seps;
            }
            else
            {
                add_infraction(INF_HEADER_WRAPPING);
                create_event(EVENT_HEADER_WRAPPING);
            }
        }
    }
    return length - num_seps;
}

// Divide header field lines into field name and field value
void HttpMsgHeadShared::parse_header_lines()
{
    header_name = new Field[num_headers];
    header_value = new Field[num_headers];
    header_name_id = new HeaderId[num_headers];

    for (int k=0; k < num_headers; k++)
    {
        int colon;
        for (colon=0; colon < header_line[k].length(); colon++)
        {
            if (header_line[k].start()[colon] == ':')
                break;
        }
        if (colon < header_line[k].length())
        {
            header_name[k].set(colon, header_line[k].start());
            header_value[k].set(header_line[k].length() - colon - 1,
                                header_line[k].start() + colon + 1);
        }
        else
        {
            add_infraction(INF_BAD_HEADER);
            create_event(EVENT_BAD_HEADER);
            header_name[k].set(STAT_PROBLEMATIC);
            header_value[k].set(STAT_PROBLEMATIC);
        }
    }
}

void HttpMsgHeadShared::derive_header_name_id(int index)
{
    const int32_t length = header_name[index].length();
    const uint8_t* buffer = header_name[index].start();

    if (length <= 0)
    {
        header_name_id[index] = HEAD__PROBLEMATIC;
        return;
    }

    // Normalize header field name to lower case and remove LWS for matching purposes
    int32_t lower_length = 0;
    uint8_t* lower_name = new uint8_t[length];
    for (int32_t k=0; k < length; k++)
    {
        if (!is_sp_tab_cr_lf[buffer[k]])
        {
            lower_name[lower_length++] = ((buffer[k] < 'A') || (buffer[k] > 'Z')) ?
                buffer[k] : buffer[k] - ('A' - 'a');
            if (!is_print_char[buffer[k]])
            {
                add_infraction(INF_BAD_CHAR_IN_HEADER_NAME);
                create_event(EVENT_BAD_CHAR_IN_HEADER_NAME);
            }
        }
        else
        {
            add_infraction(INF_HEAD_NAME_WHITESPACE);
            create_event(EVENT_HEAD_NAME_WHITESPACE);
        }
    }
    header_name_id[index] = (HeaderId)str_to_code(lower_name, lower_length, header_list);
    delete[] lower_name;
}

HttpMsgHeadShared::NormalizedHeader* HttpMsgHeadShared::get_header_node(HeaderId header_id) const
{
    if (!headers_present[header_id])
        return nullptr;

    NormalizedHeader* list_ptr;
    for (list_ptr = norm_heads; list_ptr->id != header_id; list_ptr = list_ptr->next);
    return (list_ptr);
}

int HttpMsgHeadShared::get_header_count(HeaderId header_id) const
{
    NormalizedHeader* node = get_header_node(header_id);
    return (node != nullptr) ? node->count : 0;
}

const Field& HttpMsgHeadShared::get_classic_raw_header()
{
    if (classic_raw_header.length() != STAT_NOT_COMPUTE)
        return classic_raw_header;
    const HeaderId cookie_head = (source_id == SRC_CLIENT) ? HEAD_COOKIE : HEAD_SET_COOKIE;
    if (!headers_present[cookie_head])
    {
        // There are no cookies so the classic headers are the whole thing
        classic_raw_header.set(msg_text);
        return classic_raw_header;
    }

    // Figure out how much space to allocate by stepping through the headers in advance
    int32_t length = 0;
    for (int k = 0; k < num_headers; k++)
    {
        if (header_name_id[k] == cookie_head)
            continue;
        // All header line Fields point into the buffer holding the entire message section.
        // Calculation must account for separators between header lines, but there are none
        // following the final header line.
        const int32_t head_len = (k == num_headers-1) ? header_line[k].length() :
            header_line[k+1].start() - header_line[k].start();
        length += head_len;
    }

    // Step through headers again and do the copying this time
    uint8_t* const buffer = new uint8_t[length];
    int32_t current = 0;
    for (int k = 0; k < num_headers; k++)
    {
        if (header_name_id[k] == cookie_head)
            continue;
        const int32_t head_len = (k == num_headers-1) ? header_line[k].length() :
            header_line[k+1].start() - header_line[k].start();
        memcpy(buffer + current, header_line[k].start(), head_len);
        current += head_len;
    }
    assert(current == length);

    classic_raw_header.set(length, buffer, true);
    return classic_raw_header;
}

const Field& HttpMsgHeadShared::get_classic_norm_header()
{
    return classic_normalize(get_classic_raw_header(), classic_norm_header, params->uri_param);
}

const Field& HttpMsgHeadShared::get_classic_raw_cookie()
{
    HeaderId cookie_head = (source_id == SRC_CLIENT) ? HEAD_COOKIE : HEAD_SET_COOKIE;
    return get_header_value_norm(cookie_head);
}

const Field& HttpMsgHeadShared::get_classic_norm_cookie()
{
    return classic_normalize(get_classic_raw_cookie(), classic_norm_cookie, params->uri_param);
}

const Field& HttpMsgHeadShared::get_header_value_raw(HeaderId header_id) const
{
    // If the same header field appears more than once the first one will be returned.
    if (!headers_present[header_id])
        return Field::FIELD_NULL;
    for (int k=0; k < num_headers; k++)
    {
        if (header_name_id[k] == header_id)
        {
            return header_value[k];
        }
    }
    assert(false);
    return Field::FIELD_NULL;
}

const Field& HttpMsgHeadShared::get_header_value_norm(HeaderId header_id)
{
    NormalizedHeader* node = get_header_node(header_id);
    if (node == nullptr)
        return Field::FIELD_NULL;
    header_norms[header_id]->normalize(header_id, node->count,
        transaction->get_infractions(source_id), transaction->get_events(source_id),
        header_name_id, header_value, num_headers, node->norm);
    return node->norm;
}

#ifdef REG_TEST
void HttpMsgHeadShared::print_headers(FILE* output)
{
    char title_buf[100];
    if (num_headers != STAT_NO_SOURCE)
        fprintf(output, "Number of headers: %d\n", num_headers);
    for (int j=0; j < num_headers; j++)
    {
        snprintf(title_buf, sizeof(title_buf), "Header ID %d", header_name_id[j]);
        header_value[j].print(output, title_buf);
    }
    for (int k=1; k <= HEAD__MAX_VALUE-1; k++)
    {
        if (get_header_value_norm((HeaderId)k).length() != STAT_NO_SOURCE)
        {
            snprintf(title_buf, sizeof(title_buf), "Normalized header %d", k);
            get_header_value_norm((HeaderId)k).print(output, title_buf);
        }
    }
}
#endif

