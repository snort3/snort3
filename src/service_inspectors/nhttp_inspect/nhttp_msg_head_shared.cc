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
// nhttp_msg_head_shared.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_normalizers.h"
#include "nhttp_uri_norm.h"
#include "nhttp_msg_head_shared.h"

using namespace NHttpEnums;

NHttpMsgHeadShared::~NHttpMsgHeadShared()
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
        temp_ptr->norm.delete_buffer();
        delete temp_ptr;
    }
    if (classic_raw_header_alloc)
        classic_raw_header.delete_buffer();
    if (classic_norm_header_alloc)
        classic_norm_header.delete_buffer();
    if (classic_norm_cookie_alloc)
        classic_norm_cookie.delete_buffer();
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgHeadShared::analyze()
{
    parse_header_block();
    parse_header_lines();
    create_norm_head_list();
}

void NHttpMsgHeadShared::create_norm_head_list()
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
                norm_heads = new NormalizedHeader;
                norm_heads->next = tmp_ptr;
                norm_heads->id = header_name_id[j];
                norm_heads->count = 1;
            }
        }
    }
}

// Divide up the block of header fields into individual header field lines.
void NHttpMsgHeadShared::parse_header_block()
{
    int32_t bytes_used = 0;
    num_headers = 0;
    int num_seps;
    // session_data->num_head_lines is computed without consideration of wrapping and may overstate
    // actual number of headers. Rely on num_headers which is calculated correctly.
    header_line = new Field[session_data->num_head_lines[source_id]];
    while (bytes_used < msg_text.length)
    {
        assert(num_headers < session_data->num_head_lines[source_id]);
        header_line[num_headers].start = msg_text.start + bytes_used;
        header_line[num_headers].length = find_header_end(header_line[num_headers].start,
            msg_text.length - bytes_used, num_seps);
        if (header_line[num_headers].length > MAX_HEADER_LENGTH)
        {
            infractions += INF_TOO_LONG_HEADER;
            events.create_event(EVENT_LONG_HDR);
        }
        bytes_used += header_line[num_headers++].length + num_seps;
        if (num_headers >= MAX_HEADERS)
        {
            break;
        }
    }
    if (bytes_used < msg_text.length)
    {
        // FIXIT-M eventually need to separate max header alert from internal maximum
        infractions += INF_TOO_MANY_HEADERS;
        events.create_event(EVENT_MAX_HEADERS);
    }
}

// Return the number of octets before the CRLF that ends a header. CRLF does not count when
// immediately followed by <SP> or <LF>. These whitespace characters at the beginning of the next
// line indicate that the previous header has wrapped and is continuing on the next line.
//
// The final header in the block will not be terminated by CRLF (splitter design) but will
// terminate at the end of the buffer. length is returned.
//
// Bare LF without CR is accepted as the terminator.
//
// FIXIT-M Need to generate EVENT_EXCEEDS_SPACES for excessive white space within a header

uint32_t NHttpMsgHeadShared::find_header_end(const uint8_t* buffer, int32_t length, int& num_seps)
{
    // k=1 because the splitter would not give us a header consisting solely of LF.
    for (int32_t k=1; k < length; k++)
    {
        if (buffer[k] == '\n')
        {
            // Check for wrapping
            if ((k+1 == length) || !is_sp_tab[buffer[k+1]])
            {
                num_seps = (buffer[k-1] == '\r') ? 2 : 1;
                if (num_seps == 1)
                {
                    infractions += INF_LF_WITHOUT_CR;
                    events.create_event(EVENT_IIS_DELIMITER);
                }
                return k + 1 - num_seps;
            }
        }
    }
    num_seps = 0;
    return length;
}

// Divide header field lines into field name and field value
void NHttpMsgHeadShared::parse_header_lines()
{
    header_name = new Field[num_headers];
    header_value = new Field[num_headers];
    header_name_id = new HeaderId[num_headers];

    int colon;
    for (int k=0; k < num_headers; k++)
    {
        for (colon=0; colon < header_line[k].length; colon++)
        {
            if (header_line[k].start[colon] == ':')
                break;
        }
        if (colon < header_line[k].length)
        {
            header_name[k].start = header_line[k].start;
            header_name[k].length = colon;
            header_value[k].start = header_line[k].start + colon + 1;
            header_value[k].length = header_line[k].length - colon - 1;
        }
        else
        {
            infractions += INF_BAD_HEADER;
            events.create_event(EVENT_BAD_HEADER);
            header_name[k].set(STAT_PROBLEMATIC);
            header_value[k].set(STAT_PROBLEMATIC);
        }
    }
}

void NHttpMsgHeadShared::derive_header_name_id(int index)
{
    const int32_t& length = header_name[index].length;
    const uint8_t*& buffer = header_name[index].start;

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
        if (!is_sp_tab[buffer[k]])
        {
            lower_name[lower_length++] = ((buffer[k] < 'A') || (buffer[k] > 'Z')) ?
                buffer[k] : buffer[k] - ('A' - 'a');
        }
        else
        {
            infractions += INF_HEAD_NAME_WHITESPACE;
            events.create_event(EVENT_HEAD_NAME_WHITESPACE);
        }
    }
    header_name_id[index] = (HeaderId)str_to_code(lower_name, lower_length, header_list);
    delete[] lower_name;
}

NHttpMsgHeadShared::NormalizedHeader* NHttpMsgHeadShared::get_header_node(HeaderId header_id) const
{
    if (!headers_present[header_id])
        return nullptr;

    NormalizedHeader* list_ptr;
    for (list_ptr = norm_heads; list_ptr->id != header_id; list_ptr = list_ptr->next);
    return (list_ptr);
}

int NHttpMsgHeadShared::get_header_count(HeaderId header_id) const
{
    NormalizedHeader* node = get_header_node(header_id);
    return (node != nullptr) ? node->count : 0;
}

const Field& NHttpMsgHeadShared::get_classic_raw_header()
{
    if (classic_raw_header.length != STAT_NOT_COMPUTE)
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
        const int32_t head_len = (k == num_headers-1) ? header_line[k].length :
            header_line[k+1].start - header_line[k].start;
        length += head_len;
    }

    // Step through headers again and do the copying this time
    uint8_t* const buffer = new uint8_t[length];
    int32_t current = 0;
    for (int k = 0; k < num_headers; k++)
    {
        if (header_name_id[k] == cookie_head)
            continue;
        const int32_t head_len = (k == num_headers-1) ? header_line[k].length :
            header_line[k+1].start - header_line[k].start;
        memcpy(buffer + current, header_line[k].start, head_len);
        current += head_len;
    }
    assert(current == length);

    classic_raw_header.set(length, buffer);
    classic_raw_header_alloc = true;
    return classic_raw_header;
}

const Field& NHttpMsgHeadShared::get_classic_norm_header()
{
    return classic_normalize(get_classic_raw_header(), classic_norm_header,
        classic_norm_header_alloc, params->uri_param);
}

const Field& NHttpMsgHeadShared::get_classic_raw_cookie()
{
    HeaderId cookie_head = (source_id == SRC_CLIENT) ? HEAD_COOKIE : HEAD_SET_COOKIE;
    return get_header_value_norm(cookie_head);
}

const Field& NHttpMsgHeadShared::get_classic_norm_cookie()
{
    return classic_normalize(get_classic_raw_cookie(), classic_norm_cookie,
        classic_norm_cookie_alloc, params->uri_param);
}

const Field& NHttpMsgHeadShared::get_header_value_norm(HeaderId header_id)
{
    NormalizedHeader* node = get_header_node(header_id);
    if (node == nullptr)
        return Field::FIELD_NULL;
    header_norms[header_id]->normalize(header_id, node->count, infractions, events, header_name_id,
        header_value, num_headers, node->norm);
    return node->norm;
}

#ifdef REG_TEST
void NHttpMsgHeadShared::print_headers(FILE* output)
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
        if (get_header_value_norm((HeaderId)k).length != STAT_NO_SOURCE)
        {
            snprintf(title_buf, sizeof(title_buf), "Normalized header %d", k);
            get_header_value_norm((HeaderId)k).print(output, title_buf);
        }
    }
}
#endif

