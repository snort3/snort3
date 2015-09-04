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
// nhttp_msg_head_shared.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_normalizers.h"
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
        delete temp_ptr;
    }
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgHeadShared::analyze()
{
    parse_header_block();
    parse_header_lines();
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
        }
    }
}

void NHttpMsgHeadShared::derive_header_name_id(int index)
{
    const int32_t& length = header_name[index].length;
    const uint8_t*& buffer = header_name[index].start;

    // Normalize header field name to lower case and remove LWS for matching purposes
    int32_t lower_length = 0;
    uint8_t* lower_name;
    if ((lower_name = scratch_pad.request(length)) == nullptr)
    {
        infractions += INF_NO_SCRATCH;
        header_name_id[index] = HEAD__INSUFMEMORY;
        return;
    }
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

const Field& NHttpMsgHeadShared::get_header_value_norm(HeaderId header_id)
{
    NormalizedHeader* node = get_header_node(header_id);
    if (node == nullptr)
        return Field::FIELD_NULL;
    header_norms[header_id]->normalize(header_id, node->count, scratch_pad, infractions, events,
        header_name_id, header_value, num_headers, node->norm);
    return node->norm;
}

void NHttpMsgHeadShared::print_headers(FILE* output)
{
    char title_buf[100];
    if (num_headers != STAT_NOSOURCE)
        fprintf(output, "Number of headers: %d\n", num_headers);
    for (int j=0; j < num_headers; j++)
    {
        snprintf(title_buf, sizeof(title_buf), "Header ID %d", header_name_id[j]);
        header_value[j].print(output, title_buf);
    }
    for (int k=1; k <= HEAD__MAX_VALUE-1; k++)
    {
        if (get_header_value_norm((HeaderId)k).length != STAT_NOSOURCE)
        {
            snprintf(title_buf, sizeof(title_buf), "Normalized header %d", k);
            get_header_value_norm((HeaderId)k).print(output, title_buf, true);
        }
    }
}

