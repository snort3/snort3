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
            header_count[header_name_id[j]]++;
    }
}

// Divide up the block of header fields into individual header field lines.
void NHttpMsgHeadShared::parse_header_block()
{
    int32_t bytes_used = 0;
    num_headers = 0;
    int num_seps;
    header_line = new Field[session_data->num_head_lines[source_id]];
    while (bytes_used < msg_text.length)
    {
        header_line[num_headers].start = msg_text.start + bytes_used;
        header_line[num_headers].length = find_header_end(header_line[num_headers].start,
            msg_text.length - bytes_used, &num_seps);
        assert(num_headers < session_data->num_head_lines[source_id]);
        bytes_used += header_line[num_headers++].length + num_seps;
        if (num_headers >= MAXHEADERS)
        {
            break;
        }
    }
    if (bytes_used < msg_text.length)
    {
        infractions += INF_TOO_MANY_HEADERS;
    }
}

// Return the number of octets before the CRLF that ends a header. CRLF does not count when
// immediately followed by <SP> or <LF>. These whitespace characters at the beginning of the next
// line indicate that the previous header has wrapped and is continuing on the next line.
//
// The final header in the block will not be terminated by CRLF (splitter design) but will
// terminate at the end of the buffer. length is returned.
//
// Bare LF without CR is accepted as the terminator unless preceded by backslash character. FIXIT-L
// this does not consider whether \LF is contained within a quoted string and perhaps this should
// be revisited. The current approach errs in the direction of not incorrectly dividing a single
// header into two headers.
//
// FIXIT-M any abuse of backslashes in headers should be a preprocessor alert.

uint32_t NHttpMsgHeadShared::find_header_end(const uint8_t* buffer, int32_t length, int* const
    num_seps)
{
    for (int32_t k=0; k < length-1; k++)
    {
        if ((buffer[k] != '\\') && (buffer[k+1] == '\n'))
        {
            if ((k+2 >= length) || ((buffer[k+2] != ' ') && (buffer[k+2] != '\t')))
            {
                *num_seps = (buffer[k] == '\r') ? 2 : 1;
                return k + 2 - *num_seps;
            }
        }
    }
    *num_seps = 0;
    return length;
}

// Divide header field lines into field name and field value
void NHttpMsgHeadShared::parse_header_lines()
{
    header_name = new Field[session_data->num_head_lines[source_id]];
    header_value = new Field[session_data->num_head_lines[source_id]];
    header_name_id = new HeaderId[session_data->num_head_lines[source_id]];

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
        }
    }
}

void NHttpMsgHeadShared::derive_header_name_id(int index)
{
    // Normalize header field name to lower case for matching purposes
    uint8_t* lower_name;
    if ((lower_name = scratch_pad.request(header_name[index].length)) == nullptr)
    {
        infractions += INF_NO_SCRATCH;
        header_name_id[index] = HEAD__INSUFMEMORY;
        return;
    }
    norm_to_lower(header_name[index].start, header_name[index].length, lower_name, infractions,
        nullptr);
    header_name_id[index] = (HeaderId)str_to_code(lower_name, header_name[index].length,
        header_list);
}

const Field& NHttpMsgHeadShared::get_header_value_norm(NHttpEnums::HeaderId header_id)
{
    header_norms[header_id]->normalize(header_id, header_count[header_id], scratch_pad,
        infractions,
        header_name_id, header_value, num_headers, header_value_norm[header_id]);
    return header_value_norm[header_id];
}

void NHttpMsgHeadShared::gen_events()
{
    if (infractions && INF_TOO_MANY_HEADERS)
        events.create_event(EVENT_MAX_HEADERS);
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
    for (int k=1; k <= HEAD__MAXVALUE-1; k++)
    {
        if (get_header_value_norm((HeaderId)k).length != STAT_NOSOURCE)
        {
            snprintf(title_buf, sizeof(title_buf), "Normalized header %d", k);
            get_header_value_norm((HeaderId)k).print(output, title_buf, true);
        }
    }
}

