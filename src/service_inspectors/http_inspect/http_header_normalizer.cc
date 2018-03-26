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
// http_header_normalizer.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_enum.h"
#include "http_header_normalizer.h"

#include <cstring>

using namespace HttpEnums;

// This derivation removes leading and trailing linear white space and replaces internal strings of
// linear whitespace with a single <SP>
static int32_t derive_header_content(const uint8_t* value, int32_t length, uint8_t* buffer,
    bool alert_ws, HttpInfractions* infractions, HttpEventGen* events)
{
    int32_t out_length = 0;
    bool beginning = true;
    bool last_white = true;
    for (int32_t k=0; k < length; k++)
    {
        if (!is_sp_tab_cr_lf[value[k]])
        {
            if (alert_ws && last_white && !beginning)
            {
                // white space which is not at beginning or end
                *infractions += INF_BAD_HEADER_WHITESPACE;
                events->create_event(EVENT_BAD_HEADER_WHITESPACE);
            }
            beginning = false;
            last_white = false;
            buffer[out_length++] = value[k];
        }
        else if (!last_white)
        {
            last_white = true;
            buffer[out_length++] = ' ';
        }
    }
    if ((out_length > 0) && (buffer[out_length - 1] == ' '))
    {
        out_length--;
    }
    return out_length;
}

// This method normalizes the header field value for headId.
void HeaderNormalizer::normalize(const HeaderId head_id, const int count,
    HttpInfractions* infractions, HttpEventGen* events, const HeaderId header_name_id[],
    const Field header_value[], const int32_t num_headers, Field& result_field) const
{
    if (result_field.length() != STAT_NOT_COMPUTE)
    {
        return;
    }

    assert(count > 0);

    // Search Header IDs from all the headers in this message. All repeated field values are
    // concatenated into a comma-separated list.
    // FIXIT-L Set-Cookie is a special case in the RFC because multiple Set-Cookie headers are
    // widely used but comma-concatenation of cookies is incorrect. That would be a concern for us
    // if we actually used the cookies. But since we just want a single value to show to the
    // pattern matcher, concatenating is probably fine. In the future we may wish to revisit this
    // issue. Specifically, semicolon-concatenation may be better.
    int num_matches = 0;
    int32_t buffer_length = 0;

    // FIXIT-P initialization that serves no functional purpose to prevent compiler warning
    int curr_match = -1;
    for (int k=0; k < num_headers; k++)
    {
        if (header_name_id[k] == head_id)
        {
            if (++num_matches == 1)
                curr_match = k;   // remembering location of the first matching header
            buffer_length += header_value[k].length();
            if (num_matches >= count)
                break;
        }
    }
    assert(num_matches == count);
    buffer_length += num_matches - 1;    // allow space for concatenation commas

    // We are allocating two buffers to store the normalized field value. The raw field value will
    // be copied into one of them. Concatenation and white space normalization happen during this
    // step. Next a series of normalization functions will transform the value into final form.
    // Each normalization copies the value from one buffer to the other. Based on whether the
    // number of normalization functions is odd or even, the initial buffer is chosen so that the
    // final normalization leaves the normalized header value in norm_value.

    uint8_t* const norm_value = new uint8_t[buffer_length];
    uint8_t* const temp_space = new uint8_t[buffer_length];
    uint8_t* const norm_start = (num_normalizers%2 == 0) ? norm_value : temp_space;
    uint8_t* working = norm_start;
    int32_t data_length = 0;
    for (int j=0; j < num_matches; j++)
    {
        if (j >= 1)
        {
            *working++ = ',';
            data_length++;
            while (header_name_id[++curr_match] != head_id);
        }
        int32_t growth = derive_header_content(header_value[curr_match].start(),
            header_value[curr_match].length(), working, alert_ws, infractions, events);
        working += growth;
        data_length += growth;
    }

    // Many fields names can appear more than once but some should not. If an event or infraction
    // is defined we will check as part of normalization. A comma-separated header value is
    // equivalent to a repeated header name. This is JIT code and we will not check for repeated
    // headers unless someone asks for that header.
    if ((repeat_event != EVENT__NONE) || (repeat_inf != INF__NONE))
    {
        if (count >= 2)
        {
            *infractions += repeat_inf;
            events->create_event(repeat_event);
        }
        else
        {
            for (int k=0; k < data_length; k++)
            {
                if (norm_start[k] == ',')
                {
                    *infractions += repeat_inf;
                    events->create_event(repeat_event);
                    break;
                }
            }
        }
    }

    for (int i=0; i < num_normalizers; i++)
    {
        if (i%2 != num_normalizers%2)
        {
            data_length = normalizer[i](temp_space, data_length, norm_value, infractions, events);
        }
        else
        {
            data_length = normalizer[i](norm_value, data_length, temp_space, infractions, events);
        }
    }
    delete[] temp_space;
    result_field.set(data_length, norm_value, true);
}

