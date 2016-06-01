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
// nhttp_head_norm.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "main/snort_types.h"

#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"
#include "nhttp_head_norm.h"

using namespace NHttpEnums;

// This derivation removes embedded CRLFs (wrapping), omits leading and trailing linear white
// space, and replaces internal strings of <SP> and <LF> with a single <SP>
int32_t HeaderNormalizer::derive_header_content(const uint8_t* value, int32_t length,
    uint8_t* buffer)
{
    int32_t out_length = 0;
    bool last_white = true;
    for (int32_t k=0; k < length; k++)
    {
        if ((value[k] == '\r') && (k+1 < length) && (value[k+1] == '\n'))
            k++;
        else if ((value[k] != ' ') && (value[k] != '\t'))
        {
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
    NHttpInfractions& infractions, NHttpEventGen& events, const HeaderId header_name_id[],
    const Field header_value[], const int32_t num_headers, Field& result_field) const
{
    if (result_field.length != STAT_NOT_COMPUTE)
    {
        return;
    }

    assert(count > 0);

    // Search Header IDs from all the headers in this message. concatenate_repeats means the header
    // can properly be present more than once. The standard normalization is to concatenate all the
    // repeated field values into a comma-separated list. Otherwise only the first value will be
    // normalized and the rest will be ignored.
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
            buffer_length += header_value[k].length;
            if (!concatenate_repeats || (num_matches >= count))
                break;
        }
    }
    assert((!concatenate_repeats && (num_matches == 1)) ||
            (concatenate_repeats && (num_matches == count)));
    buffer_length += num_matches - 1;    // allow space for concatenation commas

    // We are allocating two buffers to store the normalized field value. The raw field value will
    // be copied into one of them. Concatenation and white space normalization happen during this
    // step. Next a series of normalization functions will transform the value into final form.
    // Each normalization copies the value from one buffer to the other. Based on whether the
    // number of normalization functions is odd or even, the initial buffer is chosen so that the
    // final normalization leaves the normalized header value in norm_value.

    uint8_t* const norm_value = new uint8_t[buffer_length];
    uint8_t* const temp_space = new uint8_t[buffer_length];
    uint8_t* working = (num_normalizers%2 == 0) ? norm_value : temp_space;
    int32_t data_length = 0;
    for (int j=0; j < num_matches; j++)
    {
        if (j >= 1)
        {
            *working++ = ',';
            data_length++;
            while (header_name_id[++curr_match] != head_id);
        }
        int32_t growth = derive_header_content(header_value[curr_match].start,
            header_value[curr_match].length, working);
        working += growth;
        data_length += growth;
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
    result_field.set(data_length, norm_value);
    return;
}

