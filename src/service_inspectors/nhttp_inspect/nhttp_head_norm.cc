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
void HeaderNormalizer::normalize(const HeaderId head_id, const int count, ScratchPad& scratch_pad,
    NHttpInfractions& infractions, NHttpEventGen& events, const HeaderId header_name_id[],
    const Field header_value[], const int32_t num_headers, Field& result_field) const
{
    if (result_field.length != STAT_NOTCOMPUTE)
    {
        return;
    }
    if (format == NORM_NULL)
    {
        result_field.length = STAT_NOTCONFIGURED;
        return;
    }
    if (count == 0)
    {
        result_field.length = STAT_NOSOURCE;
        return;
    }

    // Search Header IDs from all the headers in this message. concatenate_repeats means the header
    // can properly be present more than once. The standard normalization is to concatenate all the
    // repeated field values into a comma-separated list. Otherwise only the first value will be
    // normalized and the rest will be ignored.
    int num_matches = 0;
    int32_t buffer_length = 0;
    int curr_match = -1;   // FIXIT-P initialization that serves no functional purpose to prevent
                           // compiler warning
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

    // We are allocating twice as much memory as we need to store the normalized field value. The
    // raw field value will be copied into one half of the buffer. Concatenation and white space
    // normalization happen during this step. Next a series of normalization functions will
    // transform the value into final form. Each normalization copies the value from one half of
    // the buffer to the other. Based on whether the number of normalization functions is odd or
    // even, the initial placement in the buffer is chosen so that the final normalization leaves
    // the field value at the front of the buffer. The buffer space actually used is locked down in
    // the scratch_pad. The remainder of the first half and all of the second half are returned to
    // the scratch_pad for future use.

    // Round up to multiple of eight so that both halves are 64-bit aligned. 200 is a "way too big"
    // fudge factor to allow for modest expansion of field size during normalization.
    buffer_length += (8-buffer_length%8)%8 + 200;
    uint8_t* const scratch = scratch_pad.request(2*buffer_length);
    if (scratch == nullptr)
    {
        result_field.length = STAT_INSUFMEMORY;
        return;
    }

    uint8_t* const front_half = scratch;
    uint8_t* const back_half = scratch + buffer_length;
    uint8_t* working = (num_normalizers%2 == 0) ? front_half : back_half;
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
            data_length = normalizer[i](back_half, data_length, front_half, infractions, events,
                norm_arg[i]);
        }
        else
        {
            data_length = normalizer[i](front_half, data_length, back_half, infractions, events,
                norm_arg[i]);
        }
        if (data_length <= 0)
        {
            result_field.length = data_length;
            return;
        }
    }
    result_field.start = scratch;
    result_field.length = data_length;
    scratch_pad.commit(data_length);
    return;
}

