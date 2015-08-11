//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>

#include "sf_email_attach_decode.h"
#include "sf_base64decode.h"
#include "decode_b64.h"

#include "utils/snort_bounds.h"
#include "utils/util.h"
#include "utils/util_unfold.h"

void B64Decode::reset_decode_state()
{
    reset_decoded_bytes();
    buffer->reset();
}

DecodeResult B64Decode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t act_encode_size = 0, act_decode_size = 0;
    uint32_t i = 0;

    if (!buffer->check_restore_buffer())
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    uint32_t encode_avail = buffer->get_encode_avail() - buffer->get_prev_encoded_bytes();

    if (sf_strip_CRLF(start, (end-start), buffer->get_encode_buff() + buffer->get_prev_encoded_bytes(),
        encode_avail, &act_encode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + buffer->get_prev_encoded_bytes();

    i = (act_encode_size)%4;

    /* Encoded data should be in multiples of 4. Then we need to wait for the remainder encoded data to
     * successfully decode the base64 data. This happens when base64 data is spanned across packets*/
    if (i)
    {
        act_encode_size = act_encode_size - i;
        buffer->save_buffer(buffer->get_encode_buff() + act_encode_size, i);
    }

    if (sf_base64decode(buffer->get_encode_buff(), act_encode_size,
        buffer->get_decode_buff(), buffer->get_decode_avail(), &act_decode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }
    else if (!act_decode_size && !encode_avail)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    decoded_bytes = act_decode_size;
    decodePtr = buffer->get_decode_buff();
    buffer->update_buffer(act_encode_size, act_decode_size);
    decode_bytes_read = buffer->get_decode_bytes_read();
    return DECODE_SUCCESS;
}

B64Decode::B64Decode(int max_depth):DataDecode(max_depth)
{
    buffer = new DecodeBuffer(max_depth);
}

B64Decode::~B64Decode()
{
   if (buffer)
       delete buffer;
}
