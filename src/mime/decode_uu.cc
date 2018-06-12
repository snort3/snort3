//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// decode_uu.cc author Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode_uu.h"

#include <cstring>

#include "utils/safec.h"
#include "utils/util_cstring.h"

#include "decode_buffer.h"

#define UU_DECODE_CHAR(c) (((c) - 0x20) & 0x3f)

void UUDecode::reset_decode_state()
{
    reset_decoded_bytes();

    if (buffer)
        buffer->reset_saved();

    begin_found = end_found = false;
}

DecodeResult UUDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;

    if (!buffer->check_restore_buffer())
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    uint32_t encode_avail = buffer->get_encode_avail() - buffer->get_prev_encoded_bytes();

    if ((uint32_t)(end- start) > encode_avail)
        act_encode_size = encode_avail;
    else
        act_encode_size = end - start;

    if (encode_avail > 0)
    {
        if (act_encode_size > encode_avail)
        {
            reset_decode_state();
            return DECODE_FAIL;
        }

        memcpy_s((buffer->get_encode_buff() + buffer->get_prev_encoded_bytes()),
            encode_avail, start, act_encode_size);
    }

    act_encode_size = act_encode_size + buffer->get_prev_encoded_bytes();

    if (sf_uudecode(buffer->get_encode_buff(), act_encode_size, buffer->get_decode_buff(),
            buffer->get_decode_avail(), &bytes_read, &act_decode_size,
            &(begin_found), &(end_found)) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }
    else if (!act_decode_size && !encode_avail)
    {
        /* Have insufficient data to decode */
        reset_decode_state();
        return DECODE_FAIL;
    }

    /* Found the end. No more encoded data */

    if (end_found)
    {
        end_found = false;
        begin_found = false;
    }

    if (bytes_read < act_encode_size)
    {
        buffer->save_buffer(buffer->get_encode_buff() + bytes_read, (act_encode_size - bytes_read));
        act_encode_size = bytes_read;
    }
    else
        buffer->reset_saved();

    decoded_bytes = act_decode_size;
    decodePtr = buffer->get_decode_buff();
    buffer->update_buffer(act_encode_size, act_decode_size);
    decode_bytes_read = buffer->get_decode_bytes_read();
    return DECODE_SUCCESS;
}

UUDecode::UUDecode(int max_depth, int detect_depth) : DataDecode(max_depth, detect_depth)
{
    buffer = new DecodeBuffer(max_depth);
}

UUDecode::~UUDecode()
{
    if (buffer)
        delete buffer;
}

int sf_uudecode(uint8_t* src, uint32_t slen, uint8_t* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied, bool* begin_found, bool* end_found)
{
    int sol = 1, length = 0;
    const uint8_t* ptr;
    uint8_t* end, * dptr, * dend;

    if (!src || !slen || !dst || !dlen ||  !bytes_read || !bytes_copied || !begin_found ||
        !end_found )
        return -1;

    ptr = src;
    end = src + slen;
    dptr = dst;
    dend = dst + dlen;
    /* begin not found. Search for begin */
    if ( !(*begin_found) )
    {
        if ( slen < 5 )
        {
            /* Not enough data to search */
            *bytes_read = 0;
            *bytes_copied = 0;
            return 0;
        }
        else
        {
            const uint8_t* sod = (const uint8_t*)snort::SnortStrnStr((const char*)src, 5, "begin");

            if (sod)
            {
                *begin_found = true;
                /*begin str found. Move to the actual data*/
                ptr = (const uint8_t*)snort::SnortStrnStr((const char*)(sod), (end - sod), "\n");
                if ( !ptr )
                {
                    *bytes_read = slen;
                    *bytes_copied = 0;
                    return 0;
                }
            }
            else
            {
                /*Encoded data for UUencode should start with begin. Error encountered.*/
                return -1;
            }
        }
    }

    while ( (ptr < end) && (dptr < dend))
    {
        if (*ptr == '\n')
        {
            sol = 1;
            ptr++;
            continue;
        }

        if (sol)
        {
            sol = 0;
            length = UU_DECODE_CHAR(*ptr);

            if ( length <= 0 )
            {
                /* empty line with no encoded characters indicates end of output */
                break;
            }
            else if ( length == 5 )
            {
                if (*ptr == 'e')
                {
                    *end_found = true;
                    break;
                }
            }
            /* check if destination buffer is big enough */
            if (( dend - dptr) < length)
            {
                length = dend - dptr;
            }

            length = (length * 4) / 3;

            /*check if src buffer has enough encoded data*/
            if ( (end - (ptr + 1)) < length)
            {
                /*not enough data to decode. We will wait for the next packet*/
                break;
            }

            ptr++;

            while ( length > 0 )
            {
                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 2) | (UU_DECODE_CHAR(ptr[1]) >> 4);
                ptr++;
                if (--length == 0 )
                    break;

                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 4) | (UU_DECODE_CHAR(ptr[1]) >> 2);
                ptr++;
                if (--length == 0)
                    break;

                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 6) | (UU_DECODE_CHAR(ptr[1]));
                ptr += 2;
                length -= 2;
            }
        }
        else
        {
            /* probably padding. skip over it.*/
            ptr++;
        }
    }

    if (*end_found)
        *bytes_read = end - src;
    else
        *bytes_read = ptr - src;
    *bytes_copied = dptr - dst;
    return 0;
}

