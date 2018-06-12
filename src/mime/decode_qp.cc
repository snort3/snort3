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
// decode_qp.cc author Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode_qp.h"

#include <cctype>
#include <cstdlib>

#include "utils/util_unfold.h"

#include "decode_buffer.h"

void QPDecode::reset_decode_state()
{
    reset_decoded_bytes();
    buffer->reset_saved();
}

DecodeResult QPDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;

    if (!buffer->check_restore_buffer())
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    uint32_t encode_avail = buffer->get_encode_avail() - buffer->get_prev_encoded_bytes();

    if (snort::sf_strip_LWS(start, (end-start), buffer->get_encode_buff() + buffer->get_prev_encoded_bytes(),
        encode_avail, &act_encode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + buffer->get_prev_encoded_bytes();

    if (sf_qpdecode((char *)buffer->get_encode_buff(), act_encode_size,
        (char *)buffer->get_decode_buff(), buffer->get_decode_avail(),
        &bytes_read, &act_decode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }
    else if (!act_decode_size && !encode_avail)
    {
        reset_decode_state();
        return DECODE_FAIL;
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

QPDecode::QPDecode(int max_depth, int detect_depth) : DataDecode(max_depth, detect_depth)
{
    buffer = new DecodeBuffer(max_depth);
}

QPDecode::~QPDecode()
{
    if (buffer)
        delete buffer;
}

int sf_qpdecode(const char* src, uint32_t slen, char* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied)
{
    if (!src || !slen || !dst || !dlen || !bytes_read || !bytes_copied )
        return -1;

    *bytes_read = 0;
    *bytes_copied = 0;

    while ( (*bytes_read < slen) && (*bytes_copied < dlen))
    {
        char ch = src[*bytes_read];
        *bytes_read += 1;

        if ( ch == '=' )
        {
            if ( (*bytes_read < slen))
            {
                if (src[*bytes_read] == '\n')
                {
                    *bytes_read += 1;
                    continue;
                }
                else if ( *bytes_read < (slen - 1) )
                {
                    char ch1 = src[*bytes_read];
                    char ch2 = src[*bytes_read + 1];
                    if ( ch1 == '\r' && ch2 == '\n')
                    {
                        *bytes_read += 2;
                        continue;
                    }
                    if (isxdigit((int)ch1) && isxdigit((int)ch2))
                    {
                        char hexBuf[3];
                        char* eptr;
                        hexBuf[0] = ch1;
                        hexBuf[1] = ch2;
                        hexBuf[2] = '\0';
                        dst[*bytes_copied]= (char)strtoul(hexBuf, &eptr, 16);
                        if ((*eptr != '\0'))
                        {
                            return -1;
                        }
                        *bytes_read += 2;
                        *bytes_copied +=1;
                        continue;
                    }
                    dst[*bytes_copied] = ch;
                    *bytes_copied +=1;
                    continue;
                }
                else
                {
                    *bytes_read -= 1;
                    return 0;
                }
            }
            else
            {
                *bytes_read -= 1;
                return 0;
            }
        }
        else if ( isprint(ch) || isblank(ch) || ch == '\r' || ch == '\n' )
        {
            dst[*bytes_copied] = ch;
            *bytes_copied +=1;
        }
    }

    return 0;
}

