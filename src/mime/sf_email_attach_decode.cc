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

#include "utils/snort_bounds.h"
#include "utils/util.h"
#include "utils/util_unfold.h"


#define UU_DECODE_CHAR(c) (((c) - 0x20) & 0x3f)

inline void DataDecode::clear_prev_encode_buf()
{
    prev_encoded_bytes = 0;
    prev_encoded_buf = nullptr;
}

void DataDecode::reset_decoded_bytes()
{
    decodePtr = nullptr;
    decoded_bytes = 0;
}

void DataDecode::reset_decode_state()
{
    reset_decoded_bytes();
    clear_prev_encode_buf();
}


// 1. Stop decoding when we have reached either the decode depth or encode depth.
// 2. Stop decoding when we are out of memory
bool DataDecode::is_buffer_available(uint32_t& encode_avail, uint32_t& decode_avail)
{
    if (!(encode_depth))
    {
        encode_avail = decode_avail = buf_size;
    }
    else
    {
        encode_avail = encode_depth - encode_bytes_read;
        decode_avail = decode_depth - decode_bytes_read;
    }

    if (encode_avail ==0 || decode_avail ==0 ||
        (!encodeBuf) || (!decodeBuf))
    {
        reset_decode_state();
        return false;
    }

    return true;
}

void DataDecode::resume_decode(uint32_t& encode_avail, uint32_t& prev_bytes)
{
    uint32_t i = 0;

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of data spanned across packets*/

    if ( !prev_encoded_bytes )
        return;

    if (prev_encoded_bytes > encode_avail)
        prev_encoded_bytes = encode_avail;

    if (prev_encoded_buf)
    {
        prev_bytes = prev_encoded_bytes;
        encode_avail = encode_avail - prev_bytes;
        while (prev_encoded_bytes)
        {
            encodeBuf[i] = prev_encoded_buf[i];
            i++;
            prev_encoded_bytes--;
        }
    }
}

DecodeResult B64Decode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t encode_avail = 0, decode_avail = 0;
    uint32_t act_encode_size = 0, act_decode_size = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!is_buffer_available(encode_avail, decode_avail))
        return DECODE_EXCEEDED;

    resume_decode(encode_avail, prev_bytes);

    if (sf_strip_CRLF(start, (end-start), encodeBuf + prev_bytes, encode_avail,
        &act_encode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + prev_bytes;

    i = (act_encode_size)%4;

    /* Encoded data should be in multiples of 4. Then we need to wait for the remainder encoded data to
     * successfully decode the base64 data. This happens when base64 data is spanned across packets*/
    if (i)
    {
        prev_encoded_bytes = i;
        act_encode_size = act_encode_size - i;
        prev_encoded_buf = encodeBuf + act_encode_size;
    }

    if (sf_base64decode(encodeBuf, act_encode_size, decodeBuf, decode_avail, &act_decode_size) !=
        0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }
    else if (!act_decode_size && !encode_avail)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    decodePtr = decodeBuf;
    decoded_bytes = act_decode_size;
    encode_bytes_read += act_encode_size;
    decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

DecodeResult QPDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t encode_avail = 0, decode_avail = 0;
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!is_buffer_available(encode_avail, decode_avail))
        return DECODE_EXCEEDED;

    resume_decode(encode_avail, prev_bytes);

    if (sf_strip_LWS(start, (end-start), encodeBuf + prev_bytes, encode_avail,
        &act_encode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + prev_bytes;

    if (sf_qpdecode((char*)encodeBuf, act_encode_size, (char*)decodeBuf, decode_avail,
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
        prev_encoded_bytes = (act_encode_size - bytes_read);
        prev_encoded_buf = encodeBuf + bytes_read;
        act_encode_size = bytes_read;
    }

    decodePtr = decodeBuf;
    decoded_bytes = act_decode_size;
    encode_bytes_read += act_encode_size;
    decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

void UUDecode::reset_decode_state()
{
    DataDecode::reset_decode_state();
    begin_found = end_found = false;
}

DecodeResult UUDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t encode_avail = 0, decode_avail = 0;
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!is_buffer_available(encode_avail, decode_avail))
           return DECODE_EXCEEDED;

    resume_decode(encode_avail, prev_bytes);

    if ((uint32_t)(end- start) > encode_avail)
        act_encode_size = encode_avail;
    else
        act_encode_size = end - start;

    if (encode_avail > 0)
    {
        if (SafeMemcpy((encodeBuf + prev_bytes), start, act_encode_size, encodeBuf, (encodeBuf+
            encode_avail + prev_bytes)) != SAFEMEM_SUCCESS)
        {
            reset_decode_state();
            return DECODE_FAIL;
        }
    }

    act_encode_size = act_encode_size + prev_bytes;

    if (sf_uudecode(encodeBuf, act_encode_size, decodeBuf, decode_avail, &bytes_read,
        &act_decode_size,
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
        prev_encoded_bytes = (act_encode_size - bytes_read);
        prev_encoded_buf = encodeBuf + bytes_read;
        act_encode_size = bytes_read;
    }

    decodePtr = decodeBuf;
    decoded_bytes = act_decode_size;
    encode_bytes_read += act_encode_size;
    decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

DecodeResult BitDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t bytes_avail = 0;
    uint32_t act_size = 0;

    clear_prev_encode_buf();

    if (!(decode_depth))
    {
        bytes_avail = buf_size;
    }
    else if ( decode_depth < 0 )
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        bytes_avail = decode_depth - decode_bytes_read;
    }

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if (bytes_avail ==0)
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    if ( (uint32_t)(end-start) < bytes_avail )
    {
        act_size = ( end - start);
    }
    else
    {
        act_size = bytes_avail;
    }

    decoded_bytes = act_size;
    decodePtr = (uint8_t*)start;
    decode_bytes_read += act_size;

    return DECODE_SUCCESS;
}

int DataDecode::get_detection_depth()
{
    // unlimited
    if (!decode_depth)
        return decoded_bytes;
    // exceeded depth before (decode_bytes_read has been updated)
    else if (decode_depth < decode_bytes_read - decoded_bytes)
        return 0;
    // lower than depth
    else if (decode_depth > decode_bytes_read)
        return decoded_bytes;
    // cut off
    else
        return (decode_depth + decoded_bytes - decode_bytes_read);
}

int DataDecode::get_decoded_data(uint8_t** buf,  uint32_t* size)
{
    if (decoded_bytes > 0)
        *size = decoded_bytes;
    else
        return 0;

    if (decodePtr != NULL)
        *buf = decodePtr;
    else
        return 0;
}

#define MAX_DEPTH       65536

DataDecode::DataDecode(int max_depth)
{
    if (!max_depth)
        buf_size = MAX_DEPTH;
    else
        buf_size = max_depth;

    encode_depth = decode_depth = max_depth;
    encode_bytes_read = decode_bytes_read = 0;
    prev_encoded_bytes = 0;
    prev_encoded_buf = nullptr;
    decoded_bytes = 0;

    if (max_depth < 0)
        return;

    encodeBuf = (uint8_t*)SnortAlloc(buf_size);
    decodeBuf = (uint8_t*)SnortAlloc(buf_size);
}

DataDecode::~DataDecode()
{
    if (encodeBuf)
        free(encodeBuf);
    if (decodeBuf)
        free(decodeBuf);
}

int sf_qpdecode(char* src, uint32_t slen, char* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied)
{
    char ch;

    if (!src || !slen || !dst || !dlen || !bytes_read || !bytes_copied )
        return -1;

    *bytes_read = 0;
    *bytes_copied = 0;

    while ( (*bytes_read < slen) && (*bytes_copied < dlen))
    {
        ch = src[*bytes_read];
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

int sf_uudecode(uint8_t* src, uint32_t slen, uint8_t* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied, bool* begin_found, bool* end_found)
{
    uint8_t* sod;
    int sol = 1, length = 0;
    uint8_t* ptr, * end, * dptr, * dend;

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
            sod = (uint8_t*)SnortStrnStr((const char*)src, 5, "begin");
            if (sod)
            {
                *begin_found = true;
                /*begin str found. Move to the actual data*/
                ptr = (uint8_t*)SnortStrnStr((const char*)(sod), (end - sod), "\n");
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
