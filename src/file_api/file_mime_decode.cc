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

#include "file_mime_decode.h"

#include "utils/snort_bounds.h"
#include "utils/sf_base64decode.h"
#include "utils/util_unfold.h"
#include "utils/util.h"
#include "utils/sf_email_attach_decode.h"

#define MAX_BUF 65535

#define UU_DECODE_CHAR(c) (((c) - 0x20) & 0x3f)

int MimeDecode::getCodeDepth(int code_depth, int64_t file_depth)
{
    if (file_depth < 0 )
        return code_depth;
    else if (( file_depth > MAX_BUF) || (!file_depth) )
        return 0;
    else if (file_depth > code_depth)
        return (int)file_depth;
    else
        return code_depth;
}

static inline int limitDetection(int depth, int decoded_bytes, int decode_bytes_total)
{
    if (!depth)
        return decoded_bytes;
    else if (depth < decode_bytes_total - decoded_bytes)
        return 0;
    else if (depth > decode_bytes_total)
        return decoded_bytes;
    else
        return (depth + decoded_bytes - decode_bytes_total);
}

inline void MimeDecode::ClearPrevEncodeBuf()
{
    prev_encoded_bytes = 0;
    prev_encoded_buf = nullptr;
}


void MimeDecode::reset_bytes_read()
{
    uu_state.begin_found = uu_state.end_found = 0;
    ClearPrevEncodeBuf();
    b64_state.encode_bytes_read = b64_state.decode_bytes_read = 0;
    qp_state.encode_bytes_read = qp_state.decode_bytes_read = 0;
    uu_state.encode_bytes_read = uu_state.decode_bytes_read = 0;
    bitenc_state.bytes_read = 0;
}

void MimeDecode::reset_decoded_bytes()
{
    decodePtr = nullptr;
    decoded_bytes = 0;
    decode_present = 0;
}

inline void MimeDecode::reset_decode_state()
{
    uu_state.begin_found = uu_state.end_found = 0;
    reset_decoded_bytes();
    ClearPrevEncodeBuf();
}

void MimeDecode::clear_decode_state()
{
    decode_type = DECODE_NONE;
    reset_decode_state();
}

DecodeResult MimeDecode::Base64Decode(const uint8_t* start, const uint8_t* end)
{
    uint32_t encode_avail = 0, decode_avail = 0;
    uint8_t* encode_buf, * decode_buf;
    uint32_t act_encode_size = 0, act_decode_size = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!(b64_state.encode_depth))
    {
        encode_avail = decode_avail = buf_size;
    }
    else if ((b64_state.encode_depth) < 0)
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        encode_avail = b64_state.encode_depth - b64_state.encode_bytes_read;
        decode_avail = b64_state.decode_depth - b64_state.decode_bytes_read;
    }

    encode_buf = encodeBuf;
    decode_buf = decodeBuf;

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if (encode_avail ==0 || decode_avail ==0 ||
        (!encode_buf) || (!decode_buf))
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of base64 data spanned across packets*/
    if ( prev_encoded_bytes )
    {
        if (prev_encoded_bytes > encode_avail)
            prev_encoded_bytes = encode_avail;

        if (prev_encoded_buf)
        {
            prev_bytes = prev_encoded_bytes;
            encode_avail = encode_avail - prev_bytes;
            while (prev_encoded_bytes)
            {
                /* Since this data cannot be more than 3 bytes*/
                encode_buf[i] = prev_encoded_buf[i];
                i++;
                prev_encoded_bytes--;
            }
        }
    }

    if (sf_strip_CRLF(start, (end-start), encode_buf + prev_bytes, encode_avail,
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
        prev_encoded_buf = encode_buf + act_encode_size;
    }

    if (sf_base64decode(encode_buf, act_encode_size, decode_buf, decode_avail, &act_decode_size) !=
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

    decode_present = 1;
    decodePtr = decode_buf;
    decoded_bytes = act_decode_size;
    b64_state.encode_bytes_read += act_encode_size;
    b64_state.decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

DecodeResult MimeDecode::QPDecode(const uint8_t* start, const uint8_t* end)
{
    uint32_t encode_avail = 0, decode_avail = 0;
    uint8_t* encode_buf, * decode_buf;
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!(qp_state.encode_depth))
    {
        encode_avail = decode_avail = buf_size;
    }
    else if ((qp_state.encode_depth) < 0)
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        encode_avail = qp_state.encode_depth - qp_state.encode_bytes_read;
        decode_avail = qp_state.decode_depth - qp_state.decode_bytes_read;
    }

    encode_buf = encodeBuf;
    decode_buf = decodeBuf;

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if (encode_avail ==0 || decode_avail ==0 ||
        (!encode_buf) || (!decode_buf))
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of base64 data spanned across packets*/
    if ( prev_encoded_bytes )
    {
        if (prev_encoded_bytes > encode_avail)
            prev_encoded_bytes = encode_avail;

        if (prev_encoded_buf)
        {
            prev_bytes = prev_encoded_bytes;
            encode_avail = encode_avail - prev_bytes;
            while (prev_encoded_bytes)
            {
                /* Since this data cannot be more than 3 bytes*/
                encode_buf[i] = prev_encoded_buf[i];
                i++;
                prev_encoded_bytes--;
            }
        }
    }

    if (sf_strip_LWS(start, (end-start), encode_buf + prev_bytes, encode_avail,
        &act_encode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + prev_bytes;

    if (sf_qpdecode((char*)encode_buf, act_encode_size, (char*)decode_buf, decode_avail,
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
        prev_encoded_buf = encode_buf + bytes_read;
        act_encode_size = bytes_read;
    }

    decode_present = 1;
    decodePtr = decode_buf;
    decoded_bytes = act_decode_size;
    qp_state.encode_bytes_read += act_encode_size;
    qp_state.decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

DecodeResult MimeDecode::UUDecode(const uint8_t* start, const uint8_t* end)
{
    uint32_t encode_avail = 0, decode_avail = 0;
    uint8_t* encode_buf, * decode_buf;
    uint32_t act_encode_size = 0, act_decode_size = 0, bytes_read = 0;
    uint32_t prev_bytes = 0;
    uint32_t i = 0;

    if (!(uu_state.encode_depth))
    {
        encode_avail = decode_avail = buf_size;
    }
    else if ((uu_state.encode_depth) < 0)
    {
        uu_state.begin_found = 0;
        return DECODE_EXCEEDED;
    }
    else
    {
        encode_avail = uu_state.encode_depth - uu_state.encode_bytes_read;
        decode_avail = uu_state.decode_depth - uu_state.decode_bytes_read;
    }

    encode_buf = encodeBuf;
    decode_buf = decodeBuf;

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if (encode_avail ==0 || decode_avail ==0 ||
        (!encode_buf) || (!decode_buf))
    {
        uu_state.begin_found = 0;
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of base64 data spanned across packets*/
    if ( prev_encoded_bytes )
    {
        if (prev_encoded_bytes > encode_avail)
            prev_encoded_bytes = encode_avail;

        if (prev_encoded_buf)
        {
            prev_bytes = prev_encoded_bytes;
            encode_avail = encode_avail - prev_bytes;
            while (prev_encoded_bytes)
            {
                /* Since this data cannot be more than 3 bytes*/
                encode_buf[i] = prev_encoded_buf[i];
                i++;
                prev_encoded_bytes--;
            }
        }
    }

    if ((uint32_t)(end- start) > encode_avail)
        act_encode_size = encode_avail;
    else
        act_encode_size = end - start;

    if (encode_avail > 0)
    {
        if (SafeMemcpy((encode_buf + prev_bytes), start, act_encode_size, encode_buf, (encode_buf+
            encode_avail + prev_bytes)) != SAFEMEM_SUCCESS)
        {
            reset_decode_state();
            return DECODE_FAIL;
        }
    }

    act_encode_size = act_encode_size + prev_bytes;

    if (sf_uudecode(encode_buf, act_encode_size, decode_buf, decode_avail, &bytes_read,
        &act_decode_size,
        &(uu_state.begin_found), &(uu_state.end_found)) != 0)
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

    if (uu_state.end_found)
    {
        uu_state.end_found = 0;
        uu_state.begin_found = 0;
    }

    if (bytes_read < act_encode_size)
    {
        prev_encoded_bytes = (act_encode_size - bytes_read);
        prev_encoded_buf = encode_buf + bytes_read;
        act_encode_size = bytes_read;
    }

    decode_present = 1;
    decoded_bytes = act_decode_size;
    decodePtr = decode_buf;
    uu_state.encode_bytes_read += act_encode_size;
    uu_state.decode_bytes_read += act_decode_size;

    return DECODE_SUCCESS;
}

DecodeResult MimeDecode::BitEncExtract(const uint8_t* start, const uint8_t* end)
{
    uint32_t bytes_avail = 0;
    uint32_t act_size = 0;

    ClearPrevEncodeBuf();

    if (!(bitenc_state.depth))
    {
        bytes_avail = buf_size;
    }
    // FIXIT-L this check on start should be obviated by use better member functions
    else if ( bitenc_state.depth < 0 )
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        bytes_avail = bitenc_state.depth - bitenc_state.bytes_read;
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

    decode_present = 1;
    decoded_bytes = act_size;
    decodePtr = (uint8_t*)start;
    bitenc_state.bytes_read += act_size;

    return DECODE_SUCCESS;
}

void MimeDecode::process_decode_type(const char* start, int length, bool cnt_xf)
{
    const char* tmp = NULL;

    if (cnt_xf)
    {
        if (b64_state.encode_depth > -1)
        {
            tmp = SnortStrcasestr(start, length, "base64");
            if ( tmp != NULL )
            {
                decode_type = DECODE_B64;
                return;
            }
        }

        if (qp_state.encode_depth > -1)
        {
            tmp = SnortStrcasestr(start, length, "quoted-printable");
            if ( tmp != NULL )
            {
                decode_type = DECODE_QP;
                return;
            }
        }

        if (uu_state.encode_depth > -1)
        {
            tmp = SnortStrcasestr(start, length, "uuencode");
            if ( tmp != NULL )
            {
                decode_type = DECODE_UU;
                return;
            }
        }
    }

    if (bitenc_state.depth > -1)
    {
        decode_type = DECODE_BITENC;
        return;
    }
}

DecodeResult MimeDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    DecodeResult iRet = DECODE_FAIL;

    switch (decode_type)
    {
    case DECODE_B64:
        iRet = Base64Decode(start, end);
        break;
    case DECODE_QP:
        iRet = QPDecode(start, end);
        break;
    case DECODE_UU:
        iRet = UUDecode(start, end);
        break;
    case DECODE_BITENC:
        iRet = BitEncExtract(start, end);
        break;
    default:
        break;
    }

    return iRet;
}

int MimeDecode::get_detection_depth(int b64_depth, int qp_depth, int uu_depth, int bitenc_depth)
{
    int iRet = 0;

    switch (decode_type)
    {
    case DECODE_B64:
        iRet = limitDetection(b64_depth, decoded_bytes, b64_state.decode_bytes_read);
        break;
    case DECODE_QP:
        iRet = limitDetection(qp_depth, decoded_bytes, qp_state.decode_bytes_read);
        break;
    case DECODE_UU:
        iRet = limitDetection(uu_depth, decoded_bytes, uu_state.decode_bytes_read);
        break;
    case DECODE_BITENC:
        iRet = limitDetection(bitenc_depth, decoded_bytes, bitenc_state.bytes_read);
        break;
    default:
        break;
    }

    return iRet;
}

int MimeDecode::get_decoded_data(uint8_t** buf,  uint32_t* size)
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

DecodeType MimeDecode::get_decode_type()
{
    return decode_type;
}

MimeDecode::MimeDecode(
    int max_depth, int b64_depth, int qp_depth,
    int uu_depth, int bitenc_depth, int64_t file_depth)
{
    work_buffer = (uint8_t*)SnortAlloc(2*max_depth);

    decode_type = DECODE_NONE;
    decode_present = 0;
    prev_encoded_bytes = 0;
    prev_encoded_buf = nullptr;
    decoded_bytes = 0;
    buf_size = max_depth;

    encodeBuf = (uint8_t*)work_buffer;
    decodeBuf = (uint8_t*)work_buffer + max_depth;

    b64_state.encode_depth = b64_state.decode_depth = getCodeDepth(b64_depth, file_depth);
    b64_state.encode_bytes_read = b64_state.decode_bytes_read = 0;

    qp_state.encode_depth = qp_state.decode_depth = getCodeDepth(qp_depth, file_depth);
    qp_state.encode_bytes_read = qp_state.decode_bytes_read = 0;

    uu_state.encode_depth = uu_state.decode_depth = getCodeDepth(uu_depth, file_depth);
    uu_state.encode_bytes_read = uu_state.decode_bytes_read = 0;
    uu_state.begin_found = 0;
    uu_state.end_found = 0;

    bitenc_state.depth = getCodeDepth(bitenc_depth, file_depth);
    bitenc_state.bytes_read = 0;
}

MimeDecode::~MimeDecode()
{
    if (work_buffer)
        free(work_buffer);
}
