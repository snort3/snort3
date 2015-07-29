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
// sf_email_attach_decode.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef FILE_MIME_DECODE_H
#define FILE_MIME_DECODE_H

// Email attachment decoder, supports Base64, QP, UU, and Bit7/8

#include <stdlib.h>

#include "main/snort_types.h"

typedef enum
{
    DECODE_SUCCESS,
    DECODE_EXCEEDED, // Decode Complete when we reach the max depths
    DECODE_FAIL
} DecodeResult;

typedef enum
{
    DECODE_NONE = 0,
    DECODE_B64,
    DECODE_QP,
    DECODE_UU,
    DECODE_BITENC,
    DECODE_ALL
} DecodeType;

struct Base64_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
};

struct QP_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
};

struct UU_DecodeState
{
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
    uint8_t begin_found;
    uint8_t end_found;
};

struct BitEnc_DecodeState
{
    uint32_t bytes_read;
    int depth;
};

class MimeDecode
{
public:
    MimeDecode(int max_depth, int b64_depth, int qp_depth,
        int uu_depth, int bitenc_depth, int64_t file_depth);
    ~MimeDecode();

    // get the decode type from buffer
    // bool cnt_xf: true if there is transfer encode defined, false otherwise
    void process_decode_type(const char* start, int length, bool cnt_xf);

    // Main function to decode file data
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end);

    // Retrieve the decoded data the previous decode_data() call
    int get_decoded_data(uint8_t** buf,  uint32_t* size);

    int get_detection_depth(int b64_depth, int qp_depth, int uu_depth, int bitenc_depth);

    void clear_decode_state();
    void reset_decoded_bytes();
    void reset_bytes_read();

    DecodeType get_decode_type();

private:
    uint8_t* work_buffer = NULL;
    DecodeType decode_type = DECODE_NONE;
    uint8_t decode_present;
    uint32_t prev_encoded_bytes;
    uint32_t decoded_bytes = 0;
    uint32_t buf_size;
    uint8_t* prev_encoded_buf;
    uint8_t* encodeBuf;
    uint8_t* decodeBuf;
    uint8_t* decodePtr = NULL;
    Base64_DecodeState b64_state;
    QP_DecodeState qp_state;
    UU_DecodeState uu_state;
    BitEnc_DecodeState bitenc_state;
    int get_code_depth(int code_depth, int64_t file_depth);
    inline void clear_prev_encode_buf();
    inline void reset_decode_state();
    DecodeResult Base64_decode(const uint8_t* start, const uint8_t* end);
    DecodeResult QP_decode(const uint8_t* start, const uint8_t* end);
    DecodeResult UU_decode(const uint8_t* start, const uint8_t* end);
    DecodeResult BitEnc_extract(const uint8_t* start, const uint8_t* end);
};

// Todo: add statistics
//struct MimeStats
//{
//    uint64_t memcap_exceeded;
//    uint64_t attachments[DECODE_ALL];
//    uint64_t decoded_bytes[DECODE_ALL];
//};

#endif

