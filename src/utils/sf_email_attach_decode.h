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

#ifndef SF_EMAIL_ATTACH_DECODE_H
#define SF_EMAIL_ATTACH_DECODE_H

// Email attachment decoder

#include <stdlib.h>

#include "main/snort_types.h"

typedef enum
{
    DECODE_SUCCESS,
    DECODE_EXCEEDED, // Decode Complete when we reach the max depths
    DECODE_FAIL
} DecodeResult;

class DataDecode
{
public:
    DataDecode(int max_depth);
    virtual ~DataDecode();

    // Main function to decode file data
    virtual DecodeResult decode_data(const uint8_t* start, const uint8_t* end) = 0;

    // Retrieve the decoded data the previous decode_data() call
    int get_decoded_data(uint8_t** buf,  uint32_t* size);

    void reset_decoded_bytes();
    virtual void reset_decode_state();
    int get_detection_depth(int depth);

protected:
    uint8_t* work_buffer = NULL;
    uint32_t prev_encoded_bytes;
    uint32_t decoded_bytes = 0;
    uint32_t buf_size;
    uint8_t* prev_encoded_buf;
    uint8_t* encodeBuf;
    uint8_t* decodeBuf;
    uint8_t* decodePtr = NULL;
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
    bool check_buffer();
    inline void clear_prev_encode_buf();

};

class B64Decode:public DataDecode
{
public:
    using DataDecode::DataDecode;
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end) override;
};

class QPDecode:public DataDecode
{
public:
    using DataDecode::DataDecode;
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end) override;
};

class UUDecode:public DataDecode
{
public:
    using DataDecode::DataDecode;
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end) override;
    void reset_decode_state() override;
private:
    bool begin_found = false;
    bool end_found = false;
};

class BitDecode:public DataDecode
{
public:
    using DataDecode::DataDecode;
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end) override;
};

int sf_qpdecode(char* src, uint32_t slen, char* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied);

int sf_uudecode(uint8_t* src, uint32_t slen, uint8_t* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied, bool* begin_found, bool* end_found);

#endif

