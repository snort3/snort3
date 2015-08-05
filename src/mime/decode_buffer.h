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

#ifndef DECODE_BUFFER_H
#define DECODE_BUFFER_H

// Manage decode buffers

#include <stdlib.h>

#include "main/snort_types.h"

class DecodeBuffer
{
public:
    DecodeBuffer(int max_depth);
    ~DecodeBuffer();
    bool is_buffer_available(uint32_t& encode_avail, uint32_t& decode_avail);
    void resume_decode(uint32_t& encode_avail, uint32_t& prev_bytes);
    void save_buffer(uint8_t* buff, uint32_t buff_size);
    void update_buffer(uint32_t act_encode_size, uint32_t act_decode_size);
    void reset();
    uint8_t* get_decode_buff() {return decodeBuf;};
    uint8_t* get_encode_buff() {return encodeBuf;};
    uint32_t get_decode_bytes_read() {return decode_bytes_read;};

private:
    uint32_t buf_size;
    uint32_t prev_encoded_bytes;
    uint8_t* prev_encoded_buf;
    uint8_t* encodeBuf = nullptr;
    uint8_t* decodeBuf = nullptr;
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int encode_depth;
    int decode_depth;
};

#endif

