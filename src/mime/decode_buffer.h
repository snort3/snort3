//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// Hui Cao <huica@cisco.com>

#ifndef DECODE_BUFFER_H
#define DECODE_BUFFER_H

// Manage decode/encode buffers

#include "main/snort_types.h"

class DecodeBuffer
{
public:
    DecodeBuffer(int max_depth);
    ~DecodeBuffer();

    // Make sure buffer is available and restore the buffer saved
    bool check_restore_buffer();

    // Save buffer for future use (restore)
    void save_buffer(uint8_t* buff, uint32_t buff_size);

    // Move forward buffer pointer
    void update_buffer(uint32_t act_encode_size, uint32_t act_decode_size);

    void reset_saved();
    uint8_t* get_decode_buff() { return decodeBuf; }
    uint8_t* get_encode_buff() { return encodeBuf; }
    uint32_t get_decode_bytes_read() { return decode_bytes_read; }
    uint32_t get_decode_avail();
    uint32_t get_encode_avail();
    uint32_t get_prev_encoded_bytes() { return prev_encoded_bytes; }

private:
    uint32_t buf_size;
    uint32_t prev_encoded_bytes;
    uint8_t* prev_encoded_buf;
    uint8_t* encodeBuf = nullptr;
    uint8_t* decodeBuf = nullptr;
    uint32_t encode_bytes_read;
    uint32_t decode_bytes_read;
    int code_depth;
};

#endif

