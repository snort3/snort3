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

#ifndef DECODE_BASE_H
#define DECODE_BASE_H

// Email attachment decoder

#include <cstdint>

enum DecodeResult
{
    DECODE_SUCCESS,
    DECODE_EXCEEDED, // Decode Complete when we reach the max depths
    DECODE_FAIL
};

class DataDecode
{
public:
    DataDecode(int max_depth, int detect_depth);
    virtual ~DataDecode() = default;

    // Main function to decode file data
    virtual DecodeResult decode_data(const uint8_t* start, const uint8_t* end) = 0;

    // Retrieve the decoded data the previous decode_data() call
    int get_decoded_data(const uint8_t** buf,  uint32_t* size);

    virtual void reset_decoded_bytes();

    virtual void reset_decode_state();

    // Used to limit number of bytes examined for rule evaluation
    int get_detection_depth();

protected:
    uint32_t decoded_bytes = 0;
    uint32_t decode_bytes_read;
    const uint8_t* decodePtr = nullptr;
    int detection_depth;
};

#endif

