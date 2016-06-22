//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <mime/decode_base.h>
#include "utils/util.h"

void DataDecode::reset_decoded_bytes()
{
    decodePtr = nullptr;
    decoded_bytes = 0;
}

void DataDecode::reset_decode_state()
{
    reset_decoded_bytes();
}

int DataDecode::get_detection_depth()
{
    // unlimited
    if (!decode_depth)
        return decoded_bytes;
    // exceeded depth before (decode_bytes_read has been updated)
    else if (decode_depth < (int64_t)decode_bytes_read - decoded_bytes)
        return 0;
    // lower than depth
    else if (decode_depth > (int64_t)decode_bytes_read)
        return decoded_bytes;
    // cut off
    else
        return (decode_depth + (int64_t )decoded_bytes - decode_bytes_read);
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

    return (*size);
}

#define MAX_DEPTH       65536

DataDecode::DataDecode(int max_depth)
{
    decode_depth = max_depth;
    decode_bytes_read = 0;
    decoded_bytes = 0;
}

DataDecode::~DataDecode()
{

}
