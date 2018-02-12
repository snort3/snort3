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
// decode_base.cc author Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode_base.h"

void DataDecode::reset_decoded_bytes()
{
    decodePtr = nullptr;
    decoded_bytes = 0;
}

void DataDecode::reset_decode_state()
{
    reset_decoded_bytes();
    decode_bytes_read = 0;
}

int DataDecode::get_detection_depth()
{
    // unlimited
    if (!detection_depth)
        return decoded_bytes;
    // exceeded depth before (decode_bytes_read has been updated)
    else if (detection_depth < (int64_t)decode_bytes_read - decoded_bytes)
        return 0;
    // lower than depth
    else if (detection_depth > (int64_t)decode_bytes_read)
        return decoded_bytes;
    // cut off
    else
        return (detection_depth + (int64_t )decoded_bytes - decode_bytes_read);
}

int DataDecode::get_decoded_data(const uint8_t** buf,  uint32_t* size)
{
    if (decoded_bytes > 0)
        *size = decoded_bytes;
    else
        return 0;

    if (decodePtr != nullptr)
        *buf = decodePtr;
    else
        return 0;

    return (*size);
}

DataDecode::DataDecode(int, int detect_depth)
{
    detection_depth = detect_depth;
    decode_bytes_read = 0;
    decoded_bytes = 0;
}

