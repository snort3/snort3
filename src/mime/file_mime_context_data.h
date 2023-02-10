//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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
// file_mime_context_data.h author Bhagya Tholpady <bbantwal@cisco.com>

#ifndef FILE_MIME_CONTEXT_DATA_H
#define FILE_MIME_CONTEXT_DATA_H

#include "detection/ips_context_data.h"

class MimeDecodeContextData : public snort::IpsContextData
{
public:
    MimeDecodeContextData();
    ~MimeDecodeContextData() override;

    static unsigned mime_ips_id;

    uint8_t* decode_buf = nullptr;
    uint8_t* decompress_buf = nullptr;
    uint32_t decompress_buf_size = 0;

    static void init();

    static uint8_t* get_decode_buf();
    static uint8_t* get_decompress_buf();
    static uint32_t get_decompress_buf_size();
};

#endif

