//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifndef DECODE_UU_H
#define DECODE_UU_H

// UU decoder

#include "mime/decode_base.h"

class UUDecode : public DataDecode
{
public:
    UUDecode(int max_depth, int detect_depth);
    ~UUDecode() override;

    // Main function to decode file data
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end) override;

    void reset_decode_state() override;

private:
    bool begin_found = false;
    bool end_found = false;
    class DecodeBuffer* buffer = nullptr;
};

int sf_uudecode(uint8_t* src, uint32_t slen, uint8_t* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied, bool* begin_found, bool* end_found);

#endif

