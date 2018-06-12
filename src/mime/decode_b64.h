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

#ifndef DECODE_B64_H
#define DECODE_B64_H

// Email attachment decoder

#include "main/snort_types.h"
#include "mime/decode_base.h"

class B64Decode : public DataDecode
{
public:
    B64Decode(int max_depth, int detect_depth);
    ~B64Decode() override;

    // Main function to decode file data
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end) override;

    void reset_decode_state() override;

private:
    class DecodeBuffer* buffer = nullptr;
};

namespace snort
{
// FIXIT-L inbuf should probably be const uint8_t*
SO_PUBLIC int sf_base64decode(
    uint8_t* inbuf, uint32_t inbuf_size,
    uint8_t* outbuf, uint32_t outbuf_size,
    uint32_t* bytes_written
    );
}
#endif

