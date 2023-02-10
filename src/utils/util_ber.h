//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
// util_ber.h author Brandon Stultz <brastult@cisco.com>

#ifndef UTIL_BER_H
#define UTIL_BER_H

#include "main/snort_types.h"
#include "framework/cursor.h"

namespace snort
{

enum BerType
{
    BOOLEAN = 1,
    INTEGER,
    BIT_STRING,
    STRING,
};

struct BerElement
{
    uint32_t type;
    uint32_t length;
    uint64_t header_length;
    uint64_t total_length;
    const uint8_t* data;
};

class SO_PUBLIC BerReader
{
public:
    BerReader(const Cursor& c)
    {
        beg = c.buffer();
        cursor = c.start();
        end = c.endo();
    }

    bool read(const uint8_t* c, BerElement& e);

    bool convert(const BerElement& e, uint32_t& intval);
    bool extract(const uint8_t*& c, uint32_t& intval);

    bool skip(const uint8_t*& c, uint32_t type);
    bool data(const uint8_t*& c, uint32_t type);

private:
    bool read_int(uint32_t size, uint32_t& intval);

    bool read_type(uint32_t& type);
    bool read_length(uint32_t& length);

    const uint8_t* beg;
    const uint8_t* cursor;
    const uint8_t* end;
};

}
#endif

