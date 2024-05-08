//--------------------------------------------------------------------------
// Copyright (C) 2024-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef DETECTION_BUF_H
#define DETECTION_BUF_H

// buffers used by DetectionEngine and IpsContext

#include <cassert>
#include <cstdint>

#define DECODE_BLEN 65535

struct DataPointer
{
    DataPointer(const uint8_t* d, unsigned l) :
        data(d), len(l) {}
    const uint8_t* data;
    unsigned len;
};

struct DataBuffer
{
    static constexpr unsigned decode_blen = DECODE_BLEN;

    DataBuffer() = default;
    DataBuffer(const DataBuffer&) = delete;
    DataBuffer& operator=(const DataBuffer&) = delete;
    ~DataBuffer()
    { delete [] data; }

    void allocate_data()
    {
        assert(nullptr == data);
        const_cast<uint8_t*&>(data) = new uint8_t[DECODE_BLEN];
    }

    uint8_t* const data = nullptr;
    unsigned len = 0;
};

struct MatchedBuffer
{
    MatchedBuffer(const char* const n, const uint8_t* const d, unsigned s) :
        name(n), data(d), size(s)
    {}
    MatchedBuffer() = delete;

    const char* const name = nullptr;
    const uint8_t* const data = nullptr;
    unsigned size = 0;
};

#endif

