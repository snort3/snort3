//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// Author: Bhagya Bantwal <bbantwal@cisco.com>
// Based on work by:
// Dan Roelker <droelker@sourcefire.com> and Marc Norton <mnorton@sourcefire.com>

#ifndef BITOP_H
#define BITOP_H

// A simple, dynamically sized bit vector implementation

#include <cstdint>
#include <vector>

class BitOp
{
public:
    BitOp(size_t bit)
    { bit_buf.resize(index(bit) + 1); }

    ~BitOp() = default;

    BitOp(const BitOp&) = delete;
    BitOp& operator=(const BitOp&) = delete;

    void set(unsigned int bit);
    bool is_set(unsigned int bit) const;
    void clear(unsigned int bit);

private:
    size_t size() const
    { return bit_buf.size(); }

    size_t index(size_t bit) const
    { return (bit + 7) >> 3; }

    uint8_t& byte(size_t bit)
    { return bit_buf[index(bit)]; }

    uint8_t mask(size_t bit) const
    { return (uint8_t)(0x80 >> (bit & 7)); }

    std::vector<uint8_t> bit_buf;
};

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

inline void BitOp::set(unsigned int bit)
{
    if ( index(bit) >= size() )
        bit_buf.resize(index(bit) + 1);
    byte(bit) |= mask(bit);
}

inline bool BitOp::is_set(unsigned int bit) const
{
    if ( index(bit) >= size() )
        return false;
    return bit_buf[index(bit)] & mask(bit);
}

inline void BitOp::clear(unsigned int bit)
{
    if ( index(bit) >= size() )
        return;
    byte(bit) &= ~mask(bit);
}

#endif

