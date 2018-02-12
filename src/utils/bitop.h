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

// Author: Bhagya Bantwal <bbantwal@cisco.com>
// Based on work by:
// Dan Roelker <droelker@sourcefire.com> and Marc Norton <mnorton@sourcefire.com>

#ifndef BITOP_H
#define BITOP_H

// A simple, dynamically sized bit vector implementation

#include <cassert>
#include <cstdint>
#include <cstring>

class BitOp
{
public:
    BitOp(size_t);
    ~BitOp();

    BitOp(const BitOp&) = delete;
    BitOp& operator=(const BitOp&) = delete;

    void reset();
    void set(unsigned int bit);
    bool is_set(unsigned int bit) const;
    void clear(unsigned int bit);

    size_t size() const;

    // FIXIT-L add operator overloads for [], &=, |=, etc
    size_t get_buf_size() const;
    uint8_t& get_buf_element(size_t);
    const uint8_t& get_buf_element(size_t) const;

private:
    uint8_t mask(size_t bit) const;

    uint8_t* bit_buf;
    const size_t buf_size;
};

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

inline BitOp::BitOp(size_t len) :
    buf_size(len ? (len + 7) >> 3 : 1)
{
    bit_buf = new uint8_t[len]();
}

inline BitOp::~BitOp()
{ delete[] bit_buf; }

inline uint8_t BitOp::mask(size_t bit) const
{ return (uint8_t)(0x80 >> (bit & 7)); }

// Reset the bit buffer so that it can be reused
inline void BitOp::reset()
{ memset(bit_buf, 0, buf_size); }

// Set the bit in the specified position within the bit buffer.
inline void BitOp::set(unsigned int bit)
{
    assert(size() > bit);
    bit_buf[bit >> 3] |= mask(bit);
}

// Checks if the bit at the specified position is set
inline bool BitOp::is_set(unsigned int bit) const
{
    assert(size() > bit);
    return mask(bit) & bit_buf[bit >> 3];
}

// Clear the bit in the specified position within the bit buffer.
inline void BitOp::clear(unsigned int bit)
{
    assert(size() > bit);
    bit_buf[bit >> 3] &= ~mask(bit);
}

inline size_t BitOp::size() const
{ return buf_size << 3; }

inline size_t BitOp::get_buf_size() const
{ return buf_size; }

inline uint8_t& BitOp::get_buf_element(size_t i)
{ return bit_buf[i]; }

inline const uint8_t& BitOp::get_buf_element(size_t i) const
{ return bit_buf[i]; }

#endif

