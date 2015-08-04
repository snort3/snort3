//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "utils/util.h"

class BitOp
{
public:
    BitOp(unsigned int len)
    {
        assert(len);

        bit_buf = (uint8_t*)SnortAlloc(len);

        buf_size = (unsigned int)len;
        max_bits = (unsigned int)(len << 3);
    }

    ~BitOp()
    {
        free(bit_buf);
    }

    void reset();
    void set(unsigned int bit);
    bool is_set(unsigned int bit);
    void clear(unsigned int bit);

    unsigned int get_max_bits()
    { return max_bits; }

    //FIXIT-L This should be eliminated and better encapsulated.
    uint8_t& operator[](unsigned int pos)
    { if ( pos > buf_size) pos = 0; return bit_buf[pos]; }

private:
    uint8_t* bit_buf;
    unsigned int buf_size;
    unsigned int max_bits;
};

// Reset the bit buffer so that it can be reused
inline void BitOp::reset()
{
    memset(bit_buf, 0, buf_size);
}

// Set the bit in the specified position within the bit buffer.
inline void BitOp::set(unsigned int bit)
{
    if ( max_bits <= bit )
    {
        assert(false);
        return;
    }
    uint8_t mask = (uint8_t)(0x80 >> (bit & 7));
    bit_buf[bit >> 3] |= mask;
}

// Checks if the bit at the specified position is set
inline bool BitOp::is_set(unsigned int bit)
{
    if ( max_bits <= bit )
    {
        assert(false);
        return false;
    }
    uint8_t mask = (uint8_t)(0x80 >> (bit & 7));
    return (mask & bit_buf[bit >> 3]);
}

// Clear the bit in the specified position within the bit buffer.
inline void BitOp::clear(unsigned int bit)
{
    if ( max_bits <= bit )
    {
        assert(false);
        return;
    }
    uint8_t mask = (uint8_t)(0x80 >> (bit & 7));
    bit_buf[bit >> 3] &= ~mask;
}

#endif

