//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// util_ber.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ber.h"

namespace snort
{

bool BerReader::read_int(uint32_t size, uint32_t& intval)
{
    unsigned bytes = 0;

    intval = 0;

    // cursor must be valid
    if ( cursor < beg || cursor > end )
        return false;

    // check if we can read int data
    if ( size > end - cursor )
        return false;

    for ( unsigned i = 0; i < size; i++ )
    {
        uint8_t b = *cursor++;

        // handle null padding
        if ( bytes == 0 && b == 0 )
            continue;

        intval <<= 8;
        intval |= b;
        bytes++;

        // check if int fits into uint32_t
        if ( bytes > 4 )
            return false;
    }

    return true;
}

bool BerReader::read_type(uint32_t& type)
{
    unsigned bytes = 0;
    uint8_t b;

    type = 0;

    // cursor must be valid
    if ( cursor < beg || cursor + 1 > end )
        return false;

    b = *cursor++;

    if ( (b & 0x1F) != 0x1F )
    {
        // short-form type
        type = b;
        return true;
    }

    // long-form type
    while ( true )
    {
        if ( cursor + 1 > end )
            return false;

        b = *cursor++;

        // handle null padding
        if ( bytes == 0 && b == 0x80 )
            continue;

        type <<= 7;
        type |= b & 0x7F;
        bytes++;

        // check if type fits into uint32_t
        if ( bytes > 4 )
            return false;

        // check continuation bit
        if ( (b & 0x80) == 0 )
            break;
    }

    return true;
}

bool BerReader::read_length(uint32_t& length)
{
    unsigned size;
    uint8_t b;

    length = 0;

    // cursor must be valid
    if ( cursor < beg || cursor + 1 > end )
        return false;

    b = *cursor++;

    if ( (b & 0x80) == 0 )
    {
        // short-form length
        length = b;
        return true;
    }

    // long-form length
    size = b & 0x7F;

    if ( size == 0 )
        return false;

    if ( !read_int(size, length) )
        return false;

    return true;
}

bool BerReader::read(const uint8_t* c, BerElement& e)
{
    const uint8_t* start = c;

    cursor = c;

    if ( !read_type(e.type) )
        return false;

    if ( !read_length(e.length) )
        return false;

    // set BER data pointer
    e.data = cursor;

    // integer underflow check
    if ( start > cursor )
        return false;

    // calculate BER header length
    e.header_length = cursor - start;

    // calculate total BER length
    e.total_length = e.header_length + e.length;

    // integer overflow check
    if ( e.total_length < e.header_length )
        return false;

    return true;
}

bool BerReader::convert(const BerElement& e, uint32_t& intval)
{
    if ( e.type != BerType::INTEGER )
        return false;

    // set cursor to int data
    cursor = e.data;

    if ( !read_int(e.length, intval) )
        return false;

    return true;
}

bool BerReader::extract(const uint8_t*& c, uint32_t& intval)
{
    BerElement e;

    if ( !read(c, e) )
        return false;

    if ( !convert(e, intval) )
        return false;

    // save end of element position
    c = cursor;

    return true;
}

bool BerReader::skip(const uint8_t*& c, uint32_t type)
{
    BerElement e;

    if ( !read(c, e) )
        return false;

    if ( e.type != type )
        return false;

    // integer underflow check
    if ( cursor > end )
        return false;

    // check if we can jump BER data
    if ( e.length > end - cursor )
        return false;

    // jump BER data
    cursor += e.length;

    // save end of element position
    c = cursor;

    return true;
}

bool BerReader::data(const uint8_t*& c, uint32_t type)
{
    BerElement e;

    if ( !read(c, e) )
        return false;

    if ( e.type != type )
        return false;

    c = e.data;

    return true;
}

}

