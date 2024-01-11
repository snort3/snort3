//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef HASH_KEY_OPERATIONS_H
#define HASH_KEY_OPERATIONS_H

#include "main/snort_types.h"

namespace
{
    inline uint32_t rot(uint32_t x, unsigned k) { return (x << k) | (x >> (32 - k)); }
    inline void mix(uint32_t& a, uint32_t& b, uint32_t& c)
    {
        a -= c; a ^= rot(c, 4); c += b;
        b -= a; b ^= rot(a, 6); a += c;
        c -= b; c ^= rot(b, 8); b += a;
        a -= c; a ^= rot(c,16); c += b;
        b -= a; b ^= rot(a,19); a += c;
        c -= b; c ^= rot(b, 4); b += a;
    }
    inline void finalize(uint32_t& a, uint32_t& b, uint32_t& c)
    {
        c ^= b; c -= rot(b,14);
        a ^= c; a -= rot(c,11);
        b ^= a; b -= rot(a,25);
        c ^= b; c -= rot(b,16);
        a ^= c; a -= rot(c,4);
        b ^= a; b -= rot(a,14);
        c ^= b; c -= rot(b,24);
    }
}

namespace snort
{
SO_PUBLIC void mix_str(
    uint32_t& a, uint32_t& b, uint32_t& c,
    // n == 0 => strlen(s)
    const char* s, unsigned n = 0);

SO_PUBLIC uint32_t str_to_hash(const uint8_t *str, size_t length);

static inline int hash_nearest_power_of_2(int nrows)
{
    nrows -= 1;
    for (unsigned i = 1; i < sizeof(nrows) * 8; i <<= 1)
        nrows = nrows | (nrows >> i);
    nrows += 1;

    return nrows;
}

static inline uint64_t hash_mac(const uint8_t* a)
{
    uint64_t hash = a[0];
    hash = (hash << 8) | a[1];
    hash = (hash << 8) | a[2];
    hash = (hash << 8) | a[3];
    hash = (hash << 8) | a[4];
    hash = (hash << 8) | a[5];
    return hash;
}

class HashKeyOperations
{
public:
    HashKeyOperations(int rows);
    virtual ~HashKeyOperations() = default;

    virtual unsigned do_hash(const unsigned char* key, int len);
    virtual bool key_compare(const void* key1, const void* key2, size_t len);

protected:
    unsigned seed;
    unsigned scale;
    unsigned hardener;
};
}

#endif

