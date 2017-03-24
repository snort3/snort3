//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SFHASHFCN_H
#define SFHASHFCN_H

#include "main/snort_types.h"

#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

#define mix(a,b,c) \
{ \
    a -= c;  a ^= rot(c, 4);  c += b; \
    b -= a;  b ^= rot(a, 6);  a += c; \
    c -= b;  c ^= rot(b, 8);  b += a; \
    a -= c;  a ^= rot(c,16);  c += b; \
    b -= a;  b ^= rot(a,19);  a += c; \
    c -= b;  c ^= rot(b, 4);  b += a; \
}

#define finalize(a,b,c) \
{ \
    c ^= b; c -= rot(b,14); \
    a ^= c; a -= rot(c,11); \
    b ^= a; b -= rot(a,25); \
    c ^= b; c -= rot(b,16); \
    a ^= c; a -= rot(c,4);  \
    b ^= a; b -= rot(a,14); \
    c ^= b; c -= rot(b,24); \
}

SO_PUBLIC void mix_str(
    uint32_t& a, uint32_t& b, uint32_t& c,
    // n == 0 => strlen(s)
    const char* s, unsigned n = 0);

SO_PUBLIC size_t str_to_hash(const uint8_t *str, int length);

struct SFHASHFCN
{
    unsigned seed;
    unsigned scale;
    unsigned hardener;
    // FIXIT-H use types for these callbacks
    unsigned (* hash_fcn)(SFHASHFCN*, unsigned char* d, int n);
    int (* keycmp_fcn)(const void* s1, const void* s2, size_t n);
};

SFHASHFCN* sfhashfcn_new(int nrows);
void sfhashfcn_free(SFHASHFCN*);

unsigned sfhashfcn_hash(SFHASHFCN*, unsigned char* d, int n);

int sfhashfcn_set_keyops(
    SFHASHFCN*,
    // FIXIT-H use types for these callbacks
    unsigned (* hash_fcn)(SFHASHFCN* p, unsigned char* d, int n),
    int (* keycmp_fcn)(const void* s1, const void* s2, size_t n) );

#endif

