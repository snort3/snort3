//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash_key_operations.h"

#include <cassert>

#include "main/snort_config.h"
#include "utils/util.h"

#include "primetable.h"

using namespace snort;

HashKeyOperations::HashKeyOperations(int rows)
{
    static bool one = true;

    if ( one ) /* one time init */
    {
        srand( (unsigned)time(nullptr) );
        one = false;
    }

    if ( SnortConfig::static_hash() )
    {
        seed = 3193;
        scale = 719;
        hardener = 133824503;
    }
    else
    {
        seed = nearest_prime( (rand() % rows) + 3191);
        scale = nearest_prime( (rand() % rows) + 709);
        hardener = ((unsigned) rand() * rand()) + 133824503;
    }
}

unsigned HashKeyOperations::do_hash(const unsigned char* key, int len)
{
    unsigned hash = seed;
    while ( len )
    {
        hash *= scale;
        hash += *key++;
        len--;
    }
    return hash ^ hardener;
}

bool HashKeyOperations::key_compare(const void* key1, const void* key2, size_t len)
{
    if ( memcmp(key1, key2, len) )
        return false;
    else
        return true;
}

namespace snort
{
void mix_str(uint32_t& a, uint32_t& b, uint32_t& c, const char* s, unsigned n)
{
    unsigned i, j;

    if ( !n )
        n = strlen(s);

    for ( i=0,j=0; i<n; i+=4 )
    {
        uint32_t tmp = 0;
        unsigned k = n - i;

        if (k > 4)
            k=4;

        for (unsigned l=0; l<k; l++)
            tmp |= (unsigned char) s[i + l] << l*8;

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j = 0;
        }
    }

    if (j != 0)
        mix(a,b,c);
}

uint32_t str_to_hash(const uint8_t *str, size_t length)
{
    uint32_t a = 0, b = 0, c = 0;

    for (size_t i = 0, j = 0; i < length; i += 4)
    {
        uint32_t tmp = 0;
        size_t k = length - i;

        if (k > 4)
            k = 4;

        for (size_t m = 0; m < k; m++)
            tmp |= *(str + i + m) << m * 8;

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a, b, c);
            j = 0;
        }
    }

    finalize(a, b, c);
    return c;
}
} //namespace snort
