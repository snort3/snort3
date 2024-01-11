//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// boyer_moore_search.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <cctype>

#include "boyer_moore_search.h"

namespace snort
{

BoyerMooreSearch::BoyerMooreSearch(const uint8_t* pattern, unsigned pattern_len)
    : pattern(pattern), pattern_len(pattern_len)
{
    assert(pattern_len > 0);

    last = pattern_len - 1;

    make_skip();
}

// skip[c] is the distance between the last character of the
// pattern and the rightmost occurrence of c in the pattern.
// If c does not occur in the pattern then skip[c] = pattern_len.
void BoyerMooreSearch::make_skip()
{
    for ( unsigned i = 0; i < 256; i++ )
        skip[i] = pattern_len;

    for ( unsigned i = 0; i < last; i++ )
        skip[pattern[i]] = last - i;
}

int BoyerMooreSearchCase::search(const uint8_t* buffer, unsigned buffer_len) const
{
    const uint8_t* start = buffer;

    while ( buffer_len >= pattern_len )
    {
        for ( unsigned pos = last; buffer[pos] == pattern[pos]; pos-- )
            if ( pos == 0 )
                return buffer - start;

        buffer_len -= skip[buffer[last]];
        buffer += skip[buffer[last]];
    }

    return -1;
}

int BoyerMooreSearchNoCase::search(const uint8_t* buffer, unsigned buffer_len) const
{
    const uint8_t* start = buffer;

    while ( buffer_len >= pattern_len )
    {
        for ( unsigned pos = last; toupper(buffer[pos]) == pattern[pos]; pos-- )
            if ( pos == 0 )
                return buffer - start;

        buffer_len -= skip[toupper(buffer[last])];
        buffer += skip[toupper(buffer[last])];
    }

    return -1;
}

}

