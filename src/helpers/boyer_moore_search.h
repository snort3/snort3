//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// boyer_moore_search.h author Brandon Stultz <brastult@cisco.com>

#ifndef BOYER_MOORE_SEARCH_H
#define BOYER_MOORE_SEARCH_H

// Boyer-Moore literal content matching routines (single pattern)
// use LiteralSearch::instantiate to get hyperscan if available

#include "helpers/literal_search.h"
#include "main/snort_types.h"

namespace snort
{

class SO_PUBLIC BoyerMooreSearch : public LiteralSearch
{
protected:
    BoyerMooreSearch(const uint8_t* pattern, unsigned pattern_len);

protected:
    void make_skip();

    const uint8_t* pattern;
    unsigned pattern_len;
    unsigned last;

    unsigned skip[256];
};

class SO_PUBLIC BoyerMooreSearchCase : public BoyerMooreSearch
{
public:
    BoyerMooreSearchCase(const uint8_t* pat, unsigned pat_len) :
        BoyerMooreSearch(pat, pat_len) { }

    int search(const uint8_t* buffer, unsigned buffer_len) const;

    int search(void*, const uint8_t* buffer, unsigned buffer_len) const override
    { return search(buffer, buffer_len); }
};

class SO_PUBLIC BoyerMooreSearchNoCase : public BoyerMooreSearch
{
public:
    BoyerMooreSearchNoCase(const uint8_t* pat, unsigned pat_len) :
        BoyerMooreSearch(pat, pat_len) { }

    int search(const uint8_t* buffer, unsigned buffer_len) const;

    int search(void*, const uint8_t* buffer, unsigned buffer_len) const override
    { return search(buffer, buffer_len); }
};

}
#endif

