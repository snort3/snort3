//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// literal_search.h author Russ Combs <rucombs@cisco.com>

#ifndef LITERAL_SEARCH_H
#define LITERAL_SEARCH_H

// literal content matching (single pattern)
// used eg with content during signature evaluation

#include "main/snort_types.h"

namespace snort
{

class SO_PUBLIC LiteralSearch
{
public:
    using Handle = void;

    static Handle* setup();        // call from module ctor
    static void cleanup(Handle*);  // call from module dtor

    static LiteralSearch* instantiate(
            Handle*, const uint8_t* pattern, unsigned pattern_len, bool no_case = false, bool hs = false);
    virtual ~LiteralSearch() = default;

    virtual int search(Handle*, const uint8_t* buffer, unsigned buffer_len) const = 0;

protected:
    LiteralSearch() = default;
};

}
#endif

