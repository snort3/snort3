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
// hyper_search.h author Russ Combs <rucombs@cisco.com>

#ifndef HYPER_SEARCH_H
#define HYPER_SEARCH_H

// Hyperscan-based literal content matching (single pattern)
// use LiteralSearch::instantiate to fallback to boyer-moore
// if hyperscan is not available.

#include "helpers/literal_search.h"
#include "main/snort_types.h"

extern "C" struct hs_database;

namespace snort
{

class SO_PUBLIC HyperSearch : public snort::LiteralSearch
{
public:
    using Handle = snort::LiteralSearch::Handle;

    static Handle* setup();        // call from module ctor
    static void cleanup(Handle*);  // call from module dtor

    HyperSearch(Handle*, const uint8_t* pattern, unsigned pattern_len, bool no_case = false);
    ~HyperSearch() override;

    int search(Handle*, const uint8_t* buffer, unsigned buffer_len) const override;

private:
    struct hs_database* db;
    unsigned pattern_len;
};

}
#endif

