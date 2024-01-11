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
// hyper_search.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hyper_search.h"

#include <cassert>
#include <cctype>
#include <cstring>

#include <hs_compile.h>
#include <hs_runtime.h>

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "utils/util.h"

#include "hyper_scratch_allocator.h"

namespace snort
{

LiteralSearch::Handle* HyperSearch::setup()
{ return new HyperScratchAllocator; }

void HyperSearch::cleanup(LiteralSearch::Handle* h)
{
    HyperScratchAllocator* scratcher = (HyperScratchAllocator*)h;
    delete scratcher;
}

//--------------------------------------------------------------------------

HyperSearch::HyperSearch(LiteralSearch::Handle* h, const uint8_t* pattern, unsigned len, bool no_case)
{
    assert(h);
    HyperScratchAllocator* scratcher = (HyperScratchAllocator*)h;

    assert(len > 0);
    pattern_len = len;

    hs_compile_error_t* err = nullptr;

    unsigned flags = HS_FLAG_SINGLEMATCH;
    if ( no_case )
        flags |= HS_FLAG_CASELESS;

#ifndef HAVE_HS_COMPILE_LIT
    std::string hex_pat;

    for ( unsigned i = 0; i < len; ++i )
    {
        char hex[5];
        snprintf(hex, sizeof(hex), "\\x%02X", pattern[i]);
        hex_pat += hex;
    }

    if ( hs_compile((const char*)hex_pat.c_str(), flags,
        HS_MODE_BLOCK, nullptr, (hs_database_t**)&db, &err) != HS_SUCCESS )
#else
    if ( hs_compile_lit((const char*)pattern, flags, pattern_len,
        HS_MODE_BLOCK, nullptr, (hs_database_t**)&db, &err) != HS_SUCCESS )
#endif
    {
        std::string print_str;
        uint8_to_printable_str(pattern, len, print_str);
        ParseError("can't compile content '%s'", print_str.c_str());
        hs_free_compile_error(err);
        return;
    }
    if ( !scratcher->allocate(db) )
    {
        std::string print_str;
        uint8_to_printable_str(pattern, len, print_str);
        ParseError("can't allocate scratch for content '%s'", print_str.c_str());
    }
}

HyperSearch::~HyperSearch()
{
    if ( db )
        hs_free_database(db);
}

}

struct ScanContext
{
    unsigned index;
    bool found = false;
};

static int hs_match(unsigned int, unsigned long long, unsigned long long to, unsigned int, void* context)
{
    ScanContext* scan = (ScanContext*)context;
    scan->index = (unsigned)to;
    scan->found = true;
    return 1;
}

namespace snort
{

int HyperSearch::search(LiteralSearch::Handle* h, const uint8_t* buffer, unsigned buffer_len) const
{
    HyperScratchAllocator* scratcher = (HyperScratchAllocator*)h;
    ScanContext scan;
    hs_scan(db, (const char*)buffer, buffer_len, 0, scratcher->get(), hs_match, &scan);
    return scan.found ? ((int)(scan.index - pattern_len)) : -1;
}

}

