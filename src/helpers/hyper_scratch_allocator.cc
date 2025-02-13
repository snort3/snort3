//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// hyper_scratch_allocator.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hyper_scratch_allocator.h"
#include "log/messages.h"

namespace snort
{

HyperScratchAllocator::~HyperScratchAllocator()
{
    if ( scratch )
        hs_free_scratch(scratch);
}

bool HyperScratchAllocator::allocate(hs_database_t* db)
{
    return hs_alloc_scratch(db, &scratch) == HS_SUCCESS;
}

bool HyperScratchAllocator::setup(SnortConfig* sc)
{
    if ( !scratch )
        return false;

    for ( unsigned i = 0; i < sc->num_slots; ++i )
        hs_clone_scratch(scratch, get_addr(sc, i));

    hs_free_scratch(scratch);
    scratch = nullptr;

    return true;
}

void HyperScratchAllocator::cleanup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        hs_scratch_t* ss = get(sc, i);
        hs_free_scratch(ss);
        set(sc, i, nullptr);
    }
}

}

