//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// memory_cap.cc author Joel Cornett <jocornet@cisco.com>

#include "memory_cap.h"

#include "profiler/memory_profiler_active_context.h"

namespace memory
{

bool DefaultCap::free_space(size_t)
{
    // FIXIT-M J add debug logging
    return true;
}

// FIXIT-H J add thread-local memory tracking
void DefaultCap::update_allocations(size_t n)
{ mp_active_context.update_allocs(n); }

// FIXIT-H J add thread-local memory tracking
void DefaultCap::update_deallocations(size_t n)
{ mp_active_context.update_deallocs(n); }

} // namespace memory
