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

#include <cassert>

#include "main/snort_config.h"
#include "main/thread.h"
#include "profiler/memory_profiler_active_context.h"
#include "memory_config.h"

namespace memory
{

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

struct Tracker
{
    size_t allocated = 0;
    size_t deallocated = 0;

    size_t used() const
    {
        assert(allocated >= deallocated);
        return allocated - deallocated;
    }

    constexpr Tracker() = default;
};


// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static THREAD_LOCAL Tracker s_tracker;


// -----------------------------------------------------------------------------
// public interface
// -----------------------------------------------------------------------------

bool DefaultCap::free_space(size_t n)
{
    if ( !is_packet_thread() )
        return true;

    const auto& config = *snort_conf->memory;

    if ( !config.enable || !config.cap )
        return true;

    // FIXIT-H call prune handler and attempt to free memory
    return s_tracker.used() + n <= config.cap;
}

void DefaultCap::update_allocations(size_t n)
{
    if ( is_packet_thread() )
        s_tracker.allocated += n;

    mp_active_context.update_allocs(n);
}

void DefaultCap::update_deallocations(size_t n)
{
    if ( is_packet_thread() )
        s_tracker.deallocated += n;

    mp_active_context.update_deallocs(n);
}

} // namespace memory
