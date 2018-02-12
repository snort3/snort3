//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// memory_profiler_active_context.h author Joel Cornett <jocornet@cisco.com>

#ifndef MEMORY_PROFILER_ACTIVE_CONTEXT_H
#define MEMORY_PROFILER_ACTIVE_CONTEXT_H

#include "active_context.h"
#include "memory_defs.h"

class MemoryActiveContext : public ActiveContext<MemoryTracker>
{
public:
    void update_allocs(size_t n)
    { get_default().update_allocs(n); }

    void update_deallocs(size_t n)
    { get_default().update_deallocs(n); }
};

extern THREAD_LOCAL MemoryActiveContext mp_active_context;

#endif
