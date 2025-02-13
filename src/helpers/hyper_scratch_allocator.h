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
// hyper_scratch_allocator.h author Russ Combs <rucombs@cisco.com>

#ifndef HYPER_SCRATCH_ALLOCATOR_H
#define HYPER_SCRATCH_ALLOCATOR_H

#include "helpers/scratch_allocator.h"

#include <hs_compile.h>
#include <hs_runtime.h>

#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/thread.h"

//--------------------------------------------------------------------------
// scratch management
//--------------------------------------------------------------------------

namespace snort
{
struct SnortConfig;

class SO_PUBLIC HyperScratchAllocator : public ScratchAllocator
{
public:
    ~HyperScratchAllocator() override;

    bool setup(SnortConfig*) override;
    void cleanup(SnortConfig*) override;
    void update(SnortConfig*) override
    { }
    bool allocate(hs_database_t*);

    hs_scratch_t* get()
    { return get(SnortConfig::get_conf(), snort::get_instance_id()); }

private:
    hs_scratch_t** get_addr(SnortConfig* sc, unsigned idx)
    { return (hs_scratch_t**)&sc->state[idx][id]; }

    hs_scratch_t* get(const SnortConfig* sc, unsigned idx)
    { return (hs_scratch_t*)sc->state[idx][id]; }

    void set(SnortConfig* sc, unsigned idx, void* pv)
    { sc->state[idx][id] = pv; }

private:
    hs_scratch_t* scratch = nullptr;
};

}
#endif

