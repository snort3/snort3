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
// scratch_allocator.h author Russ Combs <rucombs@cisco.com>

#ifndef SCRATCH_ALLOCATOR_H
#define SCRATCH_ALLOCATOR_H

// manages scratch memory - allocates required memory for each packet thread
// in SnortConfig.state[slot][id] where 0 <= slot < SnortConfig.num_slots and
// id = SnortConfig::request_scratch().  The use of scratch memory is strictly
// per packet, it can not be referenced on a flow, as it will change with each
// config reload.
//
// setup() should return false if no memory was allocated otherwise cleanup()
// will be called when the config is deleted.  this can happen eg if the
// associated module is not used in the current configuration.
//
// scratch allocators may use a prototype to allocate the packet thread
// memory.  the prototype should be freed in setup to avoid leaks and to
// ensure the prototypes for different configs are not interdependent (eg
// preventing a decrease in required scratch).

#include "main/snort_types.h"

namespace snort
{
struct SnortConfig;

class SO_PUBLIC ScratchAllocator
{
public:
    virtual ~ScratchAllocator();

    virtual bool setup(SnortConfig*) = 0;
    virtual void cleanup(SnortConfig*) = 0;
    virtual void update(SnortConfig*) = 0;

    int get_id() { return id; }

protected:
    ScratchAllocator();

    int id;
};

typedef bool (* ScratchSetup)(SnortConfig*);
typedef void (* ScratchCleanup)(SnortConfig*);
typedef void (* ScratchUpdate)(SnortConfig*);

class SO_PUBLIC SimpleScratchAllocator : public ScratchAllocator
{
public:
    SimpleScratchAllocator(ScratchSetup fs, ScratchCleanup fc, ScratchUpdate fu = nullptr)
        : fsetup(fs), fcleanup(fc), fupdate(fu) { }

    bool setup(SnortConfig* sc) override
    { return fsetup(sc); }

    void cleanup(SnortConfig* sc) override
    { fcleanup(sc); }

    void update(SnortConfig* sc) override
    {
        if (fupdate)
            fupdate(sc);
    }

private:
    ScratchSetup fsetup;
    ScratchCleanup fcleanup;
    ScratchUpdate fupdate;
};

}
#endif

