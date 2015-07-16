//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// memcap.h author Russ Combs <rucombs@cisco.com>

#ifndef MEMCAP_H
#define MEMCAP_H

// this memcap is just a basic tracker to compare a current total against a
// limit.  this will be updated when memory management is implemented.

#include <stdint.h>

class Memcap
{
public:
    Memcap(uint64_t u = 0) { cap = u; use = 0; }

    void set_cap(uint64_t c) { cap = c; }
    uint64_t get_cap() { return cap; }
    bool at_max() { return cap and use >= cap; }
    void alloc(uint64_t sz) { use += sz; }
    void dealloc(uint64_t sz) { if ( use >= sz) use -= sz; }
    uint64_t used() { return use; }

private:
    uint64_t cap;
    uint64_t use;
};

#endif

