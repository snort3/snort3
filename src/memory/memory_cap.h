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

// memory_cap.h author Joel Cornett <jocornet@cisco.com>

#ifndef MEMORY_CAP_H
#define MEMORY_CAP_H

#include <cstddef>

namespace memory
{

class MemoryCap
{
public:
    static bool free_space(size_t);
    static void update_allocations(size_t);
    static void update_deallocations(size_t);

    static bool over_threshold();

    // call from main thread
    static void calculate(unsigned num_threads);

    // call from main thread
    static void print();

private:
    static size_t thread_cap;
    static size_t preemptive_threshold;
};

} // namespace memory

#endif
