//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "memory/heap_interface.h"

#include <cstddef>

#include "framework/counts.h"
#include "main/snort_types.h"

struct MemoryConfig;
class ControlConn;

namespace memory
{

struct MemoryCounts
{
    PegCount start_up_use;
    PegCount cur_in_use;
    PegCount max_in_use;
    PegCount epochs;
    PegCount allocated;
    PegCount deallocated;
    PegCount reap_cycles;
    PegCount reap_attempts;
    PegCount reap_failures;
    PegCount reap_aborts;
    PegCount reap_decrease;
    PegCount reap_increase;
    // reporting only
    PegCount app_all;
    PegCount active;
    PegCount resident;
    PegCount retained;
};

typedef bool (*PruneHandler)();

class SO_PUBLIC MemoryCap
{
public:
    // main thread
    static void init(unsigned num_threads);
    static void term();

    // main thread - in configure
    static void set_heap_interface(HeapInterface*);
    static void set_pruner(PruneHandler);

    // main thread - after configure
    static void start(const MemoryConfig&, PruneHandler);
    static void stop();
    static void print(bool verbose, bool init = false);

    // packet threads
    static void thread_init();
    static void thread_term();
    static void free_space();

    // main and packet threads
    static MemoryCounts& get_mem_stats();

    // main thread - shutdown
    static void update_pegs(PegCount*);

    static void dump_mem_stats(ControlConn*);
#if defined(REG_TEST) || defined(UNIT_TEST)
    static void test_main_check();
#endif
};

}

#endif
