//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifndef THREAD_CONFIG_H
#define THREAD_CONFIG_H

#include <hwloc.h>
#include <map>
#include <string>

#include "main/thread.h"

struct CpuSet;

namespace snort
{

class SO_PUBLIC ThreadConfig
{
public:
    static bool init();
    static CpuSet* validate_cpuset_string(const char*);
    static void destroy_cpuset(CpuSet*);
    static void set_instance_max(unsigned);
    static unsigned get_instance_max();
    static void term();
    static void start_watchdog();
    static void preemptive_kick();
    static void set_instance_tid(int);
    static int get_instance_tid(int);

    ~ThreadConfig();
    void apply_thread_policy(SThreadType type, unsigned id);
    void set_thread_affinity(SThreadType, unsigned id, CpuSet*);
    void set_named_thread_affinity(const std::string&, CpuSet*);
    void implement_thread_affinity(SThreadType, unsigned id);
    void implement_named_thread_affinity(const std::string& name);
    bool implement_thread_mempolicy(SThreadType type, unsigned id);

    static constexpr unsigned int DEFAULT_THREAD_ID = 0;

private:
    struct TypeIdPair
    {
        SThreadType type;
        unsigned id;
    };
    struct TypeIdPairComparer
    {
        bool operator()(const TypeIdPair& left, const TypeIdPair& right) const
        {
            if (left.type < right.type)
                return true;
            if (left.type == right.type && left.id < right.id)
                return true;
            return false;
        }
    };
    std::map<TypeIdPair, CpuSet*, TypeIdPairComparer> thread_affinity;
    std::map<std::string, CpuSet*> named_thread_affinity;

    bool set_preferred_mempolicy(int node);
    int get_numa_node(hwloc_topology_t, hwloc_cpuset_t);
};
}
#endif
