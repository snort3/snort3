//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// numa.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef NUMA_H
#define NUMA_H

#include <numa.h>
#include <numaif.h>
#include <sched.h>
#include <hwloc.h>

class NumaWrapper
{
public:
    virtual ~NumaWrapper() {}
    virtual int available()
    {
        return numa_available();
    }
    virtual int max_node()
    {
        return numa_max_node();
    }
    virtual int preferred()
    {
        return numa_preferred();
    }
    virtual int set_mem_policy(int mode, const unsigned long *nodemask,
                              unsigned long maxnode)
    {
        return set_mempolicy(mode, nodemask, maxnode);
    }
};

class HwlocWrapper
{
public:
    virtual ~HwlocWrapper() {}
    virtual unsigned get_nbobjs_by_depth(hwloc_topology_t topology, int depth)
    {
        return hwloc_get_nbobjs_by_depth(topology, depth);
    }
    virtual hwloc_obj_t get_obj_by_depth(hwloc_topology_t topology, int depth, unsigned idx)
    {
        return hwloc_get_obj_by_depth(topology, depth, idx);
    }
    virtual int get_type_depth(hwloc_topology_t topology, hwloc_obj_type_t type)
    {
        return hwloc_get_type_depth(topology, type);
    }
    virtual int bitmap_intersects(hwloc_const_cpuset_t set1, hwloc_const_cpuset_t set2)
    {
        return hwloc_bitmap_intersects(set1, set2);
    }
};
#endif

