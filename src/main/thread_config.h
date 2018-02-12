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

#ifndef THREAD_CONFIG_H
#define THREAD_CONFIG_H

#include <map>

#include "main/thread.h"

struct CpuSet;

class ThreadConfig
{
public:
    static bool init();
    static CpuSet* validate_cpuset_string(const char*);
    static void destroy_cpuset(CpuSet*);
    static void set_instance_max(unsigned);
    static unsigned get_instance_max();
    static void term();

    ~ThreadConfig();
    void set_thread_affinity(SThreadType, unsigned id, CpuSet*);
    void implement_thread_affinity(SThreadType, unsigned id);
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
};

#endif
