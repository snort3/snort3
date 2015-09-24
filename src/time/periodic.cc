//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "periodic.h"

#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <list>

#ifdef UNIT_TEST
#include "test/catch.hpp"
#endif

#include "main/snort_types.h"
#include "utils/util.h"

struct PeriodicCheckFuncNode
{
    PeriodicFunc func;
    void* arg;

    uint32_t period;
    uint32_t time_left;

    uint16_t priority;
};

typedef std::list<PeriodicCheckFuncNode> PeriodicList;
static PeriodicList periodic_list;

void periodic_register(
    PeriodicFunc periodic_func, void* arg,
    uint16_t priority, uint32_t period)
{
    PeriodicCheckFuncNode node;

    node.func = periodic_func;
    node.arg = arg;
    node.period = period;
    node.time_left = period;
    node.priority = priority;

    std::list<PeriodicCheckFuncNode>::iterator it = periodic_list.begin();

    while ( it != periodic_list.end() and it->priority < priority )
        ++it;

    // insert higher priority first
    periodic_list.insert(it, node);
}

void periodic_release()
{
    periodic_list.clear();
}

void periodic_check()
{
    for ( auto& it : periodic_list )
    {
        if ( !it.time_left )
        {
            it.func(it.arg);
            it.time_left = it.period;
        }
        else
            it.time_left--;
    }
}

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
static void* s_arg = nullptr;

static void test(void* pv)
{ s_arg = pv; }

TEST_CASE("periodic", "[periodic]")
{
    const char* arg1 = "arg1";
    const char* arg2 = "arg2";

    periodic_register(test, (void*)arg1, 1, 2);
    periodic_register(test, (void*)arg2, 1, 1);

    periodic_register(test, nullptr, 0, 3);
    periodic_register(test, nullptr, 3, 4);

    periodic_check();
    CHECK(!s_arg);

    periodic_check();
    CHECK(s_arg == arg2);

    periodic_check();
    CHECK(s_arg == arg1);

    periodic_release();
}
#endif

