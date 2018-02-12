//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "periodic.h"

#include <list>

#ifdef UNIT_TEST
#include <vector>
#include "catch/snort_catch.h"
#endif

struct PeriodicHookNode
{
    PeriodicHook hook;
    void* arg;

    uint16_t priority;

    uint32_t period;
    uint32_t time_left;

    PeriodicHookNode(PeriodicHook hook, void* arg, uint16_t priority, uint32_t period) :
        hook(hook), arg(arg), priority(priority), period(period), time_left(period) { }
};

static std::list<PeriodicHookNode> s_periodic_handlers;

void Periodic::register_handler(PeriodicHook hook, void* arg, uint16_t priority, uint32_t period)
{
    auto it = s_periodic_handlers.begin();

    while ( it != s_periodic_handlers.end() && it->priority < priority )
        ++it;

    s_periodic_handlers.emplace(it, hook, arg, priority, period);
}

void Periodic::check()
{
    for ( auto& it : s_periodic_handlers )
    {
        if ( !it.time_left )
        {
            it.hook(it.arg);
            it.time_left = it.period;
        }

        else
            --it.time_left;
    }
}

void Periodic::unregister_all()
{ s_periodic_handlers.clear(); }

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
static std::vector<int> s_test_args;

static void s_test_handler(void* pv)
{ s_test_args.push_back(*(int*)(pv)); }

TEST_CASE("periodic", "[periodic]")
{
    const int
        arg1 = 1,
        arg2 = 2,
        arg3 = 3;

    const std::vector<int>
        expect2 = { arg1 },
        expect3 = { arg2, arg3 };

    REQUIRE( s_periodic_handlers.empty() );
    REQUIRE( s_test_args.empty() );

    Periodic::register_handler(s_test_handler, (void*)&arg1, 1, 1);
    Periodic::register_handler(s_test_handler, (void*)&arg2, 1, 2);
    Periodic::register_handler(s_test_handler, (void*)&arg3, 2, 2);

    Periodic::check();
    CHECK( s_test_args.empty() );

    Periodic::check();
    CHECK( s_test_args == expect2 );
    s_test_args.clear();

    Periodic::check();
    CHECK( s_test_args == expect3 );
    s_test_args.clear();

    Periodic::check();
    Periodic::check();
    CHECK( s_test_args == expect2 );

    Periodic::unregister_all();
    CHECK( s_periodic_handlers.empty() );
}
#endif

