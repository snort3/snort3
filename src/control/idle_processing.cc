//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// idle_processing.c author Ron Dempster <rdempster@sourcefire.com>
//
// Allow functions to be registered to be called when packet
// processing is idle.

#include "idle_processing.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <vector>

#ifdef UNIT_TEST
#include "test/catch.hpp"
#endif

typedef std::vector<IdleHook> IdleList;
static IdleList idle_list;

void IdleProcessingRegisterHandler(IdleHook f)
{
    idle_list.push_back(f);
}

void IdleProcessingExecute(void)
{
    for ( auto f : idle_list )
        f();
}

void IdleProcessingCleanUp(void)
{
    idle_list.clear();
}

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
static unsigned s_niph1 = 0;
static unsigned s_niph2 = 0;

static void iph1() { s_niph1++; }
static void iph2() { s_niph2++; }

TEST_CASE("idle callback", "[control]")
{
    IdleProcessingRegisterHandler(iph1);
    IdleProcessingRegisterHandler(iph2);

    IdleProcessingExecute();
    CHECK(s_niph1 == 1);
    CHECK(s_niph2 == 1);

    IdleProcessingExecute();
    CHECK(s_niph1 == 2);
    CHECK(s_niph2 == 2);

    IdleProcessingCleanUp();
}
#endif

