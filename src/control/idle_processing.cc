//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "idle_processing.h"

#include <vector>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

static std::vector<IdleHook> s_idle_handlers;

void IdleProcessing::register_handler(IdleHook f)
{ s_idle_handlers.push_back(f); }

void IdleProcessing::execute()
{
    for ( const auto& f : s_idle_handlers )
        f();
}

void IdleProcessing::unregister_all()
{ s_idle_handlers.clear(); }

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
    IdleProcessing::register_handler(iph1);
    IdleProcessing::register_handler(iph2);

    IdleProcessing::execute();
    CHECK(s_niph1 == 1);
    CHECK(s_niph2 == 1);

    IdleProcessing::execute();
    CHECK((s_niph1 == 2));
    CHECK((s_niph2 == 2));

    IdleProcessing::unregister_all();

    IdleProcessing::execute();
    CHECK((s_niph1 == 2));
    CHECK((s_niph2 == 2));
}
#endif

