//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// unit_test.h author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "unit_test.h"

#define CATCH_CONFIG_RUNNER
#include "snort_catch.h"

using namespace snort;

static bool s_catch = false;
static std::vector<std::string> test_tags;

void catch_set_filter(const char* s)
{
    if ( s && strcmp(s, "all") )
        test_tags.push_back( s );

    s_catch = true;
}

bool catch_enabled()
{
    return s_catch;
}

static bool run_catch()
{
    Catch::Session session;

    if ( !test_tags.empty() )
        session.configData().testsOrTags = test_tags;

    return session.run() == 0;
}

int catch_test()
{
    if ( !run_catch() )
        return -1;

    return 0;
}

// This isn't in snort_catch.cc because the linker may exclude the file if no static components
// reference TestCaseInstaller
SO_PUBLIC TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name)
{ REGISTER_TEST_CASE(fun, name); }

SO_PUBLIC TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name, const char* group)
{ REGISTER_TEST_CASE(fun, name, group); }
