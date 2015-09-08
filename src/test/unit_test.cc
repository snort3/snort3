//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <vector>
#include <string>

#include "unit_test.h"

#include <stdlib.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#include <check.h>

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#include <check.h>

#include "suite_decl.h"

static print_output s_mode = CK_LAST;
static bool s_catch = false;
static std::vector<std::string> test_tags;

typedef Suite* (* SuiteCtor_f)();

static SuiteCtor_f s_suites[] =
{
#include "suite_list.h"
    nullptr
};

void unit_test_mode(const char* s)
{
    if ( !s || !strcasecmp(s, UNIT_TEST_MODE_OFF) )
        s_mode = CK_LAST;

    else if ( !strcasecmp(s, UNIT_TEST_MODE_SILENT) )
        s_mode = CK_SILENT;

    else if ( !strcasecmp(s, UNIT_TEST_MODE_MINIMAL) )
        s_mode = CK_MINIMAL;

    else if ( !strcasecmp(s, UNIT_TEST_MODE_NORMAL) )
        s_mode = CK_NORMAL;

    else if ( !strcasecmp(s, UNIT_TEST_MODE_VERBOSE) )
        s_mode = CK_VERBOSE;

    else //if ( !strcasecmp(s, UNIT_TEST_MODE_ENV) )
        s_mode = CK_ENV;
}

void unit_test_catch_test_filter(const char* s)
{
    if ( s && strcmp(s, "all") )
        test_tags.push_back( s );

    s_catch = true;
}

bool check_enabled()
{
    return s_mode != CK_LAST;
}

bool catch_enabled()
{
    return s_catch;
}

static bool run_check()
{
    int nErr;
    SuiteCtor_f* ctor = s_suites;
    SRunner* pr = nullptr;

    while ( *ctor )
    {
        Suite* ps = (* ctor)();

        if ( !pr )
            pr = srunner_create(ps);
        else
            srunner_add_suite(pr, ps);

        ++ctor;
    }
    if ( !pr )
        return false;

    // tbd - possible to support forking?
    srunner_set_fork_status(pr, CK_NOFORK);

    // PrintTests();
    //if ( argc > 1 ) s_debug = 1;

    // srunner_set_log() overrides CK_ENV
    const char* log = getenv("CK_LOG");
    if ( log )
        srunner_set_log (pr, log);

    srunner_run_all(pr, s_mode);
    nErr = srunner_ntests_failed(pr);

    srunner_free(pr);
    return !nErr;
}

// check defines fail, so we must squash that because
// catch uses stream and that has a fail method
#undef fail
#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

static bool run_catch()
{
  Catch::Session session;

  // write to session.configData() or session.Config() to customize
  if( s_mode == CK_VERBOSE )
      session.configData().showSuccessfulTests = true;

  if( test_tags.size() > 0 )
      session.configData().testsOrTags = test_tags;

  return session.run() == 0;
}

int check_test()
{
    if ( !run_check() )
        return -1;

    return 0;
}

int catch_test()
{
    if ( !run_catch() )
        return -1;

    return 0;
}

