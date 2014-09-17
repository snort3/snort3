/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// unit_test.h author Russ Combs <rucombs@cisco.com>
//
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

#include "suite_decl.h"

static print_output s_mode = CK_LAST;

typedef Suite* (*SuiteCtor_f)();

static SuiteCtor_f s_suites[] =
{
#include "suite_list.h"
    nullptr
};

void unit_test_mode(const char* s)
{
    if ( !s || !strcasecmp(s, "off") )
        s_mode = CK_LAST;

    else if ( !strcasecmp(s, "silent") )
        s_mode = CK_SILENT;

    else if ( !strcasecmp(s, "minimal") )
        s_mode = CK_MINIMAL;

    else if ( !strcasecmp(s, "normal") )
        s_mode = CK_NORMAL;

    else if ( !strcasecmp(s, "verbose") )
        s_mode = CK_VERBOSE;

    else //if ( !strcasecmp(s, "env") )
        s_mode = CK_ENV;
}

bool unit_test_enabled()
{
    return s_mode != CK_LAST;
}

int unit_test()
{
    int nErr;
    SuiteCtor_f* ctor = s_suites;
    SRunner* pr = nullptr;

    while ( *ctor )
    {
        Suite* ps = (*ctor)();

        if ( !pr )
            pr = srunner_create(ps);
        else
            srunner_add_suite(pr, ps);

        ++ctor;
    }
    if ( !pr )
        return -1;

    // tbd - possible to support forking?
    srunner_set_fork_status(pr, CK_NOFORK);

    // PrintTests();
    //if ( argc > 1 ) s_debug = 1;

    // srunner_set_log() overrides CK_ENV
    const char* log = getenv("CK_LOG");
    if ( log ) srunner_set_log (pr, log);

    srunner_run_all(pr, s_mode);
    nErr = srunner_ntests_failed(pr);

    srunner_free(pr);
    return (nErr == 0) ? 0 : -1;
}

