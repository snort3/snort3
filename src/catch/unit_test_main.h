//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// unit_test_main.h author Michael Altizer <mialtize@cisco.com>

#ifndef UNIT_TEST_MAIN_H
#define UNIT_TEST_MAIN_H

// Unit test framework to be included *only* by the main source file to handle
// forcing the linking of objects file containing only Catch test cases.

#include "catch/unit_test.h"

// Unresolved external symbol declarations and references.
SNORT_CATCH_FORCED_INCLUSION_EXTERN(bitop_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(lua_stack_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(sfdaq_module_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(sfip_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(sfrf_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(sfrt_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(sfthd_test);
SNORT_CATCH_FORCED_INCLUSION_EXTERN(stopwatch_test);

bool catch_extern_tests[] =
{
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(bitop_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(lua_stack_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(sfdaq_module_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(sfip_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(sfrf_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(sfrt_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(sfthd_test),
    SNORT_CATCH_FORCED_INCLUSION_SYMBOL(stopwatch_test),
};

#endif

