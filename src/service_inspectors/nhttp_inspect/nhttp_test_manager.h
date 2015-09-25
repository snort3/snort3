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
// nhttp_test_manager.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_TEST_MANAGER_H
#define NHTTP_TEST_MANAGER_H

#include <sys/types.h>
#include <stdio.h>

//-------------------------------------------------------------------------
// NHttpTestManager class
//-------------------------------------------------------------------------

class NHttpTestInput;

class NHttpTestManager
{
public:
    static bool use_test_input() { return test_input; }
    static void activate_test_input();
    static void activate_test_output() { test_output = true; }
    static NHttpTestInput* get_test_input_source() { return test_input_source; }
    static void update_test_number(int64_t new_test_number);
    static bool use_test_output() { return test_output || test_input; }
    static FILE* get_output_file() { return (test_out != nullptr) ? test_out : stdout; }
    static int64_t get_test_number() { return test_number; }

private:
    NHttpTestManager() = delete;

    static bool test_input;
    static NHttpTestInput* test_input_source;

    // Printing results of message processing
    static bool test_output;
    static const char* test_output_prefix;
    static FILE* test_out;
    static int64_t test_number;
};

#endif

