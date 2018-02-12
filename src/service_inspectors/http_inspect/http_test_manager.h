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
// http_test_manager.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_TEST_MANAGER_H
#define HTTP_TEST_MANAGER_H

#if defined(REG_TEST) || defined(UNIT_TEST)

#include <sys/types.h>
#include <cstdio>

//-------------------------------------------------------------------------
// HttpTestManager class
//-------------------------------------------------------------------------

class HttpTestInput;

class HttpTestManager
{
public:
    static bool use_test_input() { return test_input; }
    static void activate_test_input();
    static void activate_test_output() { test_output = true; }
    static HttpTestInput* get_test_input_source() { return test_input_source; }
    static void update_test_number(int64_t new_test_number);
    static bool use_test_output() { return test_output || test_input; }
    static FILE* get_output_file() { return (test_out != nullptr) ? test_out : stdout; }
    static int64_t get_test_number() { return test_number; }
    static void set_print_amount(long print_amount_) { print_amount = print_amount_; }
    static long get_print_amount() { return print_amount; }
    static void set_print_hex(bool print_hex_) { print_hex = print_hex_; }
    static bool get_print_hex() { return print_hex; }
    static void set_show_pegs(bool show_pegs_) { show_pegs = show_pegs_; }
    static bool get_show_pegs() { return show_pegs; }
    static void set_show_scan(bool show_scan_) { show_scan = show_scan_; }
    static bool get_show_scan() { return show_scan; }

private:
    HttpTestManager() = delete;

    static bool test_input;
    static HttpTestInput* test_input_source;

    // Printing results of message processing
    static bool test_output;
    static const char* test_output_prefix;
    static FILE* test_out;
    static int64_t test_number;
    static long print_amount;
    static bool print_hex;
    static bool show_pegs;
    static bool show_scan;
};

#endif
#endif

