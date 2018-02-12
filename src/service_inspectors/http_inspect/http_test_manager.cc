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
// http_test_manager.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef REG_TEST

#include <stdexcept>

#include "http_test_manager.h"

#include "http_test_input.h"

bool HttpTestManager::test_input = false;
bool HttpTestManager::test_output = false;
HttpTestInput* HttpTestManager::test_input_source = nullptr;
const char* HttpTestManager::test_output_prefix = "httpresults/testcase";
int64_t HttpTestManager::test_number = -1;
FILE* HttpTestManager::test_out = nullptr;
long HttpTestManager::print_amount = 1200;
bool HttpTestManager::print_hex = false;
bool HttpTestManager::show_pegs = true;
bool HttpTestManager::show_scan = false;

void HttpTestManager::update_test_number(int64_t new_test_number)
{
    if (new_test_number != test_number)
    {
        if (test_out != nullptr)
            fclose (test_out);
        test_number = new_test_number;
        char file_name[100];
        snprintf(file_name, sizeof(file_name), "%s%" PRIi64 ".txt", test_output_prefix,
            test_number);
        if ((test_out = fopen(file_name, "w+")) == nullptr)
            throw std::runtime_error("Cannot open test output file");
    }
}

void HttpTestManager::activate_test_input()
{
    test_input = true;
    if (test_input_source == nullptr)
    {
        test_input_source = new HttpTestInput("http_test_msgs.txt");
    }
}

#endif

