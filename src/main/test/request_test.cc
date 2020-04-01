//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// request_test.cc author Devendra Dahiphale <ddahipha@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include "main/request.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

namespace snort
{
void ErrorMessage(const char*,...) { }
void LogMessage(const char*,...) { }
}

using namespace snort;

//--------------------------------------------------------------------------
// Request tests
//--------------------------------------------------------------------------
TEST_GROUP(request_tests)
{};

//--------------------------------------------------------------------------
// Make sure multiple responses are queued
//--------------------------------------------------------------------------
TEST(request_tests, queued_response_test)
{
    Request request(STDOUT_FILENO);

    CHECK(request.send_queued_response() == false); // empty queue
    request.respond("reloading", true);
    request.respond("swapping", true);
    CHECK(request.send_queued_response() == true);
    CHECK(request.send_queued_response() == true);
    CHECK(request.send_queued_response() == false); // empty queue after being written
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

