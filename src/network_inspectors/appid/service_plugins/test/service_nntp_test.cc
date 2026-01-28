//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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
//
// service_nntp_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../service_nntp.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(nntp_validate_data_tests)
{
    void setup() override
    {
    }
    void teardown() override
    {
    }
};

TEST(nntp_validate_data_tests, nntp_validate_loop)
{    
    constexpr uint16_t size = std::numeric_limits<uint16_t>::max();
    uint8_t data[size];
    memset(data, 0, sizeof(data));
    uint16_t offset = 0;
    int flags = 0;
    
    int result = nntp_validate_data(data, &offset, size, &flags);
    CHECK_EQUAL(0, result);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}