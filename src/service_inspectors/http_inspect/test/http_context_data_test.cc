//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// http_context_data_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/ips_context.h"
#include "service_inspectors/http_inspect/http_context_data.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace
{
    IpsContext* test_context = nullptr;
    IpsContextData* test_context_data = nullptr;
}

IpsContext::IpsContext(unsigned) { }
IpsContext::~IpsContext() = default;
IpsContext* DetectionEngine::get_next_context() { return test_context; }
void DetectionEngine::wait_for_context() { }
IpsContextData* DetectionEngine::get_data(unsigned, IpsContext*) { return test_context_data; }
IpsContextData* DetectionEngine::get_data(unsigned) { return test_context_data; }
void DetectionEngine::set_data(unsigned, IpsContextData* data) { test_context_data = data; }
// cppcheck-suppress functionStatic
void IpsContext::set_context_data(unsigned, IpsContextData* context_data)
{ test_context_data = context_data; }

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

TEST_GROUP(http_context_data_test)
{
    void setup() override
    {
        test_context = new IpsContext;
    }

    void teardown() override
    {
        if ( test_context_data )
        {
            test_context_data->clear();
            delete test_context_data;
            test_context_data = nullptr;
        }

        delete test_context;
        test_context = nullptr;
    }
};

TEST(http_context_data_test, claimed_buffer_survives_context_clear)
{
    uint8_t* buffer = new uint8_t[4];

    HttpContextData::save_pending_section_buffer(buffer);
    CHECK(test_context_data != nullptr);

    HttpContextData::claim_pending_section_buffer(test_context, buffer);

    // clear() must not delete a successfully claimed buffer.
    test_context_data->clear();
    delete[] buffer;
}

TEST(http_context_data_test, unclaimed_buffer_is_released_on_context_clear)
{
    HttpContextData::save_pending_section_buffer(new uint8_t[4]);
    CHECK(test_context_data != nullptr);

    // CppUTest's leak detection verifies that the buffer is released.
    test_context_data->clear();
}
