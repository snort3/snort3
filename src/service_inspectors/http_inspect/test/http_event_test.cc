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
// http_event_test.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <bitset>

#include "service_inspectors/http_inspect/http_event.h"
#include "service_inspectors/http_inspect/http_inspect_base.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

namespace snort
{
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

TEST_GROUP(http_event_gen_test) {};

TEST(http_event_gen_test, create_event_if_new_queues_only_first_time)
{
    HttpEventGen events;

    CHECK(events.create_event_if_new(HttpEnums::EVENT_REQUEST_LINE_NOT_VALID));
    CHECK_FALSE(events.create_event_if_new(HttpEnums::EVENT_REQUEST_LINE_NOT_VALID));
}

TEST(http_event_gen_test, create_event_if_new_ignores_none_event)
{
    HttpEventGen events;

    CHECK_FALSE(events.create_event_if_new(HttpEnums::EVENT__NONE));
}

TEST(http_event_gen_test, create_event_if_new_honors_initial_suppression)
{
    std::bitset<HttpEnums::EVENT__MAX_VALUE> suppressed;
    suppressed.set(HttpEnums::EVENT_REQUEST_LINE_NOT_VALID - 1);
    HttpEventGen events(suppressed);

    CHECK_FALSE(events.create_event_if_new(HttpEnums::EVENT_REQUEST_LINE_NOT_VALID));
}

TEST(http_event_gen_test, create_event_if_new_sees_base_create_event_suppression)
{
    HttpEventGen events;

    events.create_event(HttpEnums::EVENT_REQUEST_LINE_NOT_VALID);

    CHECK_FALSE(events.create_event_if_new(HttpEnums::EVENT_REQUEST_LINE_NOT_VALID));
}
