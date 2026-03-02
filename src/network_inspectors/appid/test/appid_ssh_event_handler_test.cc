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

// appid_ssh_event_handler_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "../appid_ssh_event_handler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
unsigned FlowData::flow_data_id = 0;
unsigned FlowData::create_flow_data_id()
{ return ++flow_data_id; }

void LogLabel(const char*, FILE*) {}
void LogText(const char*, FILE*) {}

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
char* snort_strndup(const char* src, size_t)
{
    return snort_strdup(src);
}
}

unsigned int SshEventFlowData::id = 0;

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
THREAD_LOCAL bool appid_trace_enabled = false;
void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

TEST_GROUP(appid_ssh_event_handler_tests)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(appid_ssh_event_handler_tests, verify_flow_id_persistance)
{
    SshEventFlowData::init();

    SshEventFlowData data1;
    SshEventFlowData data2;
    SshEventFlowData data3;

    CHECK_EQUAL(data1.get_id(),data2.get_id());
    CHECK_EQUAL(data1.get_id(),data3.get_id());
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
