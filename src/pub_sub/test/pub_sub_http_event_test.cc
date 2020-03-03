//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_event_test.cc author Katura Harvey <katharve@cisco.com>

// Unit test for the HttpEvent methods to retrieve HTTP/2 information

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pub_sub/http_events.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_field.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpCommon;

// Stubs to make the code link
const Field Field::FIELD_NULL { STAT_NO_SOURCE };
const Field& HttpMsgSection::get_classic_buffer(unsigned int, unsigned long, unsigned long)
    { return Field::FIELD_NULL; }

TEST_GROUP(pub_sub_http_event_test)
{
};


TEST(pub_sub_http_event_test, http_traffic)
{
    uint32_t stream_id = 0;
    HttpEvent event(nullptr, false, stream_id);
    CHECK_FALSE(event.get_is_http2());
    CHECK(event.get_http2_stream_id() == stream_id);
}

TEST(pub_sub_http_event_test, http2_traffic)
{
    uint32_t stream_id = 3;
    HttpEvent event(nullptr, true, stream_id);
    CHECK(event.get_is_http2());
    CHECK(event.get_http2_stream_id() == stream_id);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

