//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_body_event_test.cc author Vitalii Tron <vtron@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "pub_sub/http_body_event.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

TEST_GROUP(pub_sub_http_body_event_test)
{

};

TEST(pub_sub_http_body_event_test, regular_event)
{
    int32_t in_message_length = 500;
    std::string in_message(in_message_length, 'A');
    const bool in_is_data_from_client = true;
    const bool last_piece = true;

    HttpBodyEvent event((const uint8_t*)in_message.c_str(), in_message_length, in_is_data_from_client, last_piece);

    int32_t out_message_length;
    const uint8_t* out_message = event.get_body(out_message_length);

    const bool out_is_data_from_client = event.is_data_from_client();
    const bool out_last_piece = event.is_last_piece();

    CHECK(out_message_length == in_message_length);
    CHECK(memcmp(out_message, in_message.c_str(), out_message_length) == 0);
    CHECK(out_is_data_from_client == in_is_data_from_client);
    CHECK(out_last_piece == last_piece);
}

TEST(pub_sub_http_body_event_test, empty_data_event)
{
    const bool in_is_data_from_client = true;
    const bool last_piece = false;

    HttpBodyEvent event(nullptr, 0, in_is_data_from_client, last_piece);

    int32_t out_message_length;
    const uint8_t* out_message = event.get_body(out_message_length);
    const bool out_is_data_from_client = event.is_data_from_client();
    const bool out_last_piece = event.is_last_piece();

    CHECK(out_message == nullptr);
    CHECK(out_message_length == 0);
    CHECK(out_is_data_from_client == in_is_data_from_client);
    CHECK(out_last_piece == last_piece);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

