//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_form_data_event_test.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "pub_sub/http_form_data_event.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

TEST_GROUP(pub_sub_http_form_data_event_test)
{
};

TEST(pub_sub_http_form_data_event_test, single_field)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("username", "john_doe");

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);
    const std::string& uri = event.get_form_data_uri();

    STRCMP_EQUAL("username=john_doe", uri.c_str());
}

TEST(pub_sub_http_form_data_event_test, multiple_fields)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("username", "admin");
    fields.emplace_back("password", "admin");
    fields.emplace_back("remember", "true");

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);
    const std::string& uri = event.get_form_data_uri();

    STRCMP_EQUAL("username=admin&password=admin&remember=true", uri.c_str());
}

TEST(pub_sub_http_form_data_event_test, empty_fields)
{
    HttpFormDataEvent::FieldVector fields;

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);
    const std::string& uri = event.get_form_data_uri();

    STRCMP_EQUAL("", uri.c_str());
}

TEST(pub_sub_http_form_data_event_test, fields_with_empty_values)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("search", "");
    fields.emplace_back("page", "1");

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);
    const std::string& uri = event.get_form_data_uri();

    STRCMP_EQUAL("search=&page=1", uri.c_str());
}

TEST(pub_sub_http_form_data_event_test, fields_with_special_characters)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("query", "' OR '1'='1");
    fields.emplace_back("id", "1;   DROP TABLE users--");

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);
    const std::string& uri = event.get_form_data_uri();

    STRCMP_EQUAL("query=' OR '1'='1&id=1; DROP TABLE users--", uri.c_str());
}

TEST(pub_sub_http_form_data_event_test, caching_multiple_calls)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("name", "test");
    fields.emplace_back("value", "123");

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);

    // First call - formats the URI
    const std::string& uri1 = event.get_form_data_uri();

    // Second call - should return cached result
    const std::string& uri2 = event.get_form_data_uri();

    STRCMP_EQUAL("name=test&value=123", uri1.c_str());
    STRCMP_EQUAL(uri1.c_str(), uri2.c_str());
}

TEST(pub_sub_http_form_data_event_test, fields_with_tab_characters)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("name", "John\tDoe");
    fields.emplace_back("Blog", " Hello!\tMy name is\t John. ");

    HttpFormDataEvent event(fields, HttpEnums::METH_POST);
    const std::string& uri = event.get_form_data_uri();

    STRCMP_EQUAL("name=John Doe&Blog=Hello! My name is John.", uri.c_str());
}

TEST(pub_sub_http_form_data_event_test, get_method_id)
{
    HttpFormDataEvent::FieldVector fields;
    fields.emplace_back("username", "admin");

    HttpFormDataEvent post_event(fields, HttpEnums::METH_POST);
    CHECK_EQUAL(HttpEnums::METH_POST, post_event.get_method_id());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
