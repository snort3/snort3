//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// tp_appid_types_test.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <string>

#include "tp_appid_types.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

// 1st CHECK_EQUAL checks that what comes out is what went in
// 2nd CHECK_EQUAL checks that AttributeData still has it
// 3rd CHECK_EQUAL checks that AttributeData doesn't leak memory upon consecutive sets
// finally check that we don't leak or double free memory when caller owns it
#define SET_GET_MACRO(func)                                             \
    ad.set_ ## func(abc.c_str(), abc.size(), true);                     \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    ad.set_ ## func(def.c_str(), def.size(), true);                     \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,def);                                         \
    outField=ad.func(1);                                                \
    delete outField;

#define SET_GET_MACRO_FRAGMENTED(func)                                  \
    ad.set_ ## func(abc.c_str(), abc.size(), false);                    \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    ad.set_ ## func(def.c_str(), def.size(), true);                     \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc+def);                                     \
    outField=ad.func(1);                                                \
    delete outField;

TEST_GROUP(tp_appid_types)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(tp_appid_types, get_set)
{
    ThirdPartyAppIDAttributeData ad;
    string abc("abc");
    string def("def");
    const string* outField=nullptr;

    SET_GET_MACRO(spdy_request_path);
    SET_GET_MACRO(spdy_request_scheme);
    SET_GET_MACRO(spdy_request_host);
    SET_GET_MACRO(http_request_url);
    SET_GET_MACRO(http_request_uri);
    SET_GET_MACRO(http_request_host);
    SET_GET_MACRO(http_request_cookie);
    SET_GET_MACRO(http_request_via);
    SET_GET_MACRO(http_response_via);
    SET_GET_MACRO(http_request_user_agent);
    SET_GET_MACRO(http_response_code);
}

TEST(tp_appid_types, get_set_fragmented)
{
    ThirdPartyAppIDAttributeData ad;
    string abc("abc");
    string def("def");
    const string* outField=nullptr;

    SET_GET_MACRO_FRAGMENTED(http_response_content);
    SET_GET_MACRO_FRAGMENTED(http_response_location);
    SET_GET_MACRO_FRAGMENTED(http_response_body);
    SET_GET_MACRO_FRAGMENTED(http_request_body);
    SET_GET_MACRO_FRAGMENTED(http_response_server);
    SET_GET_MACRO_FRAGMENTED(http_request_x_working_with);
    SET_GET_MACRO_FRAGMENTED(tls_host);
    SET_GET_MACRO_FRAGMENTED(tls_cname);
    SET_GET_MACRO_FRAGMENTED(tls_org_unit);
    SET_GET_MACRO_FRAGMENTED(http_request_referer);
    SET_GET_MACRO_FRAGMENTED(ftp_command_user);
}

TEST(tp_appid_types, max_len)
{
    ThirdPartyAppIDAttributeData ad;
    char buf[3000];

    for (int i = 0; i < 2999; i++)
        buf[i] = 'a';

    buf[2999] = '\0';
    ad.set_http_request_body(buf, 2999, true);
    string* req_body = ad.http_request_body();
    CHECK_EQUAL(req_body->size(), MAX_ATTR_LEN);
    for (int i = 0; i < MAX_ATTR_LEN; i++)
        CHECK_EQUAL((*req_body)[i], 'a');

    ad.set_http_request_body(buf, 2999, true, 2800);
    req_body = ad.http_request_body();
    CHECK_EQUAL(req_body->size(), 2800);
    for (int i = 0; i < 2800; i++)
        CHECK_EQUAL((*req_body)[i], 'a');

    ad.set_http_request_body(buf, 2999, true, 3200);
    req_body = ad.http_request_body();
    CHECK_EQUAL(req_body->size(), 2999);
    for (int i = 0; i < 2999; i++)
        CHECK_EQUAL((*req_body)[i], 'a');

    ad.set_http_request_body(buf, 1600, false);
    ad.set_http_request_body(buf, 1600, true);
    req_body = ad.http_request_body();
    CHECK_EQUAL(req_body->size(), MAX_ATTR_LEN);
    for (int i = 0; i < MAX_ATTR_LEN; i++)
        CHECK_EQUAL((*req_body)[i], 'a');

    ad.set_http_request_body(buf, 1600, false, 3200);
    ad.set_http_request_body(buf, 1600, true, 3200);
    req_body = ad.http_request_body();
    CHECK_EQUAL(req_body->size(), 3200);
    for (int i = 0; i < 3200; i++)
        CHECK_EQUAL((*req_body)[i], 'a');
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}

