//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
    ad.set_ ## func(abc.c_str(), abc.size());                           \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    ad.set_ ## func(def.c_str(), def.size());                           \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,def);                                         \
    outField=ad.func(1);                                                \
    delete outField;

#define SET_GET_OFFSET_MACRO(func)                                      \
    ad.set_ ## func(abc.c_str(), abc.size(), start, end);               \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,abc);                                         \
    ad.set_ ## func(def.c_str(), def.size(), start, end);               \
    outField=ad.func(0);                                                \
    CHECK_EQUAL(*outField,def);                                         \
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
    uint16_t start=0, end=3;
    string abc("abc");
    string def("def");
    const string* outField=nullptr;

    SET_GET_OFFSET_MACRO(spdy_request_path);
    SET_GET_MACRO(spdy_request_scheme);
    SET_GET_OFFSET_MACRO(spdy_request_host);
    SET_GET_MACRO(http_request_url);
    SET_GET_OFFSET_MACRO(http_request_uri);
    SET_GET_OFFSET_MACRO(http_request_host);
    SET_GET_OFFSET_MACRO(http_request_cookie);
    SET_GET_MACRO(http_request_via);
    SET_GET_MACRO(http_response_via);
    SET_GET_MACRO(http_response_upgrade);
    SET_GET_OFFSET_MACRO(http_request_user_agent);
    SET_GET_MACRO(http_response_version);
    SET_GET_MACRO(http_response_code);
    SET_GET_MACRO(http_response_content);
    SET_GET_MACRO(http_response_location);
    SET_GET_MACRO(http_response_body);
    SET_GET_MACRO(http_request_body);
    SET_GET_MACRO(http_response_server);
    SET_GET_MACRO(http_request_x_working_with);
    SET_GET_MACRO(tls_host);
    SET_GET_MACRO(tls_cname);
    SET_GET_MACRO(tls_org_unit);
    SET_GET_OFFSET_MACRO(http_request_referer);
    SET_GET_MACRO(ftp_command_user);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}

