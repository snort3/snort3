//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_dns_session_test.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "network_inspectors/appid/appid_dns_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

TEST_GROUP(appid_dns_session)
{
};

TEST(appid_dns_session, set_host)
{
    AppIdDnsSession dns_session;
    AppidChangeBits change_bits;

    char* host1 = "first host";
    dns_session.set_host(host1, change_bits, true);
    STRCMP_EQUAL_TEXT(host1, dns_session.get_host(), "DNS session host mismatch");
    CHECK_TEXT(change_bits.test(APPID_DNS_REQUEST_HOST_BIT), "Change bits should have DNS request bit set");
    CHECK_TEXT(!change_bits.test(APPID_DNS_RESPONSE_HOST_BIT), "Change bits should not have DNS response bit set");
    std::string str;
    change_bits_to_string(change_bits, str);
    STRCMP_EQUAL_TEXT("dns-host", str.c_str(), "Change bits string mismatch");
    char* host2 = "second host";
    dns_session.set_host(host2, change_bits, false);
    STRCMP_EQUAL_TEXT(host2, dns_session.get_host(), "DNS session host mismatch");
    CHECK_TEXT(!change_bits.test(APPID_DNS_REQUEST_HOST_BIT), "Change bits should not have DNS request bit set");
    CHECK_TEXT(change_bits.test(APPID_DNS_RESPONSE_HOST_BIT), "Change bits should have DNS response bit set");
    str.clear();
    change_bits_to_string(change_bits, str);
    STRCMP_EQUAL_TEXT("dns-response-host", str.c_str(), "Change bits string mismatch");
    dns_session.set_host(host1, change_bits, true);
    STRCMP_EQUAL_TEXT(host1, dns_session.get_host(), "DNS session host mismatch");
    CHECK_TEXT(change_bits.test(APPID_DNS_REQUEST_HOST_BIT), "Change bits should have DNS request bit set");
    CHECK_TEXT(!change_bits.test(APPID_DNS_RESPONSE_HOST_BIT), "Change bits should not have DNS response bit set");
    str.clear();
    change_bits_to_string(change_bits, str);
    STRCMP_EQUAL_TEXT("dns-host", str.c_str(), "Change bits string mismatch");
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}

