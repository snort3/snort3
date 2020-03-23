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

// client_app_aim_test.cc author Kani Murthi<kamurthi@cisco.com>
// unit test for client_app_aim_test.cc
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/client_plugins/client_app_aim.cc"
#include "network_inspectors/appid/client_plugins/client_detector.cc"
#include "protocols/packet.h"
#include "client_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void ServiceDiscovery::initialize() {}
int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection,
    ServiceDetector*, ServiceDiscoveryState*) { return 0; }
int ServiceDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }

TEST_GROUP(client_app_aim_test){};

TEST(client_app_aim_test, check_username)
{
    uint8_t data[] = {"test@gmail.com\0"};
    FLAPTLV tlv = {0x0001, 14};
    char buf[256];
    bool ret;
    ret = check_username(data, &tlv, buf, buf + 255);
    CHECK_TRUE(ret);
    STRCMP_EQUAL(buf, "test@gmail.com");
    uint8_t invalid_data[] = {"test^"};
    tlv = {0x0001, 5};
    ret = check_username(invalid_data, &tlv, buf, buf + 255);
    CHECK_FALSE(ret);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
