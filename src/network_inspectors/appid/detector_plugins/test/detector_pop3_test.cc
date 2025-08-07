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

// detector_pop3_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_inspector.h"
#include "appid_session.h"
#include "detector_plugins_mock.h"

#include "../detector_pop3.h"
#include "../detector_pop3.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

static ServiceDiscovery test_discovery;

// Stubs for AppIdInspector
AppIdConfig test_app_config;
AppIdInspector::AppIdInspector(AppIdModule&) : config(&test_app_config), ctxt(test_app_config) { }

void snort::SearchTool::reload() { }
int snort::SearchTool::find_all(const char*, unsigned, MpseMatch, bool, void* mp_arg, const snort::SnortConfig*)
{
    return 0;
}

void AppIdDetector::add_user(AppIdSession&, const char*, AppId, bool, AppidChangeBits&){}
int AppIdDetector::data_add(AppIdSession&, AppIdFlowData*) { return 1; }
AppIdFlowData* AppIdDetector::data_get(const AppIdSession&)
{
    return nullptr;
}

int ServiceDetector::fail_service(AppIdSession& asd, const Packet* pkt, AppidSessionDirection dir) { return 1; }


TEST_GROUP(detector_pop_tests)
{
    Pop3ServiceDetector* test_detector = nullptr;
    void setup() override
    {
        test_detector = new Pop3ServiceDetector(&test_discovery);
    }

    void teardown() override
    {
        delete test_detector;
        test_detector = nullptr;
    }
};

TEST(detector_pop_tests, pop_validate_incorrect_packet_len)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    AppIdSession test_asd(IpProtocol::TCP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    const uint8_t* test_data = (const uint8_t*)".";
    uint16_t test_data_size = 1;
    AppidChangeBits cb;

    POP3DetectorData dd;
    dd.server.state = POP3_STATE_CONNECT;

    auto result = test_detector->pop3_server_validate(&dd, test_data, test_data_size, test_asd, 1, cb);
    CHECK_EQUAL(-1, result);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
