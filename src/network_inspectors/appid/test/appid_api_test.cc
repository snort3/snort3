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

// appid_api_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_api.cc"

#include <string>

#include "framework/data_bus.h"
#include "protocols/protocol_ids.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"
#include "appid_http_session.h"

#include "appid_mock_definitions.h"
#include "appid_mock_http_session.h"
#include "appid_mock_inspector.h"
#include "appid_mock_session.h"

#include "network_inspectors/appid/appid_peg_counts.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

const char* AppInfoManager::get_app_name(AppId)
{
    return test_app_name;
}

AppId AppInfoManager::get_appid_by_name(const char*)
{
    return APPID_UT_ID;
}

AppInfoManager& app_info_mgr = AppInfoManager::get_instance();

Flow* flow = nullptr;
AppIdSession* mock_session = nullptr;

TEST_GROUP(appid_api)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        flow = new Flow;
        flow->set_flow_data(mock_session);
    }

    void teardown() override
    {
        delete flow;
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(appid_api, get_application_name)
{
    const char* app_name = appid_api.get_application_name(1066);
    STRCMP_EQUAL(app_name, test_app_name);
}

TEST(appid_api, get_application_id)
{
    AppId id = appid_api.get_application_id(test_app_name);
    CHECK_EQUAL(id, 1492);
}

// FIXIT - enable this test when consume ha appid api call is fixed
#ifdef APPID_HA_SUPPORT_ENABLED
TEST(appid_api, produce_ha_state)
{
    AppIdSessionHA appHA, cmp_buf;

    memset((void*)&appHA, 0, sizeof(appHA));
    memset((void*)&cmp_buf, 0, sizeof(cmp_buf));
    mock_session->common.flow_type = APPID_FLOW_TYPE_IGNORE;
    mock_session->common.flags |= APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_HTTP_SESSION;
    uint32_t val = appid_api.produce_ha_state(flow, (uint8_t*)&appHA);
    CHECK_TRUE(val == sizeof(appHA));
    CHECK_TRUE(memcmp(&appHA, &cmp_buf, val) == 0);
    mock_session->common.flow_type = APPID_FLOW_TYPE_NORMAL;
    val = appid_api.produce_ha_state(flow, (uint8_t*)&appHA);
    CHECK_TRUE(val == sizeof(appHA));
    CHECK_TRUE(appHA.appId[0] == APPID_UT_ID);
    CHECK_TRUE(appHA.appId[1] == APPID_UT_ID + 1);
    CHECK_TRUE(appHA.appId[2] == APPID_UT_ID + 2);
    CHECK_TRUE(appHA.appId[3] == APPID_UT_ID + 3);
    CHECK_TRUE(appHA.appId[4] == APPID_UT_ID + 4);
    CHECK_TRUE(appHA.appId[5] == APPID_UT_ID + 5);
    CHECK_TRUE(appHA.appId[6] == APPID_UT_ID + 6);
    CHECK_TRUE(appHA.appId[7] == APPID_UT_ID + 7);
    CHECK_TRUE(appHA.flags == (APPID_HA_FLAGS_APP | APPID_HA_FLAGS_TP_DONE
        | APPID_HA_FLAGS_SVC_DONE | APPID_HA_FLAGS_HTTP));

    mock_flow_data= nullptr;
    SfIp ip;
    ip.pton(AF_INET, "192.168.1.222");
    val = appid_api.consume_ha_state(flow, (uint8_t*)&appHA, 0, IpProtocol::TCP, &ip, 1066);
    AppIdSession* session = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);
    CHECK_TRUE(session);
    CHECK_TRUE(session->get_tp_app_id() == appHA.appId[0]);
    CHECK_TRUE(session->service.get_id() == appHA.appId[1]);
    CHECK_TRUE(session->client_inferred_service_id == appHA.appId[2]);
    CHECK_TRUE(session->service.get_port_service_id() == appHA.appId[3]);
    CHECK_TRUE(session->payload.get_id() == appHA.appId[4]);
    CHECK_TRUE(session->tp_payload_app_id == appHA.appId[5]);
    CHECK_TRUE(session->client.get_id() == appHA.appId[6]);
    CHECK_TRUE(session->misc_app_id == appHA.appId[7]);
    CHECK_TRUE(session->service_disco_state == APPID_DISCO_STATE_FINISHED);
    CHECK_TRUE(session->client_disco_state == APPID_DISCO_STATE_FINISHED);
    delete session;

    // test logic when service app is ftp control
    appHA.appId[1] = APP_ID_FTP_CONTROL;
    mock_flow_data= nullptr;
    val = appid_api.consume_ha_state(flow, (uint8_t*)&appHA, 0, IpProtocol::TCP, &ip, 1066);
    session = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);
    CHECK_TRUE(session);
    uint64_t flags = session->get_session_flags(APPID_SESSION_CLIENT_DETECTED |
        APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
    CHECK_TRUE(flags == (APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_NOT_A_SERVICE
        | APPID_SESSION_SERVICE_DETECTED));
    CHECK_TRUE(session->service.get_id() == APP_ID_FTP_CONTROL);
    CHECK_TRUE(session->service_disco_state == APPID_DISCO_STATE_STATEFUL);
    CHECK_TRUE(session->client_disco_state == APPID_DISCO_STATE_FINISHED);
    delete session;
}
#endif

TEST(appid_api, create_appid_session_api)
{
    AppIdSessionApi* appid_session_api = appid_api.create_appid_session_api(*flow);
    CHECK_TRUE(appid_session_api);
    appid_api.free_appid_session_api(appid_session_api);

    Flow* old_flow = flow;
    flow = new Flow;
    flow->set_flow_data(nullptr);
    appid_session_api = appid_api.create_appid_session_api(*flow);
    CHECK_FALSE(appid_session_api);

    AppIdSession ignore_asd(IpProtocol::TCP, nullptr, 1492, appid_inspector);
    ignore_asd.common.flow_type = APPID_FLOW_TYPE_IGNORE;
    flow->set_flow_data(&ignore_asd);
    appid_session_api = appid_api.create_appid_session_api(*flow);
    CHECK_FALSE(appid_session_api);

    delete flow;
    flow = old_flow;
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    mock_session = new AppIdSession(IpProtocol::TCP, nullptr, 1492, appid_inspector);
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

