//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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
#include <CppUTestExt/MockSupport.h>

using namespace snort;

static SnortProtocolId dummy_http2_protocol_id = 1;

namespace snort
{

class Inspector* InspectorManager::get_inspector(const char*, bool, const SnortConfig*)
{ return &dummy_appid_inspector; }

}

class DummyInspector : public snort::Inspector
{
public:
    void eval(Packet*) override {};
};

void DataBus::publish(const char*, DataEvent& event, Flow*)
{
    AppidEvent* appid_event = (AppidEvent*)&event;
    char* test_log = (char*)mock().getData("test_log").getObjectPointer();
    snprintf(test_log, 256, "Published change_bits == %s",
        appid_event->get_change_bitset().to_string().c_str());
    mock().actualCall("publish");
}

void AppIdSession::publish_appid_event(AppidChangeBits& change_bits, Flow* flow, bool, uint32_t)
{
    AppidEvent app_event(change_bits, false, 0);
    DataBus::publish(APPID_EVENT_ANY_CHANGE, app_event, flow);
}

bool SslPatternMatchers::scan_hostname(unsigned char const* server_name, unsigned long, AppId& client_id, AppId& payload_id)
{
    if (((const char*)server_name) == APPID_UT_TLS_HOST)
    {
        client_id = APPID_UT_ID + 1;
        payload_id = APPID_UT_ID + 1;
    }
    else
    {
        client_id = 0;
        payload_id = 0;
    }
    return true;
}

bool SslPatternMatchers::scan_cname(unsigned char const* cname, unsigned long, AppId& client_id, AppId& payload_id)
{
    if (((const char*)cname) == APPID_UT_TLS_HOST)
    {
        client_id = APPID_UT_ID + 2;;
        payload_id = APPID_UT_ID + 2;
    }
    else
    {
        client_id = 0;
        payload_id = 0;
    }
    return true;
}

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

const char* AppInfoManager::get_app_name(AppId)
{
    return test_app_name;
}

AppId AppInfoManager::get_appid_by_name(const char*)
{
    return APPID_UT_ID;
}

Flow* flow = nullptr;
AppIdSession* mock_session = nullptr;

TEST_GROUP(appid_api)
{
    char test_log[256];
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        flow = new Flow;
        flow->set_flow_data(mock_session);
        mock().setDataObject("test_log", "char", test_log);
    }

    void teardown() override
    {
        delete flow;
        mock().clear();
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(appid_api, get_application_name)
{
    AppIdConfig config;
    AppIdContext ctxt(config);
    const char* app_name = appid_api.get_application_name(1066, ctxt);
    STRCMP_EQUAL(app_name, test_app_name);
}

TEST(appid_api, get_application_id)
{
    AppIdConfig config;
    AppIdContext ctxt(config);
    AppId id = appid_api.get_application_id(test_app_name, ctxt);
    CHECK_EQUAL(id, 1492);
}

TEST(appid_api, produce_ha_state)
{
    AppIdSessionHA appHA, cmp_buf;

    memset((void*)&appHA, 0, sizeof(appHA));
    memset((void*)&cmp_buf, 0, sizeof(cmp_buf));
    mock_session->common.flags |= APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_HTTP_SESSION;

    mock_session->set_tp_app_id(APPID_UT_ID);
    mock_session->service.set_id(APPID_UT_ID + 1, stub_odp_ctxt);
    mock_session->client_inferred_service_id = APPID_UT_ID + 2;
    mock_session->service.set_port_service_id(APPID_UT_ID + 3);
    mock_session->payload.set_id(APPID_UT_ID + 4);
    mock_session->set_tp_payload_app_id(APPID_UT_ID + 5);
    mock_session->client.set_id(APPID_UT_ID + 6);
    mock_session->misc_app_id = APPID_UT_ID + 7;

    uint32_t val = appid_api.produce_ha_state(*flow, (uint8_t*)&appHA);
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
    val = appid_api.consume_ha_state(*flow, (uint8_t*)&appHA, 0, IpProtocol::TCP, &ip, 1066);
    CHECK_TRUE(val == sizeof(appHA));

    AppIdSession* session = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);
    CHECK_TRUE(session);
    CHECK_TRUE(session->get_tp_app_id() == appHA.appId[0]);
    CHECK_TRUE(session->service.get_id() == appHA.appId[1]);
    CHECK_TRUE(session->client_inferred_service_id == appHA.appId[2]);
    CHECK_TRUE(session->service.get_port_service_id() == appHA.appId[3]);
    CHECK_TRUE(session->payload.get_id() == appHA.appId[4]);
    CHECK_TRUE(session->get_tp_payload_app_id() == appHA.appId[5]);
    CHECK_TRUE(session->client.get_id() == appHA.appId[6]);
    CHECK_TRUE(session->misc_app_id == appHA.appId[7]);
    CHECK_TRUE(session->service_disco_state == APPID_DISCO_STATE_FINISHED);
    CHECK_TRUE(session->client_disco_state == APPID_DISCO_STATE_FINISHED);
    delete session;

    // test logic when service app is ftp control
    appHA.appId[1] = APP_ID_FTP_CONTROL;
    mock_flow_data= nullptr;
    val = appid_api.consume_ha_state(*flow, (uint8_t*)&appHA, 0, IpProtocol::TCP, &ip, 1066);
    CHECK_TRUE(val == sizeof(appHA));

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

TEST(appid_api, ssl_app_group_id_lookup)
{
    mock().expectNCalls(4, "publish");
    AppId service, client, payload = APP_ID_NONE;
    bool val = false;

    val = appid_api.ssl_app_group_id_lookup(flow, nullptr, nullptr, nullptr, nullptr,
        false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(service, APPID_UT_ID);
    CHECK_EQUAL(client, APPID_UT_ID);
    CHECK_EQUAL(payload, APPID_UT_ID);
    STRCMP_EQUAL("Published change_bits == 000000001111", test_log);

    service = APP_ID_NONE;
    client = APP_ID_NONE;
    payload = APP_ID_NONE;
    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST,
        (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST, false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 1);
    CHECK_EQUAL(payload, APPID_UT_ID + 1);
    STRCMP_EQUAL(mock_session->tsession->get_tls_host(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_first_alt_name(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL("Published change_bits == 000001000110", test_log);

    AppidChangeBits change_bits;
    mock_session->tsession->set_tls_host("www.cisco.com", 13, change_bits);
    mock_session->tsession->set_tls_cname("www.cisco.com", 13, change_bits);
    mock_session->tsession->set_tls_org_unit("Cisco", 5);
    STRCMP_EQUAL(mock_session->tsession->get_tls_host(), "www.cisco.com");
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), "www.cisco.com");
    STRCMP_EQUAL(mock_session->tsession->get_tls_org_unit(), "Cisco");
    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)"www.google.com",
        nullptr, (const char*)APPID_UT_TLS_HOST, nullptr, false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 2);
    CHECK_EQUAL(payload, APPID_UT_ID + 2);
    STRCMP_EQUAL(mock_session->tsession->get_tls_host(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_org_unit(), "Cisco");
    STRCMP_EQUAL("Published change_bits == 000001000110", test_log);

    string host = "";
    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)(host.c_str()), nullptr,
        (const char*)APPID_UT_TLS_HOST, (const char*)"Google", false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 2);
    CHECK_EQUAL(payload, APPID_UT_ID + 2);
    STRCMP_EQUAL(mock_session->tsession->get_tls_host(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_org_unit(), "Google");
    STRCMP_EQUAL("Published change_bits == 000001000000", test_log);
    mock().checkExpectations();
}

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

    delete flow;
    flow = old_flow;
}

TEST(appid_api, is_inspection_needed)
{
    DummyInspector inspector;
    inspector.set_service(dummy_http2_protocol_id);
    dummy_appid_inspector.get_ctxt().config.snortId_for_http2 = dummy_http2_protocol_id;
    CHECK_TRUE(appid_api.is_inspection_needed(inspector));

    inspector.set_service(dummy_http2_protocol_id + 1);
    CHECK_FALSE(appid_api.is_inspection_needed(inspector));
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    mock_session = new AppIdSession(IpProtocol::TCP, nullptr, 1492, dummy_appid_inspector);
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}
