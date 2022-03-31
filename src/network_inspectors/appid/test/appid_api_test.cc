//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

Packet::Packet(bool) { }
Packet::~Packet() = default;

Packet* DetectionEngine::get_current_packet()
{
    static Packet p;
    return &p;
}

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
}

void AppIdModule::reset_stats() {}

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

void AppIdSession::publish_appid_event(AppidChangeBits& change_bits, const Packet& p, bool, uint32_t)
{
    AppidEvent app_event(change_bits, false, 0, this->get_api(), p);
    DataBus::publish(APPID_EVENT_ANY_CHANGE, app_event, p.flow);
}

bool SslPatternMatchers::scan_hostname(const uint8_t* server_name, size_t, AppId& client_id, AppId& payload_id)
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

bool SslPatternMatchers::scan_cname(const uint8_t* cname, size_t, AppId& client_id, AppId& payload_id)
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

AppId AppIdSessionApi::get_service_app_id() const
{
    return application_ids[APP_PROTOID_SERVICE];
}

AppId AppIdSessionApi::get_client_app_id(uint32_t) const
{
    return application_ids[APP_PROTOID_CLIENT];
}

AppId AppIdSessionApi::get_payload_app_id(uint32_t) const
{
    return application_ids[APP_PROTOID_PAYLOAD];
}

void AppIdSession::set_ss_application_ids(AppId service_id, AppId client_id, AppId payload_id,
    AppId misc_id, AppId referred_id, AppidChangeBits& change_bits)
{
    if (api.application_ids[APP_PROTOID_SERVICE] != service_id)
    {
        api.application_ids[APP_PROTOID_SERVICE] = service_id;
        change_bits.set(APPID_SERVICE_BIT);
    }
    if (api.application_ids[APP_PROTOID_CLIENT] != client_id)
    {
        api.application_ids[APP_PROTOID_CLIENT] = client_id;
        change_bits.set(APPID_CLIENT_BIT);
    }
    if (api.application_ids[APP_PROTOID_PAYLOAD] != payload_id)
    {
        api.application_ids[APP_PROTOID_PAYLOAD] = payload_id;
        change_bits.set(APPID_PAYLOAD_BIT);
    }
    if (api.application_ids[APP_PROTOID_MISC] != misc_id)
    {
        api.application_ids[APP_PROTOID_MISC] = misc_id;
        change_bits.set(APPID_MISC_BIT);
    }
    if (api.application_ids[APP_PROTOID_REFERRED] != referred_id)
    {
        api.application_ids[APP_PROTOID_REFERRED] = referred_id;
        change_bits.set(APPID_REFERRED_BIT);
    }
}

void AppIdSession::set_ss_application_ids(AppId client_id, AppId payload_id,
    AppidChangeBits& change_bits)
{
    if (api.application_ids[APP_PROTOID_CLIENT] != client_id)
    {
        api.application_ids[APP_PROTOID_CLIENT] = client_id;
        change_bits.set(APPID_CLIENT_BIT);
    }
    if (api.application_ids[APP_PROTOID_PAYLOAD] != payload_id)
    {
        api.application_ids[APP_PROTOID_PAYLOAD] = payload_id;
        change_bits.set(APPID_PAYLOAD_BIT);
    }
}

AppIdHttpSession* AppIdSession::get_http_session(uint32_t) const { return nullptr; }

Flow* flow = nullptr;
AppIdSession* mock_session = nullptr;

TEST_GROUP(appid_api)
{
    char test_log[256];
    void setup() override
    {
        mock_init_appid_pegs();
        SfIp ip;
        mock_session = new AppIdSession(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector,
            dummy_appid_inspector.get_ctxt().get_odp_ctxt());
        pkt_thread_odp_ctxt = &mock_session->get_odp_ctxt();
        flow = new Flow;
        flow->set_flow_data(mock_session);
        mock().setDataObject("test_log", "char", test_log);
    }

    void teardown() override
    {
        delete flow;
        mock().clear();
        mock_cleanup_appid_pegs();
        delete &mock_session->get_api();
        delete mock_session;
    }
};

TEST(appid_api, get_application_name)
{
    AppIdConfig config;
    AppIdContext ctxt(config);
    const char* app_name = appid_api.get_application_name(1066, ctxt.get_odp_ctxt());
    STRCMP_EQUAL(app_name, test_app_name);
}

TEST(appid_api, get_application_id)
{
    AppIdConfig config;
    AppIdContext ctxt(config);
    AppId id = appid_api.get_application_id(test_app_name, ctxt);
    CHECK_EQUAL(id, 1492);
}

TEST(appid_api, ssl_app_group_id_lookup)
{
    mock().expectNCalls(5, "publish");
    AppId service, client, payload = APP_ID_NONE;
    bool val = false;

    AppidChangeBits change_bits;
    mock_session->set_ss_application_ids(APPID_UT_ID, APPID_UT_ID, APPID_UT_ID,
        APPID_UT_ID, APPID_UT_ID, change_bits);
    val = appid_api.ssl_app_group_id_lookup(flow, nullptr, nullptr, nullptr, nullptr,
        false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(service, APPID_UT_ID);
    CHECK_EQUAL(client, APPID_UT_ID);
    CHECK_EQUAL(payload, APPID_UT_ID);
    STRCMP_EQUAL("Published change_bits == 0000000000000000000", test_log);

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
    STRCMP_EQUAL("Published change_bits == 0000000000100011000", test_log);

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
    STRCMP_EQUAL("Published change_bits == 0000000000100011000", test_log);

    string host = "";
    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)(host.c_str()), nullptr,
        (const char*)APPID_UT_TLS_HOST, (const char*)"Google", false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 2);
    CHECK_EQUAL(payload, APPID_UT_ID + 2);
    STRCMP_EQUAL(mock_session->tsession->get_tls_host(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_org_unit(), "Google");
    STRCMP_EQUAL("Published change_bits == 0000000000100000000", test_log);

    // Override client id found by SSL pattern matcher with the client id provided by
    // Encrypted Visibility Engine if available
    service = APP_ID_NONE;
    client = APP_ID_NONE;
    payload = APP_ID_NONE;
    mock_session->set_client_id(APP_ID_NONE);
    mock_session->set_eve_client_app_id(APPID_UT_ID + 100);
    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST,
        (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST, false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 100);
    CHECK_EQUAL(payload, APPID_UT_ID + 1);
    STRCMP_EQUAL(mock_session->tsession->get_tls_host(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_first_alt_name(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL("Published change_bits == 0000000000100011000", test_log);

    mock().checkExpectations();
}

TEST(appid_api, is_inspection_needed)
{
    DummyInspector inspector;
    inspector.set_service(dummy_http2_protocol_id);
    dummy_appid_inspector.get_ctxt().config.snort_proto_ids[PROTO_INDEX_HTTP2] =
        dummy_http2_protocol_id;

    CHECK_TRUE(appid_api.is_inspection_needed(inspector));

    inspector.set_service(dummy_http2_protocol_id + 1);
    CHECK_FALSE(appid_api.is_inspection_needed(inspector));
}

TEST(appid_api, is_service_http_type)
{
    CHECK_TRUE(appid_api.is_service_http_type(APP_ID_HTTP));
    CHECK_TRUE(appid_api.is_service_http_type(APP_ID_HTTPS));
    CHECK_TRUE(appid_api.is_service_http_type(APP_ID_SMTPS));
    CHECK_FALSE(appid_api.is_service_http_type(APP_ID_SMTP));
}

TEST(appid_api, get_appid_detector_directory)
{
    STRCMP_EQUAL(appid_api.get_appid_detector_directory(), "/path/to/appid/detectors/");
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
