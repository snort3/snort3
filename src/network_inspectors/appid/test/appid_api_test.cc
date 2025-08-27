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

// appid_api_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_api.cc"

#include <string>

#include "framework/data_bus.h"
#include "managers/inspector_manager.h"
#include "protocols/protocol_ids.h"
#include "pub_sub/appid_event_ids.h"
#include "service_inspectors/http_inspect/http_msg_header.h"

#include "appid_http_session.h"
#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"
#include "appid_cpu_profile_table.h"

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
char const* APPID_UT_ORG_UNIT = "Google";
THREAD_LOCAL bool TimeProfilerStats::enabled = false;
#define ShadowTraffic_Type_Domain_Fronting    0x00000010

bool mock_inspector_exist = true;

namespace snort
{

class Inspector* InspectorManager::get_inspector(const char*, bool, const SnortConfig*)
{ return mock_inspector_exist ? &dummy_appid_inspector : nullptr; }

Packet::Packet(bool) { }
Packet::~Packet() = default;

Packet* DetectionEngine::get_current_packet()
{
    static Packet p;
    return &p;
}

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&)
{ }
}

void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

void AppIdModule::reset_stats() {}

class DummyInspector : public snort::Inspector
{
public:
    void eval(Packet*) override {};
};

void DataBus::publish(unsigned, unsigned, DataEvent& event, Flow*)
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
    DataBus::publish(0, AppIdEventIds::ANY_CHANGE, app_event, p.flow);
}

void AppIdSession::examine_ssl_metadata(AppidChangeBits& change_bits, bool partial_inspect)
{
    if (tsession == nullptr)
        return;

    set_service_id(APPID_UT_ID, get_odp_ctxt());
    api.client.set_id(APPID_UT_ID);
    api.payload.set_id(APPID_UT_ID);
}

bool HostPatternMatchers::scan_hostname(const uint8_t* server_name, size_t, AppId& client_id, AppId& payload_id)
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

bool HostPatternMatchers::scan_cname(const uint8_t* cname, size_t, AppId& client_id, AppId& payload_id)
{
    if (((const char*)cname) == APPID_UT_TLS_HOST)
    {
        client_id = APPID_UT_ID + 2;
        payload_id = APPID_UT_ID + 2;
    }
    else if (((const char*)cname) == APPID_UT_ORG_UNIT)
    {
        client_id = APPID_UT_ID + 3;
        payload_id = APPID_UT_ID + 3;
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

bool OdpContext::is_appid_cpu_profiler_enabled() { return false; }

void AppidCPUProfilingManager::cleanup_appid_cpu_profiler_table() {}

AppIdHttpSession* AppIdSession::get_http_session(uint32_t) const { return nullptr; }

Flow* flow = nullptr;
Flow* flow_no_session = nullptr;
AppIdSession* mock_session = nullptr;

TEST_GROUP(appid_api)
{
    char test_log[256];
    void setup() override
    {
        mock_init_appid_pegs();
        SfIp ip;
        mock_session = new AppIdSession(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector,
            dummy_appid_inspector.get_ctxt().get_odp_ctxt(), 0
#ifndef DISABLE_TENANT_ID
            ,0
#endif
            );
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

TEST_GROUP(appid_api_no_session)
{
    void setup()
    {
        mock_init_appid_pegs();
        flow_no_session = new Flow;
    }

    void teardown()
    {
        mock_cleanup_appid_pegs();
        delete flow_no_session;
    }
};

TEST(appid_api, get_application_name)
{
    AppIdConfig config;
    AppIdContext ctxt(config);
    const char* app_name = appid_api.get_application_name(1066, ctxt.get_odp_ctxt());
    STRCMP_EQUAL(app_name, test_app_name);
}

TEST(appid_api, get_appid_detector_directory_inspector_exist)
{
    auto res = appid_api.get_appid_detector_directory();
    STRCMP_EQUAL("test_dir", res);
}

TEST(appid_api, get_appid_detector_directory_inspector_does_not_exist)
{
    mock_inspector_exist = false;
    auto res = appid_api.get_appid_detector_directory();
    STRCMP_EQUAL("", res);
    mock_inspector_exist = true;
}

TEST(appid_api, get_application_id)
{
    AppIdConfig config;
    AppIdContext ctxt(config);
    AppId id = appid_api.get_application_id(test_app_name, ctxt);
    CHECK_EQUAL(id, 1492);
}

TEST(appid_api, set_ssl_certificate_key)
{
    AppIdConfig config;
    OdpContext odpctxt(config, nullptr);
    SfIp ip{};
    AppIdSession asd(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector, odpctxt, 0
#ifndef DISABLE_TENANT_ID
    ,0
#endif
    );
    string cert_key = "valid_certificate_key";
    appid_api.set_ssl_certificate_key(*flow, cert_key);
    asd.set_cert_key(cert_key);
    CHECK_EQUAL(asd.get_cert_key(), cert_key);
    delete &asd.get_api();
}

TEST(appid_api, ssl_app_group_id_lookup)
{
    mock().expectNCalls(1, "publish");
    AppId service, client, payload = APP_ID_NONE;
    bool val = false;

    AppidChangeBits change_bits;

    mock_session->set_ss_application_ids(0,0,0,0,0, change_bits);
    mock_session->tsession->set_tls_sni(nullptr, 0);
    mock_session->tsession->set_tls_cname(nullptr, 0);
    mock_session->tsession->set_tls_first_alt_name(nullptr, 0);
    mock_session->tsession->set_tls_org_unit(nullptr, 0);

    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST,
        (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_ORG_UNIT, false, service, client, payload);

    CHECK_TRUE(val);
    CHECK_EQUAL(service, APPID_UT_ID);
    CHECK_EQUAL(client, APPID_UT_ID);
    CHECK_EQUAL(payload, APPID_UT_ID);
    STRCMP_EQUAL(mock_session->tsession->get_tls_sni(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_first_alt_name(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_org_unit(), APPID_UT_ORG_UNIT);
    mock().checkExpectations();
}

TEST(appid_api, ssl_app_group_id_lookup_sni_mismatch)
{
    mock().expectNCalls(1, "publish");
    AppId service, client, payload = APP_ID_NONE;
    bool val = false;

    AppidChangeBits change_bits;

    mock_session->set_ss_application_ids(0,0,0,0,0, change_bits);
    mock_session->tsession->set_tls_sni(nullptr, 0);
    mock_session->tsession->set_tls_cname(nullptr, 0);
    mock_session->tsession->set_tls_first_alt_name(nullptr, 0);
    mock_session->tsession->set_tls_org_unit(nullptr, 0);

    val = appid_api.ssl_app_group_id_lookup(flow, (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST,
        (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_ORG_UNIT, true, service, client, payload);

    CHECK_TRUE(val);
    CHECK_TRUE(mock_session->tsession->is_tls_host_mismatched());
    CHECK_EQUAL(service, APPID_UT_ID);
    CHECK_EQUAL(client, APPID_UT_ID);
    CHECK_EQUAL(payload, APPID_UT_ID);
    STRCMP_EQUAL(mock_session->tsession->get_tls_sni(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_first_alt_name(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_cname(), APPID_UT_TLS_HOST);
    STRCMP_EQUAL(mock_session->tsession->get_tls_org_unit(), APPID_UT_ORG_UNIT);
    mock().checkExpectations();
}

TEST(appid_api_no_session, ssl_app_group_id_lookup)
{
    AppId service, client, payload = APP_ID_NONE;
    bool val = false;

    AppidChangeBits change_bits;
    
    flow_no_session->free_flow_data(1);
    val = appid_api.ssl_app_group_id_lookup(flow_no_session, (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST,
        (const char*)APPID_UT_TLS_HOST, (const char*)APPID_UT_TLS_HOST, false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 1);
    CHECK_EQUAL(payload, APPID_UT_ID + 1);

    // 2. First alt name match
    client = APP_ID_NONE;
    payload = APP_ID_NONE;
    val = appid_api.ssl_app_group_id_lookup(flow_no_session, nullptr, (const char*)APPID_UT_TLS_HOST,
        nullptr, (const char*)APPID_UT_TLS_HOST, false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 1);
    CHECK_EQUAL(payload, APPID_UT_ID + 1);

    // 3. CN match
    client = APP_ID_NONE;
    payload = APP_ID_NONE;
    val = appid_api.ssl_app_group_id_lookup(flow_no_session, nullptr, nullptr, (const char*)APPID_UT_TLS_HOST,
        (const char*)APPID_UT_TLS_HOST, false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 2);
    CHECK_EQUAL(payload, APPID_UT_ID + 2);

    // 4. Org unit match
    client = APP_ID_NONE;
    payload = APP_ID_NONE;
    val = appid_api.ssl_app_group_id_lookup(flow_no_session, nullptr, nullptr, nullptr, (const char*)APPID_UT_TLS_HOST,
        false, service, client, payload);
    CHECK_TRUE(val);
    CHECK_EQUAL(client, APPID_UT_ID + 2);
    CHECK_EQUAL(payload, APPID_UT_ID + 2);
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

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
