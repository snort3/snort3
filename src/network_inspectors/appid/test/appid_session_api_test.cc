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

// appid_session_api_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_session_api.cc"

#include "appid_mock_definitions.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

AppIdSession* mock_session = nullptr;
AppIdSessionApi* appid_session_api = nullptr;
static AppIdConfig config;
static OdpContext odpctxt(config, nullptr);
static Flow flow;

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
void AppIdModule::reset_stats() {}

Inspector* InspectorManager::get_inspector(char const*, bool, const snort::SnortConfig*)
{
    return nullptr;
}

namespace snort
{
    unsigned get_instance_id()
    {
        return 0;
    }
}

void AppIdSession::set_ss_application_ids(AppId service_id, AppId client_id, AppId payload_id,
    AppId misc_id, AppId referred_id, AppidChangeBits& change_bits)
{
    api.set_ss_application_ids(service_id, client_id, payload_id, misc_id, referred_id, change_bits, *flow);
}

void AppIdSession::set_application_ids_service(AppId service_id, AppidChangeBits& change_bits)
{
    api.set_application_ids_service(service_id, change_bits, *flow);
}

TEST_GROUP(appid_session_api)
{
    void setup() override
    {
        AppidChangeBits change_bits;

        SfIp ip;
        mock_session = new AppIdSession(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector, odpctxt);
        mock_session->flow = &flow;
        pkt_thread_odp_ctxt = &mock_session->get_odp_ctxt();
        mock_session->set_ss_application_ids(APPID_UT_ID, APPID_UT_ID, APPID_UT_ID,
            APPID_UT_ID, APPID_UT_ID, change_bits);
    }

    void teardown() override
    {
        delete &mock_session->get_api();
        delete mock_session;
    }
};

TEST(appid_session_api, get_service_app_id)
{
    AppId id = mock_session->get_api().get_service_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_session_api, get_misc_app_id)
{
    AppId id = mock_session->get_api().get_misc_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = mock_session->get_api().get_misc_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = mock_session->get_api().get_misc_app_id(3);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_client_app_id)
{
    AppId id = mock_session->get_api().get_client_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = mock_session->get_api().get_client_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = mock_session->get_api().get_client_app_id(3);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_payload_app_id)
{
    AppId id = mock_session->get_api().get_payload_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = mock_session->get_api().get_payload_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = mock_session->get_api().get_payload_app_id(2);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_referred_app_id)
{
    AppId id = mock_session->get_api().get_referred_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = mock_session->get_api().get_referred_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = mock_session->get_api().get_referred_app_id(2);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_app_id)
{
    SfIp ip;
    AppIdSession asd(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector, odpctxt);
    asd.flow = &flow;
    AppidChangeBits change_bits;
    asd.set_application_ids_service(APP_ID_HTTP2, change_bits);

    AppId service, client, payload, misc, referred;
    asd.get_api().get_app_id(service, client, payload, misc, referred, 0);

    CHECK_EQUAL(service, APP_ID_HTTP2);
    CHECK_EQUAL(client, APP_ID_NONE);
    CHECK_EQUAL(payload, APP_ID_NONE);
    CHECK_EQUAL(misc, APP_ID_NONE);
    CHECK_EQUAL(referred, APP_ID_NONE);

    service = client = payload = misc = referred = APPID_UT_ID;
    asd.get_api().get_app_id(&service, &client, &payload, &misc, &referred, 0);

    CHECK_EQUAL(service, APP_ID_HTTP2);
    CHECK_EQUAL(client, APP_ID_NONE);
    CHECK_EQUAL(payload, APP_ID_NONE);
    CHECK_EQUAL(misc, APP_ID_NONE);
    CHECK_EQUAL(referred, APP_ID_NONE);

    delete &asd.get_api();
}

TEST(appid_session_api, get_tls_host)
{
    AppidChangeBits change_bits;
    change_bits.set(APPID_TLSHOST_BIT);
    mock_session->tsession->set_tls_host(nullptr, 0, change_bits);
    mock_session->set_tls_host(change_bits);
    const char* val = mock_session->get_api().get_tls_host();
    STRCMP_EQUAL(val, nullptr);
    char* host = snort_strdup(APPID_UT_TLS_HOST);
    mock_session->tsession->set_tls_host(host, 0, change_bits);
    mock_session->set_tls_host(change_bits);
    val = mock_session->get_api().get_tls_host();
    STRCMP_EQUAL(val, APPID_UT_TLS_HOST);
}

TEST(appid_session_api, get_initiator_ip)
{
    SfIp expected_ip;

    expected_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    const SfIp* val = mock_session->get_api().get_initiator_ip();
    CHECK_TRUE(val->fast_eq4(expected_ip));
}

TEST(appid_session_api, is_appid_inspecting_session)
{
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    bool val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->clear_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    mock_session->set_session_flags(APPID_SESSION_ENCRYPTED);
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->session_packet_count = SSL_ALLOWLIST_PKT_LIMIT;
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);

    // 2nd if in is_appid_inspecting_session
    mock_session->clear_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->client_disco_state = APPID_DISCO_STATE_FINISHED;
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(!val);

    // 3rd if in is_appid_inspecting_session
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT;
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->set_payload_id(APP_ID_SFTP);
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT - 1;
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->set_payload_id(APP_ID_NONE);
    AppidChangeBits change_bits;
    mock_session->set_application_ids_service(APP_ID_SSH, change_bits);
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);

    // 4th if in is_appid_inspecting_session
    mock_session->set_application_ids_service(APP_ID_NONE, change_bits);
    mock_session->get_odp_ctxt().check_host_port_app_cache = true;
    val = mock_session->get_api().is_appid_inspecting_session();
    CHECK_TRUE(val);
}

TEST(appid_session_api, is_appid_available)
{
    bool val;
    val = mock_session->get_api().is_appid_available();
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_NO_TPI);
    val = mock_session->get_api().is_appid_available();
    CHECK_TRUE(val);
}

TEST(appid_session_api, get_client_info)
{
    const char* val;
    val = mock_session->get_api().get_client_info();
    STRCMP_EQUAL(val, APPID_UT_CLIENT_VERSION);
    mock_session->create_http_session();
    val = mock_session->get_api().get_client_info(0);
    STRCMP_EQUAL(APPID_UT_CLIENT_VERSION, val);
    val = mock_session->get_api().get_client_info(2);
    STRCMP_EQUAL(nullptr, val);
}
TEST(appid_session_api, get_http_session)
{
    const AppIdHttpSession* val;
    mock_session->create_http_session();
    val = mock_session->get_api().get_http_session();
    CHECK_TRUE(val != nullptr);
    val = mock_session->get_api().get_http_session(2);
    CHECK_TRUE(val == nullptr);
}
TEST(appid_session_api, get_appid_session_attribute)
{
    uint64_t flags = 0x0000000000000001;

    for ( unsigned i = 0; i < 64; i++ )
    {
        flags <<= i;
        mock_session->set_session_flags(flags);
        uint64_t fv = mock_session->get_api().get_appid_session_attribute(flags);
        CHECK_TRUE((fv & flags) == flags);
        mock_session->clear_session_flags(flags);
        fv = mock_session->get_api().get_appid_session_attribute(flags);
        CHECK_TRUE((fv & flags) == 0);
    }
}

TEST(appid_session_api, appid_dns_api)
{
    const AppIdDnsSession* dsession = mock_session->get_api().get_dns_session();

    const char* val = dsession->get_host();
    STRCMP_EQUAL(val, APPID_ID_UT_DNS_HOST);
    uint8_t query_len = dsession->get_host_len();
    CHECK_TRUE(query_len == strlen(APPID_ID_UT_DNS_HOST));

    uint16_t qoff;
    qoff = dsession->get_host_offset();
    CHECK_TRUE(qoff == APPID_UT_DNS_HOST_OFFSET);

    uint16_t rt;
    rt = dsession->get_record_type();
    CHECK_TRUE(rt == APPID_UT_DNS_PATTERN_CNAME_REC);

    uint8_t rc;
    rc = dsession->get_response_type();
    CHECK_TRUE(rc == APPID_UT_DNS_NOERROR);

    uint32_t ttl;
    ttl = dsession->get_ttl();
    CHECK_TRUE(ttl == APPID_UT_DNS_TTL);
}

TEST(appid_session_api, is_http_inspection_done)
{
    bool val;
    val = mock_session->get_api().is_http_inspection_done();
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    val = mock_session->get_api().is_http_inspection_done();
    CHECK_TRUE(val);
    AppidChangeBits change_bits;
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    val = mock_session->get_api().is_http_inspection_done();
    CHECK_FALSE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    char* host = snort_strdup(APPID_UT_TLS_HOST);
    mock_session->tsession->set_tls_host(host, 0, change_bits);
    change_bits.set(APPID_TLSHOST_BIT);
    mock_session->set_tls_host(change_bits);
    val = mock_session->get_api().is_http_inspection_done();
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    val = mock_session->get_api().is_http_inspection_done();
    CHECK_TRUE(val);
}

TEST(appid_session_api, get_client_app_detect_type)
{
    // Confirm that default detect type is APPID.
    ClientAppDetectType detect_type = mock_session->get_api().get_client_app_detect_type();
    CHECK_EQUAL(detect_type, CLIENT_APP_DETECT_APPID);

    /* Set eve client app to some appid, but keep normal client id set to none.
       The eve_client app should be picked, but the detect type should be TLS_FP.  */
    mock_session->set_client_id(APP_ID_NONE);
    mock_session->set_eve_client_app_id(638);
    AppId id = mock_session->pick_ss_client_app_id();
    CHECK_EQUAL(id, 638);
    detect_type = mock_session->get_api().get_client_app_detect_type();   
    CHECK_EQUAL(detect_type, CLIENT_APP_DETECT_TLS_FP);

    /* Now set the normal client id to something. That is the appid that should be picked,
       and the detect type should be APPID once more. */
    mock_session->set_client_id(APP_ID_HTTP2);
    id = mock_session->pick_ss_client_app_id();
    CHECK_EQUAL(id, APP_ID_HTTP2);
    detect_type = mock_session->get_api().get_client_app_detect_type();
    CHECK_EQUAL(detect_type, CLIENT_APP_DETECT_APPID);
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

