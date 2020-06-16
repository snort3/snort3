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

// appid_session_api_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_session_api.cc"

#include "appid_mock_definitions.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

AppIdSession* mock_session = nullptr;
AppIdSessionApi* appid_session_api = nullptr;
static AppIdConfig config;
static OdpContext odpctxt(config, nullptr);

TEST_GROUP(appid_session_api)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        mock_session = new AppIdSession(IpProtocol::TCP, nullptr, 1492, dummy_appid_inspector);
        appid_session_api = new AppIdSessionApi(mock_session);
    }

    void teardown() override
    {
        delete appid_session_api;
        delete mock_session;
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(appid_session_api, get_service_app_id)
{
    AppId id = appid_session_api->get_service_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_session_api, get_misc_app_id)
{
    AppId id = appid_session_api->get_misc_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = appid_session_api->get_misc_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = appid_session_api->get_misc_app_id(3);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_client_app_id)
{
    AppId id = appid_session_api->get_client_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = appid_session_api->get_client_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = appid_session_api->get_client_app_id(3);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_payload_app_id)
{
    AppId id = appid_session_api->get_payload_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = appid_session_api->get_payload_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = appid_session_api->get_payload_app_id(2);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_referred_app_id)
{
    AppId id = appid_session_api->get_referred_app_id();
    CHECK_EQUAL(id, APPID_UT_ID);
    id = appid_session_api->get_payload_app_id(0);
    CHECK_EQUAL(APPID_UT_ID, id);
    id = appid_session_api->get_payload_app_id(2);
    CHECK_EQUAL(APP_ID_NONE, id);
}

TEST(appid_session_api, get_tls_host)
{
    AppidChangeBits change_bits;
    char* host = snort_strdup(APPID_UT_TLS_HOST);
    mock_session->tsession->set_tls_host(host, 0, change_bits);
    const char* val = appid_session_api->get_tls_host();
    STRCMP_EQUAL(val, APPID_UT_TLS_HOST);
}

TEST(appid_session_api, get_initiator_ip)
{
    SfIp expected_ip;

    expected_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    SfIp* val = appid_session_api->get_initiator_ip();
    CHECK_TRUE(val->fast_eq4(expected_ip));
}

TEST(appid_session_api, is_appid_inspecting_session)
{
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    bool val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->clear_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    mock_session->set_session_flags(APPID_SESSION_ENCRYPTED);
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->session_packet_count = SSL_WHITELIST_PKT_LIMIT;
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);

    // 2nd if in is_appid_inspecting_session
    mock_session->clear_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);
    mock_session->client_disco_state = APPID_DISCO_STATE_FINISHED;
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(!val);

    // 3rd if in is_appid_inspecting_session
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT;
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->payload.set_id(APP_ID_SFTP);
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT - 1;
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(!val);
    mock_session->payload.set_id(APP_ID_NONE);
    mock_session->set_tp_app_id(APP_ID_SSH);
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);

    // 4th if in is_appid_inspecting_session
    mock_session->set_tp_app_id(APP_ID_NONE);
    mock_session->ctxt.get_odp_ctxt().check_host_port_app_cache = true;
    val = appid_session_api->is_appid_inspecting_session();
    CHECK_TRUE(val);
}

TEST(appid_session_api, is_appid_available)
{
    bool val;
    val = appid_session_api->is_appid_available();
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_NO_TPI);
    val = appid_session_api->is_appid_available();
    CHECK_TRUE(val);
}

TEST(appid_session_api, get_client_version)
{
    const char* val;
    val = appid_session_api->get_client_version();
    STRCMP_EQUAL(val, APPID_UT_CLIENT_VERSION);
    mock_session->create_http_session();
    val = appid_session_api->get_client_version(0);
    STRCMP_EQUAL(APPID_UT_CLIENT_VERSION, val);
    val = appid_session_api->get_client_version(2);
    STRCMP_EQUAL(nullptr, val);
}
TEST(appid_session_api, get_http_session)
{
    AppIdHttpSession* val;
    mock_session->create_http_session();
    val = appid_session_api->get_http_session();
    CHECK_TRUE(val != nullptr);
    val = appid_session_api->get_http_session(2);
    CHECK_TRUE(val == nullptr);
}
TEST(appid_session_api, get_appid_session_attribute)
{
    uint64_t flags = 0x0000000000000001;

    for ( unsigned i = 0; i < 64; i++ )
    {
        flags <<= i;
        mock_session->set_session_flags(flags);
        uint64_t fv = appid_session_api->get_appid_session_attribute(flags);
        CHECK_TRUE((fv & flags) == flags);
        mock_session->clear_session_flags(flags);
        fv = appid_session_api->get_appid_session_attribute(flags);
        CHECK_TRUE((fv & flags) == 0);
    }
}

TEST(appid_session_api, appid_dns_api)
{
    AppIdDnsSession* dsession = appid_session_api->get_dns_session();

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
    val = appid_session_api->is_http_inspection_done();
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    val = appid_session_api->is_http_inspection_done();
    CHECK_TRUE(val);
    AppidChangeBits change_bits;
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    val = appid_session_api->is_http_inspection_done();
    CHECK_FALSE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    char* host = snort_strdup(APPID_UT_TLS_HOST);
    mock_session->tsession->set_tls_host(host, 0, change_bits);
    val = appid_session_api->is_http_inspection_done();
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_SSL_SESSION);
    val = appid_session_api->is_http_inspection_done();
    CHECK_TRUE(val);
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

