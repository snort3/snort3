//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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
#include "thirdparty_appid_api.h"

#include "appid_mock_definitions.h"
#include "appid_mock_http_session.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

void BootpServiceDetector::AppIdFreeDhcpData(DHCPData* data)
{
    delete data;
}

void BootpServiceDetector::AppIdFreeDhcpInfo(DHCPInfo* info)
{
    delete info;
}

void NbdgmServiceDetector::AppIdFreeSMBData(FpSMBData* data)
{
    delete data;
}

const char* AppInfoManager::get_app_name(AppId)
{
    return test_app_name;
}

int32_t AppInfoManager::get_appid_by_name(const char*)
{
    return APPID_UT_ID;
}

AppInfoManager& app_info_mgr = AppInfoManager::get_instance();

Flow* flow = nullptr;
AppIdSession* mock_session = nullptr;

TEST_GROUP(appid_api)
{
    void setup()
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        flow = new Flow;
        mock_session = new AppIdSession(IpProtocol::TCP, nullptr, 1492);
        mock_session->hsession = init_http_session(mock_session);
        flow->set_flow_data(mock_session);
    }

    void teardown()
    {
        delete mock_session;
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

TEST(appid_api, get_service_app_id)
{
    AppId id = appid_api.get_service_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_service_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_port_service_app_id)
{
    AppId id = appid_api.get_port_service_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_port_service_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID + 3);
}

TEST(appid_api, get_only_service_app_id)
{
    AppId id = appid_api.get_only_service_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_only_service_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_misc_app_id)
{
    AppId id = appid_api.get_misc_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_misc_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_client_app_id)
{
    AppId id = appid_api.get_client_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_client_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_payload_app_id)
{
    AppId id = appid_api.get_payload_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_payload_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_referred_app_id)
{
    AppId id = appid_api.get_referred_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_referred_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_service_app_id)
{
    AppId id = appid_api.get_fw_service_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_fw_service_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_misc_app_id)
{
    AppId id = appid_api.get_fw_misc_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_fw_misc_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_client_app_id)
{
    AppId id = appid_api.get_fw_client_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_fw_client_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_payload_app_id)
{
    AppId id = appid_api.get_fw_payload_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_fw_payload_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_referred_app_id)
{
    AppId id = appid_api.get_fw_referred_app_id(nullptr);
    CHECK_EQUAL(id, APP_ID_NONE);
    id = appid_api.get_fw_referred_app_id(mock_session);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_flow_type)
{
    APPID_FLOW_TYPE ft = appid_api.get_flow_type(nullptr);
    CHECK_EQUAL(ft, APPID_FLOW_TYPE_IGNORE);
    ft = appid_api.get_flow_type(mock_session);
    CHECK_EQUAL(ft, APPID_FLOW_TYPE_NORMAL);
}

TEST(appid_api, get_service_port)
{
    short sp = appid_api.get_service_port(nullptr);
    CHECK_EQUAL(sp, 0);
    sp = appid_api.get_service_port(mock_session);
    CHECK_EQUAL(sp, APPID_UT_SERVICE_PORT);
}

TEST(appid_api, get_http_user_agent)
{
    const char* val = appid_api.get_http_user_agent(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_user_agent(mock_session);
    STRCMP_EQUAL(val, USERAGENT);
}

TEST(appid_api, get_http_host)
{
    const char* val = appid_api.get_http_host(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_host(mock_session);
    STRCMP_EQUAL(val, HOST);
}

TEST(appid_api, get_http_url)
{
    const char* val = appid_api.get_http_url(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_url(mock_session);
    STRCMP_EQUAL(val, URL);
}

TEST(appid_api, get_http_referer)
{
    const char* val = appid_api.get_http_referer(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_referer(mock_session);
    STRCMP_EQUAL(val, REFERER);
}

TEST(appid_api, get_http_uri)
{
    const char* val = appid_api.get_http_uri(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_uri(mock_session);
    STRCMP_EQUAL(val, URI);
}

TEST(appid_api, get_http_new_url)
{
    init_hsession_new_fields(mock_session->hsession);

    const char* val = appid_api.get_http_new_url(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_new_url(mock_session);
    STRCMP_EQUAL(val, URI);
}

TEST(appid_api, get_http_response_code)
{
    const char* val = appid_api.get_http_response_code(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_response_code(mock_session);
    STRCMP_EQUAL(val, RESPONSE_CODE);
}

TEST(appid_api, get_http_cookie)
{
    const char* val = appid_api.get_http_cookie(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_cookie(mock_session);
    STRCMP_EQUAL(val, COOKIE);
}

TEST(appid_api, get_http_new_cookie)
{
    init_hsession_new_fields(mock_session->hsession);

    const char* val = appid_api.get_http_new_cookie(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_new_cookie(mock_session);
    STRCMP_EQUAL(val, NEW_COOKIE);
}

TEST(appid_api, free_http_new_field)
{
    init_hsession_new_fields(mock_session->hsession);

    for (unsigned i = 0; i <= HTTP_FIELD_MAX; i++)
    {
        const char* val = appid_api.get_http_new_field(mock_session, (HTTP_FIELD_ID)i);
        CHECK_TRUE(val)
        appid_api.free_http_new_field(mock_session, (HTTP_FIELD_ID)i);
        CHECK_TRUE(!mock_session->hsession->new_field[i]);
    }
}

TEST(appid_api, get_http_new_field)
{
    init_hsession_new_fields(mock_session->hsession);

    const char* val = appid_api.get_http_new_field(nullptr, REQ_AGENT_FID);
    CHECK_TRUE(!val);
    val = appid_api.get_http_new_field(mock_session, REQ_HOST_FID);
    STRCMP_EQUAL(val, HOST);
    val = appid_api.get_http_new_field(mock_session, REQ_REFERER_FID);
    STRCMP_EQUAL(val, REFERER);
    val = appid_api.get_http_new_field(mock_session, REQ_URI_FID);
    STRCMP_EQUAL(val, URI);
    val = appid_api.get_http_new_field(mock_session, REQ_COOKIE_FID);
    STRCMP_EQUAL(val, NEW_COOKIE);
    val = appid_api.get_http_new_field(mock_session, REQ_BODY_FID);
    STRCMP_EQUAL(val, REQ_BODY);
    val = appid_api.get_http_new_field(mock_session, RSP_CONTENT_TYPE_FID);
    STRCMP_EQUAL(val, CONTENT_TYPE);
    val = appid_api.get_http_new_field(mock_session, RSP_LOCATION_FID);
    STRCMP_EQUAL(val, LOCATION);
    val = appid_api.get_http_new_field(mock_session, RSP_BODY_FID);
    STRCMP_EQUAL(val, RSP_BODY);
    val = appid_api.get_http_new_field(mock_session, REQ_AGENT_FID);
    STRCMP_EQUAL(val, USERAGENT);
    val = appid_api.get_http_new_field(mock_session, (HTTP_FIELD_ID)(HTTP_FIELD_MAX + 1));
    CHECK_TRUE(!val);
}

TEST(appid_api, get_http_content_type)
{
    const char* val = appid_api.get_http_content_type(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_content_type(mock_session);
    STRCMP_EQUAL(val, CONTENT_TYPE);
}

TEST(appid_api, get_http_location)
{
    const char* val = appid_api.get_http_location(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_location(mock_session);
    STRCMP_EQUAL(val, LOCATION);
}

TEST(appid_api, get_http_body)
{
    const char* val = appid_api.get_http_body(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_body(mock_session);
    STRCMP_EQUAL(val, RSP_BODY);
}

TEST(appid_api, get_http_request_body)
{
    const char* val = appid_api.get_http_request_body(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_http_request_body(mock_session);
    STRCMP_EQUAL(val, REQ_BODY);
}

TEST(appid_api, get_http_uri_offset)
{
    uint16_t val = appid_api.get_http_uri_offset(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_http_uri_offset(mock_session);
    CHECK_TRUE(val == URI_OFFSET);
    val = appid_api.get_http_uri_end_offset(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_http_uri_end_offset(mock_session);
    CHECK_TRUE(val == URI_OFFSET + strlen(URI));
}

TEST(appid_api, get_http_cookie_offset)
{
    uint16_t val = appid_api.get_http_cookie_offset(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_http_cookie_offset(mock_session);
    CHECK_TRUE(val == COOKIE_OFFSET);
    val = appid_api.get_http_cookie_end_offset(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_http_cookie_end_offset(mock_session);
    CHECK_TRUE(val == COOKIE_OFFSET + strlen(NEW_COOKIE));
}

TEST(appid_api, get_http_search)
{
    SEARCH_SUPPORT_TYPE val = appid_api.get_http_search(nullptr);
    CHECK_TRUE(val == NOT_A_SEARCH_ENGINE);
    val = appid_api.get_http_search(mock_session);
    CHECK_TRUE(val == NOT_A_SEARCH_ENGINE);
    mock_session->search_support_type = SUPPORTED_SEARCH_ENGINE;
    val = appid_api.get_http_search(mock_session);
    CHECK_TRUE(val == SUPPORTED_SEARCH_ENGINE);
    mock_session->search_support_type = UNSUPPORTED_SEARCH_ENGINE;
    val = appid_api.get_http_search(mock_session);
    CHECK_TRUE(val == UNSUPPORTED_SEARCH_ENGINE);
    mock_session->search_support_type = NOT_A_SEARCH_ENGINE;
    val = appid_api.get_http_search(mock_session);
    CHECK_TRUE(val == NOT_A_SEARCH_ENGINE);
}

TEST(appid_api, get_http_xff_addr)
{
    SfIp expected_ip_xff;

    expected_ip_xff.pton(AF_INET, APPID_UT_XFF_IP_ADDR);

    SfIp* val = appid_api.get_http_xff_addr(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_http_xff_addr(mock_session);
    CHECK_TRUE(val->fast_eq4(expected_ip_xff));
}

TEST(appid_api, get_tls_host)
{
    const char* val = appid_api.get_tls_host(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_tls_host(mock_session);
    STRCMP_EQUAL(val, APPID_UT_TLS_HOST);
}

TEST(appid_api, get_service_ip)
{
    SfIp expected_ip;

    expected_ip.pton(AF_INET, APPID_UT_SERVICE_IP_ADDR);

    SfIp* val = appid_api.get_service_ip(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_service_ip(mock_session);
    CHECK_TRUE(val->fast_eq4(expected_ip));
}

TEST(appid_api, get_initiator_ip)
{
    SfIp expected_ip;

    expected_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    SfIp* val = appid_api.get_initiator_ip(nullptr);
    CHECK_TRUE(val == 0);
    val = appid_api.get_initiator_ip(mock_session);
    CHECK_TRUE(val->fast_eq4(expected_ip));
}

TEST(appid_api, get_netbios_name)
{
    const char* val = appid_api.get_netbios_name(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_netbios_name(mock_session);
    STRCMP_EQUAL(val, APPID_UT_NETBIOS_NAME);
    snort_free((void*)val);
    val = appid_api.get_netbios_name(nullptr);
    CHECK_TRUE(!val);
}

TEST(appid_api, is_ssl_session_decrypted)
{
    bool val = appid_api.is_ssl_session_decrypted(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.is_ssl_session_decrypted(mock_session);
    CHECK_TRUE(!val);
    is_session_decrypted = true;
    val = appid_api.is_ssl_session_decrypted(mock_session);
    CHECK_TRUE(val);
}

TEST(appid_api, is_appid_inspecting_session)
{
    bool val = appid_api.is_appid_inspecting_session(nullptr);
    CHECK_TRUE(!val);
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(val);
    mock_session->clear_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    mock_session->set_session_flags(APPID_SESSION_ENCRYPTED);
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->session_packet_count = SSL_WHITELIST_PKT_LIMIT;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(val);

    // 2nd if in is_appid_inspecting_session
    mock_session->clear_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(!val);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(val);
    mock_session->client_disco_state = APPID_DISCO_STATE_FINISHED;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(!val);

    // 3rd if in is_appid_inspecting_session
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(!val);
    mock_session->payload_app_id = APP_ID_SFTP;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(!val);
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT - 1;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(!val);
    mock_session->payload_app_id = APP_ID_NONE;
    mock_session->tp_app_id = APP_ID_SSH;
    val = appid_api.is_appid_inspecting_session(mock_session);
    CHECK_TRUE(val);
}

TEST(appid_api, get_user_name)
{
    AppId service;
    bool isLoginSuccessful;

    char* val = appid_api.get_user_name(nullptr, &service, &isLoginSuccessful);
    CHECK_TRUE(!val);
    val = appid_api.get_user_name(mock_session, &service, &isLoginSuccessful);
    STRCMP_EQUAL(val, APPID_UT_USERNAME);
    CHECK_TRUE(service == APPID_UT_ID);
    CHECK_TRUE(!isLoginSuccessful);
    mock_session->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
    snort_free(val);
    val = appid_api.get_user_name(mock_session, &service, &isLoginSuccessful);
    CHECK_TRUE(!val);
    CHECK_TRUE(service == APPID_UT_ID);
    CHECK_TRUE(isLoginSuccessful);
}

TEST(appid_api, is_appid_available)
{
    bool val = appid_api.is_appid_available(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.is_appid_available(mock_session);
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_NO_TPI);
    val = appid_api.is_appid_available(mock_session);
    CHECK_TRUE(val);
}

TEST(appid_api, get_client_version)
{
    char* val = appid_api.get_client_version(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_client_version(mock_session);
    STRCMP_EQUAL(val, APPID_UT_CLIENT_VERSION);
}

TEST(appid_api, get_appid_session_attribute)
{
    uint64_t flags = 0x0000000000000001;

    for ( unsigned i = 0; i < 64; i++ )
    {
        flags <<= i;
        mock_session->set_session_flags(flags);
        uint64_t fv = appid_api.get_appid_session_attribute(mock_session, flags);
        CHECK_TRUE((fv & flags) == flags);
        mock_session->clear_session_flags(flags);
        fv = appid_api.get_appid_session_attribute(mock_session, flags);
        CHECK_TRUE((fv & flags) == 0)
    }
}

TEST(appid_api, get_service_info)
{
    char* serviceVendor;
    char* serviceVersion;
    AppIdServiceSubtype* serviceSubtype;

    appid_api.get_service_info(nullptr, &serviceVendor, &serviceVersion, &serviceSubtype);
    CHECK_TRUE(!serviceVendor);
    CHECK_TRUE(!serviceVersion);
    CHECK_TRUE(!serviceSubtype);
    appid_api.get_service_info(mock_session, &serviceVendor, &serviceVersion, &serviceSubtype);
    STRCMP_EQUAL(serviceVendor, APPID_UT_SERVICE_VENDOR);
    STRCMP_EQUAL(serviceVersion, APPID_UT_SERVICE_VERSION);
    STRCMP_EQUAL(serviceSubtype->service, APPID_UT_SERVICE);
    STRCMP_EQUAL(serviceSubtype->vendor, APPID_UT_SERVICE_VENDOR);
    STRCMP_EQUAL(serviceSubtype->version, APPID_UT_SERVICE_VERSION);
}

TEST(appid_api, appid_dns_api)
{
    uint8_t query_len;

    char* val = appid_api.get_dns_query(nullptr, &query_len);
    CHECK_TRUE(!val);
    val = appid_api.get_dns_query(mock_session, &query_len);
    STRCMP_EQUAL(val, APPID_ID_UT_DNS_HOST);
    CHECK_TRUE(query_len == strlen(APPID_ID_UT_DNS_HOST));

    uint16_t qoff = appid_api.get_dns_query_offset(nullptr);
    CHECK_TRUE(qoff == 0);
    qoff = appid_api.get_dns_query_offset(mock_session);
    CHECK_TRUE(qoff == APPID_UT_DNS_HOST_OFFSET);

    uint16_t rt = appid_api.get_dns_record_type(nullptr);
    CHECK_TRUE(rt == 0);
    rt = appid_api.get_dns_record_type(mock_session);
    CHECK_TRUE(rt == APPID_UT_DNS_PATTERN_CNAME_REC);

    uint8_t rc = appid_api.get_dns_response_type(nullptr);
    CHECK_TRUE(rc == 0);
    rc = appid_api.get_dns_response_type(mock_session);
    CHECK_TRUE(rc == APPID_UT_DNS_NOERROR);

    uint32_t ttl = appid_api.get_dns_ttl(nullptr);
    CHECK_TRUE(ttl == 0);
    ttl = appid_api.get_dns_ttl(mock_session);
    CHECK_TRUE(ttl == APPID_UT_DNS_TTL);
}

TEST(appid_api, dhcp_fp_data)
{
    DHCPData* val = appid_api.get_dhcp_fp_data(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_dhcp_fp_data(mock_session);
    CHECK_TRUE(!val);
    val = new DHCPData;
    mock_session->add_flow_data(val, APPID_SESSION_DATA_DHCP_FP_DATA, nullptr);
    val = appid_api.get_dhcp_fp_data(mock_session);
    CHECK_TRUE(val);
    appid_api.free_dhcp_fp_data(mock_session, val);
    val = appid_api.get_dhcp_fp_data(mock_session);
    CHECK_TRUE(!val);
}

TEST(appid_api, dhcp_info)
{
    DHCPInfo* val = appid_api.get_dhcp_info(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_dhcp_info(mock_session);
    CHECK_TRUE(!val);
    val = new DHCPInfo;
    mock_session->add_flow_data(val, APPID_SESSION_DATA_DHCP_INFO, nullptr);
    val = appid_api.get_dhcp_info(mock_session);
    CHECK_TRUE(val);
    appid_api.free_dhcp_info(mock_session, val);
    val = appid_api.get_dhcp_info(mock_session);
    CHECK_TRUE(!val);
}

TEST(appid_api, smb_fp_data)
{
    FpSMBData* val = appid_api.get_smb_fp_data(nullptr);
    CHECK_TRUE(!val);
    val = appid_api.get_smb_fp_data(mock_session);
    CHECK_TRUE(!val);
    val = new FpSMBData;
    mock_session->add_flow_data(val, APPID_SESSION_DATA_SMB_DATA, nullptr);
    val = appid_api.get_smb_fp_data(mock_session);
    CHECK_TRUE(val);
    appid_api.free_smb_fp_data(mock_session, val);
    val = appid_api.get_smb_fp_data(mock_session);
    CHECK_TRUE(!val);
}

TEST(appid_api, is_http_inspection_done)
{
    bool val = appid_api.is_http_inspection_done(nullptr);
    CHECK_TRUE(val);
    val = appid_api.is_http_inspection_done(mock_session);
    CHECK_TRUE(val);
}

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

    delete mock_session;
    mock_session = nullptr;
    mock_flow_data= nullptr;
    SfIp ip;
    ip.pton(AF_INET, "192.168.1.222");
    val = appid_api.consume_ha_state(flow, (uint8_t*)&appHA, 0, IpProtocol::TCP, &ip, 1066);
    mock_session = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);
    CHECK_TRUE(mock_session);
    CHECK_TRUE(mock_session->tp_app_id == appHA.appId[0]);
    CHECK_TRUE(mock_session->service_app_id == appHA.appId[1]);
    CHECK_TRUE(mock_session->client_service_app_id == appHA.appId[2]);
    CHECK_TRUE(mock_session->port_service_id == appHA.appId[3]);
    CHECK_TRUE(mock_session->payload_app_id == appHA.appId[4]);
    CHECK_TRUE(mock_session->tp_payload_app_id == appHA.appId[5]);
    CHECK_TRUE(mock_session->client_app_id == appHA.appId[6]);
    CHECK_TRUE(mock_session->misc_app_id == appHA.appId[7]);
    CHECK_TRUE(mock_session->service_disco_state == APPID_DISCO_STATE_FINISHED);
    CHECK_TRUE(mock_session->client_disco_state == APPID_DISCO_STATE_FINISHED);

    // test logic when service app is ftp control
    appHA.appId[1] = APP_ID_FTP_CONTROL;
    delete mock_session;
    mock_session = nullptr;
    mock_flow_data= nullptr;
    val = appid_api.consume_ha_state(flow, (uint8_t*)&appHA, 0, IpProtocol::TCP, &ip, 1066);
    mock_session = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);
    CHECK_TRUE(mock_session);
    uint64_t flags = mock_session->get_session_flags(APPID_SESSION_CLIENT_DETECTED |
        APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
    CHECK_TRUE(flags == (APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_NOT_A_SERVICE
        | APPID_SESSION_SERVICE_DETECTED));
    CHECK_TRUE(mock_session->service_app_id == APP_ID_FTP_CONTROL);
    CHECK_TRUE(mock_session->service_disco_state == APPID_DISCO_STATE_STATEFUL);
    CHECK_TRUE(mock_session->client_disco_state == APPID_DISCO_STATE_FINISHED);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

