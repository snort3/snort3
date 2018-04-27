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

TEST(appid_api, get_service_app_id)
{
    AppId id = appid_api.get_service_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_port_service_app_id)
{
    AppId id = appid_api.get_port_service_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID + 3);
}

TEST(appid_api, get_only_service_app_id)
{
    AppId id = appid_api.get_only_service_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_misc_app_id)
{
    AppId id = appid_api.get_misc_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_client_app_id)
{
    AppId id = appid_api.get_client_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_payload_app_id)
{
    AppId id = appid_api.get_payload_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_referred_app_id)
{
    AppId id = appid_api.get_referred_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_service_app_id)
{
    AppId id = appid_api.get_fw_service_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_misc_app_id)
{
    AppId id = appid_api.get_fw_misc_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_client_app_id)
{
    AppId id = appid_api.get_fw_client_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_payload_app_id)
{
    AppId id = appid_api.get_fw_payload_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_fw_referred_app_id)
{
    AppId id = appid_api.get_fw_referred_app_id(*flow);
    CHECK_EQUAL(id, APPID_UT_ID);
}

TEST(appid_api, get_flow_type)
{
    APPID_FLOW_TYPE ft = appid_api.get_flow_type(*flow);
    CHECK_EQUAL(ft, APPID_FLOW_TYPE_NORMAL);
}

TEST(appid_api, get_service_port)
{
    short sp = appid_api.get_service_port(*flow);
    CHECK_EQUAL(sp, APPID_UT_SERVICE_PORT);
}


TEST(appid_api, get_http_search)
{
    SEARCH_SUPPORT_TYPE val = appid_api.get_http_search(*flow);
    CHECK_TRUE(val == NOT_A_SEARCH_ENGINE);
    mock_session->search_support_type = SUPPORTED_SEARCH_ENGINE;
    val = appid_api.get_http_search(*flow);
    CHECK_TRUE(val == SUPPORTED_SEARCH_ENGINE);
    mock_session->search_support_type = UNSUPPORTED_SEARCH_ENGINE;
    val = appid_api.get_http_search(*flow);
    CHECK_TRUE(val == UNSUPPORTED_SEARCH_ENGINE);
    mock_session->search_support_type = NOT_A_SEARCH_ENGINE;
    val = appid_api.get_http_search(*flow);
    CHECK_TRUE(val == NOT_A_SEARCH_ENGINE);
}

TEST(appid_api, get_tls_host)
{
    const char* val = appid_api.get_tls_host(*flow);
    STRCMP_EQUAL(val, APPID_UT_TLS_HOST);
}

TEST(appid_api, get_service_ip)
{
    SfIp expected_ip;

    expected_ip.pton(AF_INET, APPID_UT_SERVICE_IP_ADDR);

    SfIp* val = appid_api.get_service_ip(*flow);
    CHECK_TRUE(val->fast_eq4(expected_ip));
}

TEST(appid_api, get_initiator_ip)
{
    SfIp expected_ip;

    expected_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    SfIp* val = appid_api.get_initiator_ip(*flow);
    CHECK_TRUE(val->fast_eq4(expected_ip));
}

TEST(appid_api, get_netbios_name)
{
    const char* val;
    val = appid_api.get_netbios_name(*flow);
    STRCMP_EQUAL(val, APPID_UT_NETBIOS_NAME);
}

TEST(appid_api, is_ssl_session_decrypted)
{
    bool val = appid_api.is_ssl_session_decrypted(*flow);
    CHECK_TRUE(!val);
    is_session_decrypted = true;
    val = appid_api.is_ssl_session_decrypted(*flow);
    CHECK_TRUE(val);
}

TEST(appid_api, is_appid_inspecting_session)
{
    mock_session->service_disco_state = APPID_DISCO_STATE_STATEFUL;
    bool val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(val);
    mock_session->service_disco_state = APPID_DISCO_STATE_FINISHED;
    mock_session->set_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(val);
    mock_session->clear_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE);
    mock_session->set_session_flags(APPID_SESSION_ENCRYPTED);
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(val);
    mock_session->set_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->session_packet_count = SSL_WHITELIST_PKT_LIMIT;
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(val);

    // 2nd if in is_appid_inspecting_session
    mock_session->clear_session_flags(APPID_SESSION_DECRYPTED);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(!val);
    mock_session->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(val);
    mock_session->client_disco_state = APPID_DISCO_STATE_FINISHED;
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(!val);

    // 3rd if in is_appid_inspecting_session
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT;
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(!val);
    mock_session->payload.set_id(APP_ID_SFTP);
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(!val);
    mock_session->session_packet_count = MAX_SFTP_PACKET_COUNT - 1;
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(!val);
    mock_session->payload.set_id(APP_ID_NONE);
    mock_session->tp_app_id = APP_ID_SSH;
    val = appid_api.is_appid_inspecting_session(*flow);
    CHECK_TRUE(val);
}

TEST(appid_api, get_user_name)
{
    AppId service;
    bool isLoginSuccessful;

    const char* val;
    val = appid_api.get_user_name(*flow, &service, &isLoginSuccessful);
    STRCMP_EQUAL(val, APPID_UT_USERNAME);
    CHECK_TRUE(service == APPID_UT_ID);
    CHECK_TRUE(!isLoginSuccessful);
    mock_session->set_session_flags(APPID_SESSION_LOGIN_SUCCEEDED);
    val = appid_api.get_user_name(*flow, &service, &isLoginSuccessful);
    CHECK_TRUE(service == APPID_UT_ID);
    CHECK_TRUE(isLoginSuccessful);
}

TEST(appid_api, is_appid_available)
{
    bool val;
    val = appid_api.is_appid_available(*flow);
    CHECK_FALSE(val);
    mock_session->set_session_flags(APPID_SESSION_NO_TPI);
    val = appid_api.is_appid_available(*flow);
    CHECK_TRUE(val);
}

TEST(appid_api, get_client_version)
{
    const char* val;
    val = appid_api.get_client_version(*flow);
    STRCMP_EQUAL(val, APPID_UT_CLIENT_VERSION);
}

TEST(appid_api, get_appid_session_attribute)
{
    uint64_t flags = 0x0000000000000001;

    for ( unsigned i = 0; i < 64; i++ )
    {
        flags <<= i;
        mock_session->set_session_flags(flags);
        uint64_t fv = appid_api.get_appid_session_attribute(*flow, flags);
        CHECK_TRUE((fv & flags) == flags);
        mock_session->clear_session_flags(flags);
        fv = appid_api.get_appid_session_attribute(*flow, flags);
        CHECK_TRUE((fv & flags) == 0)
    }
}

TEST(appid_api, get_service_info)
{
    const char* serviceVendor;
    const char* serviceVersion;
    AppIdServiceSubtype* serviceSubtype;

    appid_api.get_service_info(*flow, &serviceVendor, &serviceVersion, &serviceSubtype);
    STRCMP_EQUAL(serviceVendor, APPID_UT_SERVICE_VENDOR);
    STRCMP_EQUAL(serviceVersion, APPID_UT_SERVICE_VERSION);
    STRCMP_EQUAL(serviceSubtype->service, APPID_UT_SERVICE);
    STRCMP_EQUAL(serviceSubtype->vendor, APPID_UT_SERVICE_VENDOR);
    STRCMP_EQUAL(serviceSubtype->version, APPID_UT_SERVICE_VERSION);
}

TEST(appid_api, appid_dns_api)
{
    AppIdDnsSession* dsession = appid_api.get_dns_session(*flow);

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

TEST(appid_api, dhcp_fp_data)
{
    DHCPData* val;
    val = appid_api.get_dhcp_fp_data(*flow);
    CHECK_TRUE(!val);
    val = new DHCPData;
    mock_session->add_flow_data(val, APPID_SESSION_DATA_DHCP_FP_DATA, nullptr);
    val = appid_api.get_dhcp_fp_data(*flow);
    CHECK_TRUE(val);
    appid_api.free_dhcp_fp_data(*flow, val);
    val = appid_api.get_dhcp_fp_data(*flow);
    CHECK_TRUE(!val);
}

TEST(appid_api, dhcp_info)
{
    DHCPInfo* val;
    val = appid_api.get_dhcp_info(*flow);
    CHECK_TRUE(!val);
    val = new DHCPInfo;
    mock_session->add_flow_data(val, APPID_SESSION_DATA_DHCP_INFO, nullptr);
    val = appid_api.get_dhcp_info(*flow);
    CHECK_TRUE(val);
    appid_api.free_dhcp_info(*flow, val);
    val = appid_api.get_dhcp_info(*flow);
    CHECK_TRUE(!val);
}

TEST(appid_api, smb_fp_data)
{
    FpSMBData* val;
    val = appid_api.get_smb_fp_data(*flow);
    CHECK_TRUE(!val);
    val = new FpSMBData;
    mock_session->add_flow_data(val, APPID_SESSION_DATA_SMB_DATA, nullptr);
    val = appid_api.get_smb_fp_data(*flow);
    CHECK_TRUE(val);
    appid_api.free_smb_fp_data(*flow, val);
    val = appid_api.get_smb_fp_data(*flow);
    CHECK_TRUE(!val);
}

TEST(appid_api, is_http_inspection_done)
{
    bool val;
    val = appid_api.is_http_inspection_done(*flow);
    CHECK_TRUE(val);
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
    CHECK_TRUE(session->tp_app_id == appHA.appId[0]);
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

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    mock_session = new AppIdSession(IpProtocol::TCP, nullptr, 1492, appid_inspector);
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

