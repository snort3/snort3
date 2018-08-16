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

// appid_mock_session.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_MOCK_SESSION_H
#define APPID_MOCK_SESSION_H

#include "appid_dns_session.h"
#include "appid_mock_flow.h"
#include "appid_mock_http_session.h"
#include "appid_mock_inspector.h"

bool is_session_decrypted = false;

char const* APPID_UT_TLS_HOST = "vpn.topsecret.com";
char const* APPID_UT_SERVICE_IP_ADDR = "192.168.0.2";
char const* APPID_UT_INITIATOR_IP_ADDR = "192.168.0.3";

char const* APPID_UT_NETBIOS_NAME = "I AM NETBIOS!";

char const* APPID_ID_UT_DNS_HOST = "delphi.opendns.com";
#define APPID_UT_DNS_HOST_OFFSET 22
#define APPID_UT_DNS_PATTERN_CNAME_REC  5
#define APPID_UT_DNS_NOERROR 0
#define APPID_UT_DNS_TTL 5

const char* test_app_name = "testapp_1492";
const AppId APPID_UT_ID = 1492;
const short APPID_UT_SERVICE_PORT = 1066;
const char* APPID_UT_USERNAME = "pigpen";
const char* APPID_UT_CLIENT_VERSION = "a snorting client";
const char* APPID_UT_SERVICE = "at your service";
const char* APPID_UT_SERVICE_VENDOR = "cisco snorty";
const char* APPID_UT_SERVICE_VERSION = "Version City";

AppIdServiceSubtype APPID_UT_SERVICE_SUBTYPE = { nullptr, APPID_UT_SERVICE,
                                                 APPID_UT_SERVICE_VENDOR,
                                                 APPID_UT_SERVICE_VERSION };

unsigned AppIdSession::inspector_id = 0;

class MockAppIdDnsSession : public AppIdDnsSession
{
public:
    MockAppIdDnsSession()
    {
        host = (char*)APPID_ID_UT_DNS_HOST;
        host_offset = APPID_UT_DNS_HOST_OFFSET;
        record_type = APPID_UT_DNS_PATTERN_CNAME_REC;
        response_type = APPID_UT_DNS_NOERROR;
        ttl = APPID_UT_DNS_TTL;
    }
};

AppIdSession::AppIdSession(IpProtocol, const SfIp*, uint16_t, AppIdInspector& inspector)
    : FlowData(inspector_id, &inspector), inspector(inspector)
{
    common.flow_type = APPID_FLOW_TYPE_NORMAL;
    service_port = APPID_UT_SERVICE_PORT;

    client.update_user(APPID_UT_ID, APPID_UT_USERNAME);
    client.set_version(APPID_UT_CLIENT_VERSION);

    service.set_vendor(APPID_UT_SERVICE_VENDOR);
    service.set_version(APPID_UT_SERVICE_VERSION);
    subtype = &APPID_UT_SERVICE_SUBTYPE;

    search_support_type = UNKNOWN_SEARCH_ENGINE;

    tsession = new TlsSession;
    tsession->tls_host = (char*)APPID_UT_TLS_HOST;

    service_ip.pton(AF_INET, APPID_UT_SERVICE_IP_ADDR);
    common.initiator_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    netbios_name = snort_strdup(APPID_UT_NETBIOS_NAME);

    dsession = new MockAppIdDnsSession;
    tp_app_id = APPID_UT_ID;
    service.set_id(APPID_UT_ID + 1);
    client_inferred_service_id = APPID_UT_ID + 2;
    service.set_port_service_id(APPID_UT_ID + 3);
    payload.set_id(APPID_UT_ID + 4);
    tp_payload_app_id = APPID_UT_ID + 5;
    client.set_id(APPID_UT_ID + 6);
    misc_app_id = APPID_UT_ID + 7;
}

AppIdSession::~AppIdSession()
{
    delete hsession;
    delete tsession;
    delete dsession;
    if (netbios_name)
        snort_free(netbios_name);
}

DHCPInfo* dhcp_info = nullptr;
DHCPData* dhcp_data = nullptr;
FpSMBData* smb_data = nullptr;

void* AppIdSession::get_flow_data(unsigned)
{
    return nullptr;
}

int AppIdSession::add_flow_data(void* data, unsigned type, AppIdFreeFCN)
{
    if ( type == APPID_SESSION_DATA_DHCP_FP_DATA )
    {
        dhcp_data = (DHCPData*)data;
        set_session_flags(APPID_SESSION_HAS_DHCP_FP);
    }
    else if (  type == APPID_SESSION_DATA_DHCP_INFO )
    {
        dhcp_info = (DHCPInfo*)data;
        set_session_flags(APPID_SESSION_HAS_DHCP_INFO);
    }
    else if ( type == APPID_SESSION_DATA_SMB_DATA )
    {
        smb_data = (FpSMBData*)data;
        set_session_flags(APPID_SESSION_HAS_SMB_INFO);
    }
    return 0;
}

void* AppIdSession::remove_flow_data(unsigned type)
{
    void* data = nullptr;

    if ( type == APPID_SESSION_DATA_DHCP_FP_DATA )
    {
        data = dhcp_data;
        dhcp_data = nullptr;
        clear_session_flags(APPID_SESSION_HAS_DHCP_FP);
    }
    else if (  type == APPID_SESSION_DATA_DHCP_INFO )
    {
        data = dhcp_info;
        dhcp_info = nullptr;
        clear_session_flags(APPID_SESSION_HAS_DHCP_INFO);
    }
    else if ( type == APPID_SESSION_DATA_SMB_DATA )
    {
        data = smb_data;
        smb_data = nullptr;
        clear_session_flags(APPID_SESSION_HAS_SMB_INFO);
    }

    return data;
}

void AppIdSession::set_application_ids(AppId, AppId, AppId, AppId) { }

AppId AppIdSession::pick_service_app_id()
{
    return APPID_UT_ID;
}

AppId AppIdSession::pick_misc_app_id()
{
    return APPID_UT_ID;
}

AppId AppIdSession::pick_client_app_id()
{
    return APPID_UT_ID;
}

AppId AppIdSession::pick_payload_app_id()
{
    return APPID_UT_ID;
}

AppId AppIdSession::pick_referred_payload_app_id()
{
    return APPID_UT_ID;
}

void AppIdSession::get_application_ids(AppId&, AppId&, AppId&, AppId&) { }

void AppIdSession::get_application_ids(AppId&, AppId&, AppId&) { }

AppId AppIdSession::get_application_ids_service() { return APPID_UT_ID; }

AppId AppIdSession::get_application_ids_client() { return APPID_UT_ID; }

AppId AppIdSession::get_application_ids_payload() { return APPID_UT_ID; }

AppId AppIdSession::get_application_ids_misc() { return APPID_UT_ID; }

AppId AppIdSession::pick_only_service_app_id()
{
    return APPID_UT_ID;
}

bool AppIdSession::is_ssl_session_decrypted()
{
    return is_session_decrypted;
}

AppIdHttpSession* AppIdSession::get_http_session()
{
    if ( !hsession )
        hsession = new MockAppIdHttpSession(*this);
    return hsession;
}

AppIdDnsSession* AppIdSession::get_dns_session()
{
    if ( !dsession )
        dsession = new MockAppIdDnsSession();
    return dsession;
}

bool AppIdSession::is_tp_appid_done() const
{
    return true;
}

bool AppIdSession::is_tp_appid_available() const
{
    return true;
}

#endif

