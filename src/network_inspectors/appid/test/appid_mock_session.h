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
std::mutex AppIdSession::inferred_svcs_lock;
uint16_t AppIdSession::inferred_svcs_ver = 0;

class MockAppIdDnsSession : public AppIdDnsSession
{
public:
    MockAppIdDnsSession()
    {
        host = (const char*) APPID_ID_UT_DNS_HOST;
        host_offset = APPID_UT_DNS_HOST_OFFSET;
        record_type = APPID_UT_DNS_PATTERN_CNAME_REC;
        response_type = APPID_UT_DNS_NOERROR;
        ttl = APPID_UT_DNS_TTL;
    }
};

AppIdConfig::~AppIdConfig() { }
OdpContext::OdpContext(AppIdConfig&, snort::SnortConfig*) { }

static AppIdConfig stub_config;
static AppIdContext stub_ctxt(stub_config);
static OdpContext stub_odp_ctxt(stub_config, nullptr);
OdpContext* AppIdContext::odp_ctxt = &stub_odp_ctxt;
AppIdSession::AppIdSession(IpProtocol proto, const SfIp*, uint16_t, AppIdInspector& inspector)
    : FlowData(inspector_id, &inspector), ctxt(stub_ctxt), protocol(proto)
{
    service_port = APPID_UT_SERVICE_PORT;
    AppidChangeBits change_bits;

    memset(application_ids, 0, sizeof(application_ids));
    client.update_user(APPID_UT_ID, APPID_UT_USERNAME);
    client.set_version(APPID_UT_CLIENT_VERSION, change_bits);

    service.set_vendor(APPID_UT_SERVICE_VENDOR);
    service.set_version(APPID_UT_SERVICE_VERSION, change_bits);
    subtype = &APPID_UT_SERVICE_SUBTYPE;

    tsession = new TlsSession;

    service_ip.pton(AF_INET, APPID_UT_SERVICE_IP_ADDR);
    common.initiator_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    netbios_name = snort_strdup(APPID_UT_NETBIOS_NAME);

    dsession = new MockAppIdDnsSession;
    tp_app_id = APPID_UT_ID;
    service.set_id(APPID_UT_ID + 1, ctxt.get_odp_ctxt());
    client_inferred_service_id = APPID_UT_ID + 2;
    service.set_port_service_id(APPID_UT_ID + 3);
    payload.set_id(APPID_UT_ID + 4);
    tp_payload_app_id = APPID_UT_ID + 5;
    client.set_id(APPID_UT_ID + 6);
    misc_app_id = APPID_UT_ID + 7;
}

AppIdSession::~AppIdSession()
{
    for (auto* hsession: hsessions)
        delete hsession;
    delete tsession;
    delete dsession;
    if (netbios_name)
        snort_free(netbios_name);
}

void* AppIdSession::get_flow_data(unsigned)
{
    return nullptr;
}

int AppIdSession::add_flow_data(void*, unsigned, AppIdFreeFCN)
{
    return 0;
}

void AppIdSession::set_ss_application_ids(AppId service_id, AppId client_id,
    AppId payload_id, AppId misc_id, AppidChangeBits& change_bits)
{
    if (application_ids[APP_PROTOID_SERVICE] != service_id)
    {
        application_ids[APP_PROTOID_SERVICE] = service_id;
        change_bits.set(APPID_SERVICE_BIT);
    }
    if (application_ids[APP_PROTOID_CLIENT] != client_id)
    {
        application_ids[APP_PROTOID_CLIENT] = client_id;
        change_bits.set(APPID_CLIENT_BIT);
    }
    if (application_ids[APP_PROTOID_PAYLOAD] != payload_id)
    {
        application_ids[APP_PROTOID_PAYLOAD] = payload_id;
        change_bits.set(APPID_PAYLOAD_BIT);
    }
    if (application_ids[APP_PROTOID_MISC] != misc_id)
    {
        application_ids[APP_PROTOID_MISC] = misc_id;
        change_bits.set(APPID_MISC_BIT);
    }
}

AppId AppIdSession::pick_service_app_id()
{
    return service.get_id();
}

AppId AppIdSession::pick_ss_misc_app_id()
{
    return misc_app_id;
}

AppId AppIdSession::pick_ss_client_app_id()
{
    return client.get_id();
}

AppId AppIdSession::pick_ss_payload_app_id()
{
    return payload.get_id();
}

AppId AppIdSession::pick_ss_referred_payload_app_id()
{
    return APPID_UT_ID;
}

void AppIdSession::get_first_stream_app_ids(AppId&, AppId&, AppId&, AppId&) { }

void AppIdSession::get_first_stream_app_ids(AppId&, AppId&, AppId&) { }

AppId AppIdSession::get_application_ids_service() { return APPID_UT_ID; }

AppId AppIdSession::get_application_ids_client(uint32_t stream_index)
{
    if (stream_index < hsessions.size() or stream_index == 0)
      return APPID_UT_ID;

    return APP_ID_NONE;      
}

AppId AppIdSession::get_application_ids_payload(uint32_t stream_index)
{
    if (stream_index < hsessions.size() or stream_index == 0)
      return APPID_UT_ID;

    return APP_ID_NONE;      
}

AppId AppIdSession::get_application_ids_misc(uint32_t stream_index)
{
    if (stream_index < hsessions.size() or stream_index == 0)
      return APPID_UT_ID;

    return APP_ID_NONE;      
}

bool AppIdSession::is_ssl_session_decrypted()
{
    return is_session_decrypted;
}

AppIdHttpSession* AppIdSession::create_http_session(uint32_t)
{
    AppIdHttpSession* hsession = new MockAppIdHttpSession(*this);
    AppidChangeBits change_bits;

    hsession->client.set_id(APPID_UT_ID);
    hsession->client.set_version(APPID_UT_CLIENT_VERSION, change_bits);
    hsession->payload.set_id(APPID_UT_ID);
    hsession->misc_app_id = APPID_UT_ID;
    hsession->referred_payload_app_id = APPID_UT_ID;
    hsessions.push_back(hsession);
    return hsession;
}

AppIdHttpSession* AppIdSession::get_http_session(uint32_t stream_index)
{
    if (stream_index < hsessions.size())
    {
        return hsessions[stream_index];
    }
    return nullptr;
}

AppIdHttpSession* AppIdSession::get_matching_http_session(uint32_t stream_id)
{
    for (uint32_t stream_index=0; stream_index < hsessions.size(); stream_index++)
    {
        if(stream_id == hsessions[stream_index]->get_http2_stream_id())
            return hsessions[stream_index];
    }
    return nullptr;
}

AppIdDnsSession* AppIdSession::create_dns_session()
{
    if ( !dsession )
        dsession = new MockAppIdDnsSession();
    return dsession;
}

AppIdDnsSession* AppIdSession::get_dns_session()
{
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

void AppIdSession::set_application_ids_service(int, AppidChangeBits&) { }

#endif

