//--------------------------------------------------------------------------
// Copyright (C) 2016-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/ha.h"

#include "appid_dns_session.h"
#include "appid_mock_flow.h"
#include "appid_mock_http_session.h"
#include "appid_mock_inspector.h"

bool is_session_decrypted = false;

char const* APPID_UT_TLS_HOST = "vpn.topsecret.com";
char const* APPID_UT_SERVICE_IP_ADDR = "192.168.0.2";
char const* APPID_UT_INITIATOR_IP_ADDR = "192.168.0.3";

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
uint32_t OdpContext::next_version = 0;

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

AppIdConfig::~AppIdConfig() = default;
OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*) { }

void FlowHAState::add(uint8_t) { }

static AppIdConfig stub_config;
static AppIdContext stub_ctxt(stub_config);
static OdpContext stub_odp_ctxt(stub_config, nullptr);
OdpContext* AppIdContext::odp_ctxt = &stub_odp_ctxt;
AppIdSession::AppIdSession(IpProtocol proto, const SfIp* ip, uint16_t, AppIdInspector& inspector,
    OdpContext&, uint16_t) : FlowData(inspector_id, &inspector), config(stub_config),
    protocol(proto), api(*(new AppIdSessionApi(this, *ip))), odp_ctxt(stub_odp_ctxt)
{
    this->set_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED);
    odp_ctxt_version = odp_ctxt.get_version();
    set_service_port(APPID_UT_SERVICE_PORT);
    AppidChangeBits change_bits;

    set_client_user(APPID_UT_ID, APPID_UT_USERNAME, change_bits);
    set_client_version(APPID_UT_CLIENT_VERSION, change_bits);

    set_service_vendor(APPID_UT_SERVICE_VENDOR, change_bits);
    set_service_version(APPID_UT_SERVICE_VERSION, change_bits);
    add_service_subtype(*(new AppIdServiceSubtype(APPID_UT_SERVICE_SUBTYPE)), change_bits);

    tsession = new TlsSession;

    SfIp svc_ip;
    svc_ip.pton(AF_INET, APPID_UT_SERVICE_IP_ADDR);
    set_service_ip(svc_ip);
    api.initiator_ip.pton(AF_INET, APPID_UT_INITIATOR_IP_ADDR);

    api.dsession = new MockAppIdDnsSession;
    tp_app_id = APPID_UT_ID;
    set_service_id(APPID_UT_ID + 1, odp_ctxt);
    client_inferred_service_id = APPID_UT_ID + 2;
    set_port_service_id(APPID_UT_ID + 3);
    set_payload_id(APPID_UT_ID + 4);
    tp_payload_app_id = APPID_UT_ID + 5;
    set_client_id(APPID_UT_ID + 6);
    misc_app_id = APPID_UT_ID + 7;
}

AppIdSession::~AppIdSession()
{
    delete tsession;
}

void* AppIdSession::get_flow_data(unsigned) const
{
    return nullptr;
}

int AppIdSession::add_flow_data(void*, unsigned, AppIdFreeFCN)
{
    return 0;
}

AppId AppIdSession::pick_service_app_id() const
{
    return get_service_id();
}

AppId AppIdSession::pick_ss_misc_app_id() const
{
    return misc_app_id;
}

AppId AppIdSession::pick_ss_client_app_id() const
{
    return get_client_id();
}

AppId AppIdSession::pick_ss_payload_app_id() const
{
    return get_payload_id();
}

AppId AppIdSession::pick_ss_referred_payload_app_id() const
{
    return APPID_UT_ID;
}

AppIdHttpSession* AppIdSession::create_http_session(uint32_t)
{
    AppIdHttpSession* hsession = new MockAppIdHttpSession(*this);
    AppidChangeBits change_bits;

    hsession->client.set_id(APPID_UT_ID);
    hsession->client.set_version(APPID_UT_CLIENT_VERSION);
    change_bits.set(APPID_CLIENT_INFO_BIT);
    hsession->payload.set_id(APPID_UT_ID);
    hsession->misc_app_id = APPID_UT_ID;
    hsession->referred_payload_app_id = APPID_UT_ID;
    api.hsessions.push_back(hsession);
    return hsession;
}

AppIdHttpSession* AppIdSession::get_matching_http_session(uint32_t stream_id) const
{
    for (uint32_t stream_index=0; stream_index < api.hsessions.size(); stream_index++)
    {
        if (stream_id == api.hsessions[stream_index]->get_http2_stream_id())
            return api.hsessions[stream_index];
    }
    return nullptr;
}

AppIdDnsSession* AppIdSession::create_dns_session()
{
    if ( !api.dsession )
        api.dsession = new MockAppIdDnsSession();
    return api.dsession;
}

AppIdDnsSession* AppIdSession::get_dns_session() const
{
    return api.dsession;
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

