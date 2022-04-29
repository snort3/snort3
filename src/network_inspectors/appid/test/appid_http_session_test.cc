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

// appid_api_test.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_http_session.cc"

#include <string>

#include "framework/data_bus.h"
#include "memory/memory_cap.h"
#include "protocols/protocol_ids.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"
#include "appid_config.h"
#include "appid_http_session.h"
#include "appid_module.h"

#include "appid_mock_definitions.h"
#include "appid_mock_inspector.h"
#include "appid_mock_flow.h"
#include "appid_peg_counts.h"

#include "detector_plugins/http_url_patterns.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
}

void FlowHAState::add(uint8_t) { }
void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
const char* AppInfoManager::get_app_name(AppId)
{
    return "";
}

// HttpPatternMatchers mock functions
void HttpPatternMatchers::scan_key_chp(ChpMatchDescriptor&)
{
}

AppId HttpPatternMatchers::scan_header_x_working_with(const char*, uint32_t, char**)
{
    return 0;
}

AppId HttpPatternMatchers::scan_chp(ChpMatchDescriptor&, char**, char**,
    int*, AppIdHttpSession*, const OdpContext&)
{
    return 0;
}

void HttpPatternMatchers::get_server_vendor_version(const char*, int, char**,
    char**, AppIdServiceSubtype**)
{
}

void HttpPatternMatchers::identify_user_agent(const char*, int, AppId&, AppId&, char**)
{
}

int HttpPatternMatchers::get_appid_by_pattern(const char*, unsigned, char**)
{
    return 0;
}

AppId HttpPatternMatchers::get_appid_by_content_type(const char*, int)
{
    return 0;
}

bool HttpPatternMatchers::get_appid_from_url(const char*, const char*, char**,
    const char*, AppId*, AppId*, AppId*, AppId* referredPayloadAppId, bool, OdpContext&)
{
    *referredPayloadAppId = APP_ID_FACEBOOK;
    return true;
}

static AppIdConfig stub_config;
static AppIdContext stub_ctxt(stub_config);
static OdpContext stub_odp_ctxt(stub_config, nullptr);
OdpContext* AppIdContext::odp_ctxt = &stub_odp_ctxt;
static Flow flow;

// AppIdSession mock functions
AppIdSession::AppIdSession(IpProtocol, const SfIp* ip, uint16_t, AppIdInspector& inspector,
    OdpContext&, uint32_t) : FlowData(inspector_id, &inspector), config(stub_config),
        api(*(new AppIdSessionApi(this, *ip))), odp_ctxt(stub_odp_ctxt)
{}

AppIdSession::~AppIdSession()
{
    delete &api;
}

void AppIdSession::set_client_appid_data(AppId, AppidChangeBits&, char*)
{
}

void AppIdSession::set_service_appid_data(AppId, AppidChangeBits&, char*)
{
}

void AppIdSession::set_payload_appid_data(AppId, char*)
{
}

void AppIdSession::clear_http_flags()
{
}

void AppIdSession::reset_session_data(AppidChangeBits&)
{
}

bool AppIdSession::is_tp_appid_available() const
{
    return true;
}

void AppIdModule::reset_stats() {}

// AppIdDebug mock functions
void AppIdDebug::activate(const uint32_t*, const uint32_t*, uint16_t,
    uint16_t, IpProtocol, const int, uint32_t, const AppIdSession*, bool,
    int16_t, int16_t, bool)
{
}

void AppIdDebug::set_constraints(const char*, const AppIdDebugSessionConstraints*)
{
}

// Profiler mock functions
void Profiler::register_module(Module*) { }
void Profiler::register_module(const char*, const char*, Module*) { }
void Profiler::consolidate_stats() { }
void Profiler::reset_stats() { }
void Profiler::show_stats() { }

OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*) { }

AppIdConfig::~AppIdConfig() = default;

unsigned AppIdSession::inspector_id = 0;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;

TEST_GROUP(appid_http_session)
{
    AppIdHttpSession* mock_hsession;
    AppIdSession* session;

    void setup() override
    {
        SfIp sfip;
        session = new AppIdSession(IpProtocol::IP, &sfip, 0, dummy_appid_inspector, stub_odp_ctxt);
        session->flow = &flow;
        mock_hsession = new AppIdHttpSession(*session, 0);
        appidDebug = new AppIdDebug();
        AppIdPegCounts::init_pegs();
    }

    void teardown() override
    {
        delete appidDebug;
        delete mock_hsession;
        delete session;
        AppIdPegCounts::cleanup_pegs();
    }
};

TEST(appid_http_session, http_field_ids_enum_order)
{
    // Set the fields using integers, then get them by HttpFieldIds,
    // to make sure the order of the HttpFieldIds has not changed
    // in appid_http_session.h.
    AppidChangeBits change_bits;

    mock_hsession->set_field( (HttpFieldIds)0, new std::string("agent"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)1, new std::string("host"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)2, new std::string("referer"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)3, new std::string("uri"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)4, new std::string("cookie"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)5, new std::string("req_body"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)6, new std::string("content_type"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)7, new std::string("location"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)8, new std::string("rsp_body"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)9, new std::string("via"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)10, new std::string("response_code"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)11, new std::string("server"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)12, new std::string("xww"), change_bits);
    mock_hsession->set_field( (HttpFieldIds)13, new std::string("url"), change_bits);

    const std::string* field;
    field = mock_hsession->get_field(REQ_AGENT_FID);
    STRCMP_EQUAL(field->c_str(), "agent");
    field = mock_hsession->get_field(REQ_HOST_FID);
    STRCMP_EQUAL(field->c_str(), "host");
    field = mock_hsession->get_field(REQ_REFERER_FID);
    STRCMP_EQUAL(field->c_str(), "referer");
    field = mock_hsession->get_field(REQ_URI_FID);
    STRCMP_EQUAL(field->c_str(), "uri");
    field = mock_hsession->get_field(REQ_COOKIE_FID);
    STRCMP_EQUAL(field->c_str(), "cookie");
    field = mock_hsession->get_field(REQ_BODY_FID);
    STRCMP_EQUAL(field->c_str(), "req_body");
    field = mock_hsession->get_field(RSP_CONTENT_TYPE_FID);
    STRCMP_EQUAL(field->c_str(), "content_type");
    field = mock_hsession->get_field(RSP_LOCATION_FID);
    STRCMP_EQUAL(field->c_str(), "location");
    field = mock_hsession->get_field(RSP_BODY_FID);
    STRCMP_EQUAL(field->c_str(), "rsp_body");
    field = mock_hsession->get_field(MISC_VIA_FID);
    STRCMP_EQUAL(field->c_str(), "via");
    field = mock_hsession->get_field(MISC_RESP_CODE_FID);
    STRCMP_EQUAL(field->c_str(), "response_code");
    field = mock_hsession->get_field(MISC_SERVER_FID);
    STRCMP_EQUAL(field->c_str(), "server");
    field = mock_hsession->get_field(MISC_XWW_FID);
    STRCMP_EQUAL(field->c_str(), "xww");
    field = mock_hsession->get_field(MISC_URL_FID);
    STRCMP_EQUAL(field->c_str(), "url");

    // Detect changes in host, url, user agent, response, and referer fields
    // that generate appid event consumed by subscribers
    CHECK_EQUAL(change_bits.test(APPID_HOST_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_URL_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_USERAGENT_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_RESPONSE_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_REFERER_BIT), true);

    // verify empty fields do not override existing fields
    mock_hsession->set_field(REQ_AGENT_FID, nullptr, change_bits);
    field = mock_hsession->get_field(REQ_AGENT_FID);
    STRCMP_EQUAL(field->c_str(), "agent");
    mock_hsession->set_field(REQ_AGENT_FID, new std::string(""), change_bits);
    field = mock_hsession->get_field(REQ_AGENT_FID);
    STRCMP_EQUAL(field->c_str(), "agent");
    mock_hsession->set_field(REQ_AGENT_FID, nullptr, 0, change_bits);
    field = mock_hsession->get_field(REQ_AGENT_FID);
    STRCMP_EQUAL(field->c_str(), "agent");
    mock_hsession->set_field(REQ_AGENT_FID, (const uint8_t*)"", 0, change_bits);
    field = mock_hsession->get_field(REQ_AGENT_FID);
    STRCMP_EQUAL(field->c_str(), "agent");
}

TEST(appid_http_session, set_tun_dest)
{
    const TunnelDest* tun_dest  = nullptr;
    SfIp ipv6;
    ipv6.set("2001:db8:85a3::8a2e:370:7334");
    AppidChangeBits change_bits;
    mock_hsession->set_field(REQ_URI_FID, new std::string("[2001:db8:85a3::8a2e:370:7334]:51413"), change_bits);
    mock_hsession->set_tun_dest();
    tun_dest = mock_hsession->get_tun_dest();
    CHECK(tun_dest != nullptr);
    CHECK_EQUAL(tun_dest->port, 51413);
    CHECK_EQUAL((ipv6 == tun_dest->ip), true);
}

TEST(appid_http_session, set_tun_dest_bad_uri)
{
    const TunnelDest* tun_dest  = nullptr;
    AppidChangeBits change_bits;
    mock_hsession->set_field(REQ_URI_FID, new std::string("[2001:db8:85a3::8a2e:370:1234]:51413"), change_bits);
    mock_hsession->set_tun_dest();
    tun_dest = mock_hsession->get_tun_dest();
    CHECK(tun_dest != nullptr);

    // Testing with bad URL
    mock_hsession->free_tun_dest();
    mock_hsession->set_field(REQ_URI_FID, new std::string("[2001:db8:85a3::8a2e:370:1235]"), change_bits);
    mock_hsession->set_tun_dest();
    tun_dest = mock_hsession->get_tun_dest();
    CHECK(tun_dest == nullptr);
}

TEST(appid_http_session, change_bits_for_referred_appid)
{
    // Testing set_referred_payload_app_id_data
    AppidChangeBits change_bits;
    AppIdConfig config;
    OdpContext odp_ctxt(config, nullptr);
    session->set_service_id(APP_ID_HTTP, odp_ctxt);
    session->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
    mock_hsession->set_skip_simple_detect(false);
    mock_hsession->set_field( (HttpFieldIds)2, new std::string("referer"), change_bits);
    mock_hsession->process_http_packet(APP_ID_FROM_INITIATOR, change_bits, odp_ctxt.get_http_matchers());

    // Detect changes in referred appid
    CHECK_EQUAL(change_bits.test(APPID_REFERRED_BIT), true);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}

