//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "protocols/protocol_ids.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"
#include "appid_http_session.h"
#include "appid_module.h"

#include "appid_mock_definitions.h"
#include "appid_mock_inspector.h"
#include "appid_mock_flow.h"

#include "detector_plugins/http_url_patterns.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
using namespace snort;

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
const char* AppInfoManager::get_app_name(AppId)
{
    return "";
}

// HttpPatternMatchers mock functions
HttpPatternMatchers* HttpPatternMatchers::get_instance()
{
    return nullptr;
}

void HttpPatternMatchers::scan_key_chp(ChpMatchDescriptor&)
{
}

AppId HttpPatternMatchers::scan_header_x_working_with(const char*, uint32_t, char**)
{
    return 0;
}

AppId HttpPatternMatchers::scan_chp(ChpMatchDescriptor&, char**, char**,
    int*, AppIdHttpSession*, const AppIdModuleConfig*)
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

bool HttpPatternMatchers::get_appid_from_url(char*, const char*, char**,
    const char*, AppId*, AppId*, AppId*, AppId* referredPayloadAppId, bool)
{
    *referredPayloadAppId = APP_ID_FACEBOOK;
    return true;
}

// AppIdSession mock functions
AppIdSession::AppIdSession(IpProtocol, const SfIp*, uint16_t, AppIdInspector& inspector)
    : FlowData(inspector_id, &inspector)
{
}

AppIdSession::~AppIdSession()
{
}

void AppIdSession::set_client_appid_data(AppId, AppidChangeBits&, char*)
{
}

void AppIdSession::set_service_appid_data(AppId, AppidChangeBits&, char*)
{
}

void AppIdSession::set_payload_appid_data(AppId, AppidChangeBits&, char*)
{
}

void AppIdSession::clear_http_flags()
{
}

void AppIdSession::reset_session_data()
{
}

bool AppIdSession::is_payload_appid_set()
{
    return true;
}

void AppIdSession::set_referred_payload_app_id_data(AppId id, AppidChangeBits& change_bits)
{
    if (id <= APP_ID_NONE)
        return;

    if (referred_payload_app_id != id)
    {
        referred_payload_app_id = id;
        change_bits.set(APPID_REFERRED_BIT);
    }
}

// AppIdDebug mock functions
void AppIdDebug::activate(const uint32_t*, const uint32_t*, uint16_t,
    uint16_t, IpProtocol, const int, uint16_t, const AppIdSession*, bool)
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

MemoryContext::MemoryContext(MemoryTracker&) { }
MemoryContext::~MemoryContext() { }

unsigned AppIdSession::inspector_id = 0;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;

const SfIp* sfip = nullptr;
AppIdSession session(IpProtocol::IP, sfip, 0, appid_inspector);
AppIdHttpSession hsession(session);

TEST_GROUP(appid_http_session)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        appidDebug = new AppIdDebug();
    }

    void teardown() override
    {
        delete appidDebug;
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(appid_http_session, http_field_ids_enum_order)
{
    // Set the fields using integers, then get them by HttpFieldIds,
    // to make sure the order of the HttpFieldIds has not changed
    // in appid_http_session.h.
    AppidChangeBits change_bits;

    hsession.set_field( (HttpFieldIds)0, new std::string("agent"), change_bits );
    hsession.set_field( (HttpFieldIds)1, new std::string("host"), change_bits );
    hsession.set_field( (HttpFieldIds)2, new std::string("referer"), change_bits );
    hsession.set_field( (HttpFieldIds)3, new std::string("uri"), change_bits );
    hsession.set_field( (HttpFieldIds)4, new std::string("cookie"), change_bits );
    hsession.set_field( (HttpFieldIds)5, new std::string("req_body"), change_bits );
    hsession.set_field( (HttpFieldIds)6, new std::string("content_type"), change_bits );
    hsession.set_field( (HttpFieldIds)7, new std::string("location"), change_bits );
    hsession.set_field( (HttpFieldIds)8, new std::string("rsp_body"), change_bits );
    hsession.set_field( (HttpFieldIds)9, new std::string("via"), change_bits );
    hsession.set_field( (HttpFieldIds)10, new std::string("response_code"), change_bits );
    hsession.set_field( (HttpFieldIds)11, new std::string("server"), change_bits );
    hsession.set_field( (HttpFieldIds)12, new std::string("xww"), change_bits );
    hsession.set_field( (HttpFieldIds)13, new std::string("url"), change_bits );

    const std::string* field;
    field = hsession.get_field(REQ_AGENT_FID);
    STRCMP_EQUAL(field->c_str(), "agent");
    field = hsession.get_field(REQ_HOST_FID);
    STRCMP_EQUAL(field->c_str(), "host");
    field = hsession.get_field(REQ_REFERER_FID);
    STRCMP_EQUAL(field->c_str(), "referer");
    field = hsession.get_field(REQ_URI_FID);
    STRCMP_EQUAL(field->c_str(), "uri");
    field = hsession.get_field(REQ_COOKIE_FID);
    STRCMP_EQUAL(field->c_str(), "cookie");
    field = hsession.get_field(REQ_BODY_FID);
    STRCMP_EQUAL(field->c_str(), "req_body");
    field = hsession.get_field(RSP_CONTENT_TYPE_FID);
    STRCMP_EQUAL(field->c_str(), "content_type");
    field = hsession.get_field(RSP_LOCATION_FID);
    STRCMP_EQUAL(field->c_str(), "location");
    field = hsession.get_field(RSP_BODY_FID);
    STRCMP_EQUAL(field->c_str(), "rsp_body");
    field = hsession.get_field(MISC_VIA_FID);
    STRCMP_EQUAL(field->c_str(), "via");
    field = hsession.get_field(MISC_RESP_CODE_FID);
    STRCMP_EQUAL(field->c_str(), "response_code");
    field = hsession.get_field(MISC_SERVER_FID);
    STRCMP_EQUAL(field->c_str(), "server");
    field = hsession.get_field(MISC_XWW_FID);
    STRCMP_EQUAL(field->c_str(), "xww");
    field = hsession.get_field(MISC_URL_FID);
    STRCMP_EQUAL(field->c_str(), "url");

    // Detect changes in host, url, user agent, response, and referer fields
    // that generate appid event consumed by subscribers
    CHECK_EQUAL(change_bits.test(APPID_HOST_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_URL_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_USERAGENT_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_RESPONSE_BIT), true);
    CHECK_EQUAL(change_bits.test(APPID_REFERER_BIT), true);
}

TEST(appid_http_session, set_tun_dest)
{
    const TunnelDest* tun_dest  = nullptr;
    SfIp ipv6;
    ipv6.set("2001:db8:85a3::8a2e:370:7334");
    AppidChangeBits change_bits;
    hsession.set_field(REQ_URI_FID, new std::string("[2001:db8:85a3::8a2e:370:7334]:51413"), change_bits);
    hsession.set_tun_dest();
    tun_dest = hsession.get_tun_dest(); 
    CHECK(tun_dest != nullptr);
    CHECK_EQUAL(tun_dest->port, 51413);
    CHECK_EQUAL((ipv6 == tun_dest->ip), true);
}

TEST(appid_http_session, change_bits_for_referred_appid)
{
    // Testing set_referred_payload_app_id_data
    AppidChangeBits change_bits;
    AppIdPegCounts::init_pegs();
    session.service.set_id(APP_ID_HTTP);
    session.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
    hsession.set_skip_simple_detect(false);
    hsession.set_field( (HttpFieldIds)2, new std::string("referer"), change_bits );
    hsession.process_http_packet(APP_ID_FROM_INITIATOR, change_bits);

    // Detect changes in referred appid
    CHECK_EQUAL(change_bits.test(APPID_REFERRED_BIT), true);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}

