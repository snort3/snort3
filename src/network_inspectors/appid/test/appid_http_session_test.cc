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
    char**, snort::AppIdServiceSubtype**)
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
    const char*, AppId*, AppId*, AppId*, AppId*, bool)
{
    return true;
}

// AppIdSession mock functions
AppIdSession::AppIdSession(IpProtocol, const SfIp*, uint16_t, AppIdInspector& inspector)
    : FlowData(inspector_id, &inspector), inspector(inspector)
{
}

AppIdSession::~AppIdSession()
{
}

void AppIdSession::set_client_appid_data(AppId, char*)
{
}

void AppIdSession::set_service_appid_data(AppId, char*, char*)
{
}

void AppIdSession::set_payload_appid_data(AppId, char*)
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

void AppIdSession::set_referred_payload_app_id_data(AppId)
{
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
void Profiler::register_module(Module*)
{
}

void Profiler::register_module(const char*, const char*, Module*)
{
}

void Profiler::register_module(const char*, const char*, get_profile_stats_fn)
{
}

void Profiler::consolidate_stats()
{
}

void Profiler::reset_stats()
{
}

void Profiler::show_stats()
{
}

MemoryContext::MemoryContext(MemoryTracker&)
{
}

MemoryContext::~MemoryContext()
{
}

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
    hsession.set_field( (HttpFieldIds)0, new std::string("agent") );
    hsession.set_field( (HttpFieldIds)1, new std::string("host") );
    hsession.set_field( (HttpFieldIds)2, new std::string("referer") );
    hsession.set_field( (HttpFieldIds)3, new std::string("uri") );
    hsession.set_field( (HttpFieldIds)4, new std::string("cookie") );
    hsession.set_field( (HttpFieldIds)5, new std::string("req_body") );
    hsession.set_field( (HttpFieldIds)6, new std::string("content_type") );
    hsession.set_field( (HttpFieldIds)7, new std::string("location") );
    hsession.set_field( (HttpFieldIds)8, new std::string("rsp_body") );
    hsession.set_field( (HttpFieldIds)9, new std::string("via") );
    hsession.set_field( (HttpFieldIds)10, new std::string("response_code") );
    hsession.set_field( (HttpFieldIds)11, new std::string("server") );
    hsession.set_field( (HttpFieldIds)12, new std::string("xww") );
    hsession.set_field( (HttpFieldIds)13, new std::string("url") );

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
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}

