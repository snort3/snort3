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

// appid_http_event_test.cc author Steve Chew <stechew@cisco.com>
// unit test for the http inspection event handler.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "framework/data_bus.h"
#include "network_inspectors/appid/appid_http_event_handler.cc"
#include "protocols/protocol_ids.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"

#include "appid_mock_definitions.h"
#include "appid_mock_inspector.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
ThirdPartyAppIdContext* AppIdContext::tp_appid_ctxt = nullptr;
THREAD_LOCAL bool ThirdPartyAppIdContext::tp_reload_in_progress = false;
bool DiscoveryFilter::is_app_monitored(const snort::Packet*, uint8_t*){return true;}
void AppIdDebug::activate(const Flow*, const AppIdSession*, bool) { active = true; }
void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

using namespace snort;

namespace snort
{
AppIdApi appid_api;
Packet::Packet(bool) { }
Packet::~Packet() = default;

Packet* DetectionEngine::get_current_packet()
{
    static Packet p;
    return &p;
}

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
}

const char* content_type = nullptr;
const char* cookie = nullptr;
const char* host = nullptr;
const char* location = nullptr;
const char* referer = nullptr;
int32_t response_code = 0;
const char* server = nullptr;
const char* x_working_with = nullptr;
const char* uri = nullptr;
const char* useragent = nullptr;
const char* via = nullptr;

class FakeHttpMsgHeader
{
};
FakeHttpMsgHeader* fake_msg_header = nullptr;

AppIdSession* AppIdSession::allocate_session(const Packet*, IpProtocol, AppidSessionDirection,
    AppIdInspector&, OdpContext&)
{
    return nullptr;
}
void AppIdModule::reset_stats() {}
void AppIdSession::set_application_ids_service(AppId, AppidChangeBits&) {}
void AppIdSession::set_ss_application_ids(AppId, AppId, AppId, AppId, AppId, AppidChangeBits&) {}
AppIdHttpSession* AppIdSession::get_http_session(uint32_t stream_index) const
{
    if (stream_index < api.hsessions.size())
    {
        return api.hsessions[stream_index];
    }
    return nullptr;
}

void AppIdSession::delete_all_http_sessions()
{
    for (auto hsession : api.hsessions)
        delete hsession;
    api.hsessions.clear();
}

void AppIdHttpSession::set_http_change_bits(AppidChangeBits&, HttpFieldIds) {}

void AppIdHttpSession::set_scan_flags(HttpFieldIds id)
{
    switch (id)
    {
    case REQ_URI_FID:
        asd.scan_flags |= SCAN_HTTP_URI_FLAG;
        break;
    case MISC_VIA_FID:
        asd.scan_flags |= SCAN_HTTP_VIA_FLAG;
        break;
    case REQ_AGENT_FID:
        asd.scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        break;
    case RSP_CONTENT_TYPE_FID:
        asd.scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
        break;
    case MISC_SERVER_FID:
        asd.scan_flags |= SCAN_HTTP_VENDOR_FLAG;
        break;
    case MISC_XWW_FID:
        asd.scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
        break;
    case REQ_HOST_FID:
    case MISC_URL_FID:
        asd.scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
        break;
    default:
        break;
    }
}

void AppIdHttpSession::set_field(HttpFieldIds id, const std::string* str,
    AppidChangeBits&)
{
    delete meta_data[id];
    meta_data[id] = str;
    set_scan_flags(id);
}

void AppIdHttpSession::set_field(HttpFieldIds id, const uint8_t* str, int32_t len,
    AppidChangeBits&)
{
    delete meta_data[id];
    if (str and len)
    {
        meta_data[id] = new std::string((const char*)str, len);
        set_scan_flags(id);
    }
    else
        meta_data[id] = nullptr;
}
void AppIdHttpSession::print_field(HttpFieldIds, const std::string*) {}

const uint8_t* HttpEvent::get_content_type(int32_t& length)
{
    global_field.set(0, nullptr);
    if (content_type)
        global_field.set(strlen(content_type), (const uint8_t*)content_type);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_cookie(int32_t& length)
{
    global_field.set(0, nullptr);
    if (cookie)
        global_field.set(strlen(cookie), (const uint8_t*)cookie);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_authority(int32_t& length)
{
    global_field.set(0, nullptr);
    if (host)
        global_field.set(strlen(host), (const uint8_t*)host);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_location(int32_t& length)
{
    global_field.set(0, nullptr);
    if (location)
        global_field.set(strlen(location), (const uint8_t*)location);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_referer(int32_t& length)
{
    global_field.set(0, nullptr);
    if (referer)
        global_field.set(strlen(referer), (const uint8_t*)referer);
    length = global_field.length();
    return global_field.start();
}

int32_t HttpEvent::get_response_code()
{
    return response_code;
}

const uint8_t* HttpEvent::get_server(int32_t& length)
{
    global_field.set(0, nullptr);
    if (server)
        global_field.set(strlen(server), (const uint8_t*)server);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_uri(int32_t& length)
{
    global_field.set(0, nullptr);
    if (uri)
        global_field.set(strlen(uri), (const uint8_t*)uri);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_user_agent(int32_t& length)
{
    global_field.set(0, nullptr);
    if (useragent)
        global_field.set(strlen(useragent), (const uint8_t*)useragent);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_via(int32_t& length)
{
    global_field.set(0, nullptr);
    if (via)
        global_field.set(strlen(via), (const uint8_t*)via);
    length = global_field.length();
    return global_field.start();
}

const uint8_t* HttpEvent::get_x_working_with(int32_t& length)
{
    global_field.set(0, nullptr);
    if (x_working_with)
        global_field.set(strlen(x_working_with), (const uint8_t*)x_working_with);
    length = global_field.length();
    return global_field.start();
}

bool HttpEvent::contains_webdav_method()
{
    return true;
}

bool HttpEvent::get_is_httpx() const
{
    return false;
}

int64_t HttpEvent::get_httpx_stream_id() const
{
    return 0;
}

Flow* flow = nullptr;
AppIdSession* mock_session = nullptr;

AppIdSession* AppIdApi::get_appid_session(const Flow&)
{
    mock().actualCall("get_appid_session");
    return mock_session;
}

void AppIdSession::publish_appid_event(AppidChangeBits&, const Packet&, bool, uint32_t) { }

TEST_GROUP(appid_http_event)
{
    void setup() override
    {
        flow = new Flow;
        SfIp ip;
        mock_session = new AppIdSession(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector, stub_odp_ctxt);
        pkt_thread_odp_ctxt = &mock_session->get_odp_ctxt();
        mock_session->create_http_session();
        flow->set_flow_data(mock_session);
        mock_session->flags = APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED;
        appidDebug = new AppIdDebug();
        appidDebug->activate(nullptr, nullptr, false);
    }

    void teardown() override
    {
        fake_msg_header = nullptr;
        delete &mock_session->get_api();
        delete mock_session;
        delete flow;
        mock().clear();
        delete appidDebug;
    }
};

TEST(appid_http_event, handle_null_appid_data)
{
    HttpEvent event(nullptr, false, 0);
    HttpEventHandler event_handler(HttpEventHandler::REQUEST_EVENT, dummy_appid_inspector);
    mock().expectOneCall("get_appid_session");
    event_handler.handle(event, flow);
    mock().checkExpectations();
}

TEST(appid_http_event, handle_null_msg_header)
{
    HttpEvent event(nullptr, false, 0);
    HttpEventHandler event_handler(HttpEventHandler::REQUEST_EVENT, dummy_appid_inspector);

    mock().strictOrder();
    mock().expectOneCall("get_appid_session");
    event_handler.handle(event, flow);
    mock().checkExpectations();
}

#define RESPONSE_CODE 301

struct TestData
{
    HttpEventHandler::HttpEventType type = HttpEventHandler::REQUEST_EVENT;
    unsigned scan_flags = 0;
    PegCount http_flows = 1;   // Default to 1 since most tests have 1.
    const char* content_type = nullptr;
    const char* cookie = nullptr;
    const char* host = nullptr;
    const char* location = nullptr;
    const char* referer = nullptr;
    int32_t response_code = 0;
    const char* server = nullptr;
    const char* x_working_with = nullptr;
    const char* uri = nullptr;
    const char* useragent = nullptr;
    const char* via = nullptr;
};

static void run_event_handler(TestData test_data, TestData* expect_data = nullptr)
{
    HttpEvent event(nullptr, false, 0);
    FakeHttpMsgHeader http_msg_header;
    HttpEventHandler event_handler(test_data.type, dummy_appid_inspector);
    fake_msg_header = &http_msg_header;

    host = test_data.host;
    location = test_data.location;
    referer = test_data.referer;
    server = test_data.server;
    x_working_with = test_data.x_working_with;
    uri = test_data.uri;
    useragent = test_data.useragent;
    via = test_data.via;
    content_type = test_data.content_type;
    cookie = test_data.cookie;
    response_code = test_data.response_code;

    if (expect_data == nullptr)
        expect_data = &test_data;

    mock().strictOrder();
    mock().expectOneCall("get_appid_session");
    MockAppIdHttpSession* hsession = (MockAppIdHttpSession*)mock_session->get_http_session();
    hsession->reset();
    event_handler.handle(event, flow);
    LONGS_EQUAL(expect_data->scan_flags, mock_session->scan_flags);
    STRCMP_EQUAL(expect_data->host, hsession->get_cfield(REQ_HOST_FID));
    STRCMP_EQUAL(expect_data->uri, hsession->get_cfield(REQ_URI_FID));
    STRCMP_EQUAL(expect_data->content_type, hsession->get_cfield(RSP_CONTENT_TYPE_FID));
    STRCMP_EQUAL(expect_data->cookie, hsession->get_cfield(REQ_COOKIE_FID));
    STRCMP_EQUAL(expect_data->location, hsession->get_cfield(RSP_LOCATION_FID));
    STRCMP_EQUAL(expect_data->referer, hsession->get_cfield(REQ_REFERER_FID));
    STRCMP_EQUAL(expect_data->server, hsession->get_cfield(MISC_SERVER_FID));
    STRCMP_EQUAL(expect_data->x_working_with, hsession->get_cfield(MISC_XWW_FID));
    STRCMP_EQUAL(expect_data->useragent, hsession->get_cfield(REQ_AGENT_FID));
    STRCMP_EQUAL(expect_data->via, hsession->get_cfield(MISC_VIA_FID));
    if (nullptr == hsession->get_field(MISC_RESP_CODE_FID))
    {
        LONGS_EQUAL(0, expect_data->response_code);
    }
    else
    {
        LONGS_EQUAL(expect_data->response_code, strtol(hsession->get_field(
            MISC_RESP_CODE_FID)->c_str(), nullptr, 10));
    }
    mock().checkExpectations();
}

TEST(appid_http_event, handle_msg_header_no_headers_exist)
{
    TestData test_data;
    test_data.scan_flags = 0;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_only_host)
{
    TestData test_data;
    test_data.scan_flags = SCAN_HTTP_HOST_URL_FLAG;
    test_data.host = HOST;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_cookie)
{
    TestData test_data;
    test_data.scan_flags = 0;
    test_data.cookie = COOKIE;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_host_and_uri)
{
    TestData test_data;
    test_data.scan_flags = SCAN_HTTP_HOST_URL_FLAG | SCAN_HTTP_URI_FLAG;
    test_data.host = HOST;
    test_data.uri = URI;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_user_agent)
{
    TestData test_data;
    test_data.scan_flags = SCAN_HTTP_USER_AGENT_FLAG;
    test_data.useragent = USERAGENT;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_x_working_with)
{
    TestData test_data;
    test_data.scan_flags = SCAN_HTTP_XWORKINGWITH_FLAG;
    test_data.x_working_with = X_WORKING_WITH;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_referer)
{
    TestData test_data;
    test_data.scan_flags = 0;
    test_data.referer = REFERER;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_via)
{
    TestData test_data;
    test_data.scan_flags = SCAN_HTTP_VIA_FLAG;
    test_data.via = VIA;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_content_type)
{
    TestData test_data;
    test_data.type = HttpEventHandler::RESPONSE_EVENT;
    test_data.scan_flags = 0x100;
    test_data.http_flows = 0;   //  Flows are only counted on request header
    test_data.content_type = CONTENT_TYPE;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_location)
{
    TestData test_data;
    test_data.type = HttpEventHandler::RESPONSE_EVENT;
    test_data.scan_flags = 0;
    test_data.http_flows = 0;   //  Flows are only counted on request header
    test_data.location = LOCATION;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_server)
{
    TestData test_data;
    test_data.type = HttpEventHandler::RESPONSE_EVENT;
    test_data.scan_flags = 0x40;
    test_data.http_flows = 0;   //  Flows are only counted on request header
    test_data.server = SERVER;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_response_code)
{
    TestData test_data;
    test_data.type = HttpEventHandler::RESPONSE_EVENT;
    test_data.scan_flags = 0;
    test_data.http_flows = 0;   //  Flows are only counted on request header
    test_data.response_code = RESPONSE_CODE;

    run_event_handler(test_data);
}

TEST(appid_http_event, handle_msg_header_response_code_out_of_range)
{
    TestData test_data;
    test_data.type = HttpEventHandler::RESPONSE_EVENT;
    test_data.scan_flags = 0;
    test_data.http_flows = 0;   //  Flows are only counted on request header
    test_data.response_code = 1000;

    TestData expect_data = test_data;
    expect_data.response_code = 0;

    run_event_handler(test_data, &expect_data);
}

TEST(appid_http_event, handle_msg_header_all_response_headers)
{
    TestData test_data;
    test_data.type = HttpEventHandler::RESPONSE_EVENT;
    test_data.scan_flags = 0x101;
    test_data.http_flows = 0;   //  Flows are only counted on request header
    test_data.response_code = RESPONSE_CODE;
    test_data.content_type = CONTENT_TYPE;
    test_data.location = LOCATION;
    test_data.via = VIA;

    TestData expect_data = test_data;

    //  Fill in the request data too to demonstrate that it is not copied
    //  during response header handling.
    test_data.uri = URI;
    test_data.host = HOST;
    test_data.referer = REFERER;
    test_data.useragent = USERAGENT;
    test_data.cookie = COOKIE;

    run_event_handler(test_data, &expect_data);
}

TEST(appid_http_event, handle_msg_header_all_request_headers)
{
    TestData test_data;
    test_data.type = HttpEventHandler::REQUEST_EVENT;
    test_data.scan_flags = SCAN_HTTP_VIA_FLAG | SCAN_HTTP_USER_AGENT_FLAG |
        SCAN_HTTP_HOST_URL_FLAG | SCAN_HTTP_URI_FLAG;
    test_data.uri = URI;
    test_data.cookie = COOKIE;
    test_data.host = HOST;
    test_data.referer = REFERER;
    test_data.useragent = USERAGENT;
    test_data.via = VIA;

    TestData expect_data = test_data;

    //  Fill in the request data too to demonstrate that it is not copied
    //  during response header handling.
    test_data.response_code = RESPONSE_CODE;
    test_data.content_type = CONTENT_TYPE;
    test_data.location = LOCATION;

    run_event_handler(test_data, &expect_data);
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

