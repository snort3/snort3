//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_mcp_event_handler.cc"

#include "appid_mock_definitions.h"
#include "appid_mock_inspector.h"
#include "appid_mock_session.h"
#include "pub_sub/mcp_detection_event.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

static AppIdSession* session = nullptr;
static AppIdHttpSession* changed_http_session = nullptr;
static AppId changed_payload = APP_ID_NONE;
static unsigned ss_payload_updates = 0;
static unsigned published_events = 0;
static bool published_httpx = false;
static uint32_t published_stream_index = 0;

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;

namespace snort
{
AppIdApi appid_api;

Packet::Packet(bool) { }
Packet::~Packet() = default;

Packet* DetectionEngine::get_current_packet()
{
    static Packet packet;
    return &packet;
}

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&)
{ }
}

void appid_log(const Packet*, unsigned char, const char*, ...) { }
void AppIdModule::reset_stats() { }
void AppIdDebug::activate(const Flow*, const AppIdSession*, bool) { }
void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection,
    AppId, AppidChangeBits&) { }

AppIdSession* AppIdApi::get_appid_session(const Flow&)
{
    return session;
}

AppIdSession* AppIdSession::allocate_session(const Packet*, IpProtocol,
    AppidSessionDirection, AppIdInspector&, OdpContext&)
{
    return nullptr;
}

AppIdHttpSession* AppIdSession::get_http_session(uint32_t stream_index) const
{
    return stream_index < api.hsessions.size() ? api.hsessions[stream_index].get() : nullptr;
}

AppIdHttpSession* AppIdSession::get_matching_http_session(
    int64_t stream_id, uint32_t& stream_index) const
{
    for (uint32_t index = 0; index < api.hsessions.size(); ++index)
    {
        if (api.hsessions[index]->get_httpx_stream_id() == stream_id)
        {
            stream_index = index;
            return api.hsessions[index].get();
        }
    }
    return nullptr;
}

void AppIdHttpSession::set_payload(AppId app_id, AppidChangeBits& change_bits,
    const char*, const char*)
{
    changed_http_session = this;
    changed_payload = app_id;
    payload.set_id(app_id);
    change_bits.set(APPID_PAYLOAD_BIT);
}

void AppIdSession::set_ss_application_ids_payload(AppId app_id, AppidChangeBits& change_bits)
{
    ++ss_payload_updates;
    changed_payload = app_id;
    change_bits.set(APPID_PAYLOAD_BIT);
}

void AppIdSession::publish_appid_event(AppidChangeBits&, const Packet&,
    bool is_httpx, uint32_t stream_index)
{
    ++published_events;
    published_httpx = is_httpx;
    published_stream_index = stream_index;
}

TEST_GROUP(appid_mcp_event_handler)
{
    Flow* flow = nullptr;

    void setup() override
    {
        SfIp ip;
        session = new AppIdSession(IpProtocol::TCP, &ip, 0,
            dummy_appid_inspector, stub_odp_ctxt, 0
#ifndef DISABLE_TENANT_ID
            , 0
#endif
        );
        pkt_thread_odp_ctxt = &stub_odp_ctxt;
        flow = new Flow;
        changed_http_session = nullptr;
        changed_payload = APP_ID_NONE;
        ss_payload_updates = 0;
        published_events = 0;
        published_httpx = false;
        published_stream_index = 0;
        appidDebug = new AppIdDebug;
    }

    void teardown() override
    {
        delete &session->get_api();
        delete session;
        session = nullptr;
        delete flow;
        delete appidDebug;
        appidDebug = nullptr;
    }
};

TEST(appid_mcp_event_handler, http1_event_overrides_payload)
{
    AppIdHttpSession* hsession = session->create_http_session();
    const AppId prior_payload_id = APPID_UT_ID + 8;
    hsession->payload.set_id(prior_payload_id);
    const AppId service_id = session->get_service_id();
    const AppId client_id = session->get_client_id();
    Packet packet;
    McpDetectionEvent event(packet, -1, "tools/call");
    AppIdMcpEventHandler handler(dummy_appid_inspector);

    CHECK_EQUAL(prior_payload_id, hsession->payload.get_id());
    CHECK(session->get_payload_id() != APP_ID_MCP);

    handler.handle(event, flow);

    POINTERS_EQUAL(hsession, changed_http_session);
    CHECK_EQUAL(APP_ID_MCP, changed_payload);
    CHECK_EQUAL(APP_ID_MCP, session->get_payload_id());
    CHECK_EQUAL(1u, ss_payload_updates);
    CHECK_EQUAL(1u, published_events);
    CHECK_EQUAL(APP_ID_MCP, hsession->payload.get_id());
    CHECK_FALSE(published_httpx);
    CHECK_EQUAL(service_id, session->get_service_id());
    CHECK_EQUAL(client_id, session->get_client_id());
}

TEST(appid_mcp_event_handler, http1_event_ignores_missing_session)
{
    Packet packet;
    McpDetectionEvent event(packet, -1, "tools/list");
    AppIdMcpEventHandler handler(dummy_appid_inspector);

    CHECK_EQUAL(0u, session->get_api().get_hsessions_size());

    handler.handle(event, flow);

    CHECK_EQUAL(0u, session->get_api().get_hsessions_size());
    POINTERS_EQUAL(nullptr, changed_http_session);
    CHECK_EQUAL(APP_ID_NONE, changed_payload);
    CHECK_EQUAL(0u, ss_payload_updates);
    CHECK_EQUAL(0u, published_events);
}

TEST(appid_mcp_event_handler, http2_updates_only_matching_stream)
{
    const AppIdHttpSession* other_stream = session->create_http_session(3);
    AppIdHttpSession* mcp_stream = session->create_http_session(7);
    Packet packet;
    McpDetectionEvent event(packet, 7, "tools/list");
    AppIdMcpEventHandler handler(dummy_appid_inspector);

    handler.handle(event, flow);

    POINTERS_EQUAL(mcp_stream, changed_http_session);
    CHECK(changed_http_session != other_stream);
    CHECK_EQUAL(APP_ID_MCP, changed_payload);
    CHECK_EQUAL(0u, ss_payload_updates);
    CHECK_EQUAL(1u, published_events);
    CHECK_TRUE(published_httpx);
    CHECK_EQUAL(1u, published_stream_index);
}

TEST(appid_mcp_event_handler, http2_event_ignores_missing_stream)
{
    Packet packet;
    McpDetectionEvent event(packet, 7, "tools/list");
    AppIdMcpEventHandler handler(dummy_appid_inspector);

    CHECK_EQUAL(0u, session->get_api().get_hsessions_size());

    handler.handle(event, flow);

    CHECK_EQUAL(0u, session->get_api().get_hsessions_size());
    POINTERS_EQUAL(nullptr, changed_http_session);
    CHECK_EQUAL(APP_ID_NONE, changed_payload);
    CHECK_EQUAL(0u, ss_payload_updates);
    CHECK_EQUAL(0u, published_events);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
