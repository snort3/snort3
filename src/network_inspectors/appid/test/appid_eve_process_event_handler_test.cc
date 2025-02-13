//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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
//
// appid_eve_process_event_handler_test.cc author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_eve_process_event_handler.cc"

#include <string>

#include "framework/data_bus.h"
#include "protocols/protocol_ids.h"

#include "appid_mock_definitions.h"
#include "appid_mock_session.h"
#include "appid_mock_inspector.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

AppIdSession *session = nullptr;
THREAD_LOCAL AppIdDebug* appidDebug;

using namespace snort;
using namespace std;

namespace snort
{
AppIdApi appid_api;
AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
        StashGenericObject(STASH_GENERIC_OBJECT_APPID) { }
AppIdSession* AppIdApi::get_appid_session(Flow const&) { return session; }

Packet::Packet(bool) { }
Packet::~Packet() = default;

Packet* DetectionEngine::get_current_packet()
{
    static Packet p;
    return &p;
}
}

void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

AppIdSession* AppIdSession::allocate_session(const Packet*, IpProtocol,
    AppidSessionDirection, AppIdInspector&, OdpContext&)
{
    return nullptr;
}

void AppIdSession::publish_appid_event(AppidChangeBits&, const Packet&, bool, uint32_t)
{
    return;
}

bool SslPatternMatchers::scan_hostname(const uint8_t*, size_t, AppId&, AppId& payload)
{
    payload = APPID_UT_ID + 1;
    return true;
}

void AppIdSession::set_ss_application_ids_payload(AppId, AppidChangeBits&)
{
    return;
}

void AppIdSession::set_client_appid_data(AppId, char*, bool)
{
    set_client_id(APPID_UT_ID);
    return;
}

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection,
    AppId, AppidChangeBits&) { }
void AppIdModule::reset_stats() { }
void AppIdDebug::activate(snort::Flow const*, AppIdSession const*, bool) { }

void AppIdSession::update_encrypted_app_id(AppId) {}
void HttpPatternMatchers::identify_user_agent(const char*, int, AppId&, AppId& client, char**)
{
    client = APPID_UT_ID;
}

AppId AlpnPatternMatchers::match_alpn_pattern(const string& str)
{
    if (!str.compare("h3"))
        return APPID_UT_ID + 2;
    else
        return APP_ID_NONE;
}

AppId EveCaPatternMatchers::match_eve_ca_pattern(const string&, uint8_t)
{
    return APPID_UT_ID;
}

TEST_GROUP(appid_eve_process_event_handler_tests)
{
    void setup() override
    {
        SfIp ip;
        session = new AppIdSession(IpProtocol::TCP, &ip, 0, dummy_appid_inspector, stub_odp_ctxt, 0
#ifndef DISABLE_TENANT_ID
        ,0
#endif
        );
        pkt_thread_odp_ctxt = &stub_odp_ctxt;
        appidDebug = new AppIdDebug();
        appidDebug->activate(nullptr, nullptr, false);
    }

    void teardown() override
    {
        delete &session->get_api();
        delete session;
        delete appidDebug;
    }
};

TEST(appid_eve_process_event_handler_tests, eve_process_event_handler)
{
    Packet p;
    EveProcessEvent event(p, "firefox", 90);
    event.set_client_process_mapping(true);
    AppIdEveProcessEventHandler event_handler(dummy_appid_inspector);
    Flow* flow = new Flow;
    event_handler.handle(event, flow);
    CHECK(session->get_eve_client_app_id() == APPID_UT_ID);
    delete flow;
}

TEST(appid_eve_process_event_handler_tests, eve_user_agent_event_handler)
{
    Packet p;
    EveProcessEvent event(p, "firefox", 90);
    event.set_user_agent("chrome");
    AppIdEveProcessEventHandler event_handler(dummy_appid_inspector);
    Flow* flow = new Flow;
    event_handler.handle(event, flow);
    CHECK(session->get_client_id() == APPID_UT_ID);
    delete flow;
}

TEST(appid_eve_process_event_handler_tests, eve_server_name_event_handler)
{
    Packet p;
    EveProcessEvent event(p, "firefox", 90);
    event.set_server_name("www.google.com");
    AppIdEveProcessEventHandler event_handler(dummy_appid_inspector);
    Flow* flow = new Flow;
    event_handler.handle(event, flow);
    CHECK(session->get_payload_id() == APPID_UT_ID + 1);
    delete flow;
}

TEST(appid_eve_process_event_handler_tests, eve_alpn_event_handler)
{
    Packet p;
    vector<string> alpn = {"h3"};
    EveProcessEvent event(p, "firefox", 90);
    event.set_alpn(alpn);
    event.set_quic(true);
    AppIdEveProcessEventHandler event_handler(dummy_appid_inspector);
    Flow* flow = new Flow;
    event_handler.handle(event, flow);
    CHECK(session->get_alpn_service_app_id() == APPID_UT_ID + 2);
    delete flow;
}

TEST(appid_eve_process_event_handler_tests, eve_unknown_alpn_event_handler)
{
    Packet p;
    vector<string> alpn = {"smb"};
    EveProcessEvent event(p, "firefox", 90);
    event.set_alpn(alpn);
    event.set_quic(true);
    AppIdEveProcessEventHandler event_handler(dummy_appid_inspector);
    Flow* flow = new Flow;
    event_handler.handle(event, flow);
    CHECK(session->get_alpn_service_app_id() == APP_ID_NONE);
    delete flow;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

