//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_dns_payload_event_handler_test.cc author Bohdan Hryniv <bhryniv@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <cassert>
#include <cstring>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#define private public
#define protected public
#include "appid_dns_payload_event_handler.cc"
#undef private
#undef protected

#include "appid_mock_definitions.h"
#include "appid_mock_session.h"
#include "appid_mock_inspector.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

AppIdSession* session = nullptr;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;

namespace snort
{
AppIdApi appid_api;
AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) { }
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

void AppIdSession::publish_appid_event(AppidChangeBits&, const Packet&, bool, uint32_t) { }
void AppIdSession::set_payload_appid_data(AppId, char*) { }
void AppIdSession::set_ss_application_ids_payload(AppId, AppidChangeBits&) { }
void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection,
    AppId, AppidChangeBits&) { }
void AppIdModule::reset_stats() { }
void AppIdDebug::activate(Flow const*, AppIdSession const*, bool) { }

AppIdSession* AppIdSession::allocate_session(const Packet*, IpProtocol,
    AppidSessionDirection, AppIdInspector&, OdpContext&) { return nullptr; }

static int mock_validate_doh_rc = APPID_SUCCESS;
DnsUdpServiceDetector::DnsUdpServiceDetector(ServiceDiscovery*) : ServiceDetector() { }
int DnsUdpServiceDetector::validate(AppIdDiscoveryArgs&) { return APPID_SUCCESS; }
int DnsUdpServiceDetector::validate_doh(AppIdDiscoveryArgs&) { return mock_validate_doh_rc; }

DnsTcpServiceDetector::DnsTcpServiceDetector(ServiceDiscovery*) : ServiceDetector() { }
int DnsTcpServiceDetector::validate(AppIdDiscoveryArgs&) { return APPID_SUCCESS; }
int DnsTcpServiceDetector::validate_doq(AppIdDiscoveryArgs&) { return APPID_SUCCESS; }

ServiceDetector::ServiceDetector() { }
void ServiceDetector::register_appid(AppId, unsigned, OdpContext&) { }
int ServiceDetector::service_inprocess(AppIdSession&, const Packet*, AppidSessionDirection) { return 0; }
int ServiceDetector::add_service(AppidChangeBits&, AppIdSession&, const Packet*,
    AppidSessionDirection, AppId, const char*, const char*, AppIdServiceSubtype*) { return 0; }
int ServiceDetector::add_service_consume_subtype(AppIdSession&, const Packet*,
    AppidSessionDirection, AppId, const char*, const char*, AppIdServiceSubtype*,
    AppidChangeBits&) { return 0; }
int ServiceDetector::incompatible_data(AppIdSession&, const Packet*,
    AppidSessionDirection) { return 0; }
int ServiceDetector::fail_service(AppIdSession&, const Packet*,
    AppidSessionDirection) { return 0; }

bool OdpContext::is_appid_cpu_profiler_running() { return false; }
void AppIdHttpSession::set_payload(AppId, AppidChangeBits&, const char*, const char*) { }
AppIdHttpSession* AppIdSession::get_http_session(uint32_t) const { return nullptr; }

static const uint8_t dns_query[] = {
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
    'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
    0x00, 0x00, 0x01, 0x00, 0x01
};

static DnsUdpServiceDetector mock_udp_detector(nullptr);

TEST_GROUP(appid_dns_payload_event_handler_tests)
{
    AppIdDnsPayloadEventHandler* handler = nullptr;
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
        appidDebug = new AppIdDebug();
        appidDebug->activate(nullptr, nullptr, false);

        AppIdDetectors* udp_map =
            stub_odp_ctxt.get_service_disco_mgr().get_udp_detectors();
        (*udp_map)["DNS-UDP"] = &mock_udp_detector;

        handler = new AppIdDnsPayloadEventHandler(dummy_appid_inspector);

        flow = new Flow;
    }

    void teardown() override
    {
        delete flow;
        delete handler;
        delete appidDebug;

        stub_odp_ctxt.get_service_disco_mgr().get_udp_detectors()->clear();
        stub_odp_ctxt.get_service_disco_mgr().get_tcp_detectors()->clear();

        delete &session->get_api();
        delete session;
    }
};

TEST(appid_dns_payload_event_handler_tests, null_dsession_returns_gracefully)
{
    delete session->get_dns_session();
    session->api.dsession = nullptr;

    DnsPayloadEvent event(dns_query, sizeof(dns_query), true, true, true);
    handler->handle(event, flow);

    // If we reach here, the null dns session check prevented the crash.
    // Verify dns session is still null (set_doh was not called).
    CHECK(session->get_dns_session() == nullptr);
}

TEST(appid_dns_payload_event_handler_tests, valid_dsession_sets_doh)
{
    CHECK(session->get_dns_session() != nullptr);
    CHECK_FALSE(session->get_dns_session()->is_doh());

    DnsPayloadEvent event(dns_query, sizeof(dns_query), true, true, true);
    handler->handle(event, flow);

    CHECK(session->get_dns_session()->is_doh());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
