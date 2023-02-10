//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// detector_sip_test.cc author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define SIP_UNIT_TEST

#include "detector_plugins/detector_sip.cc"
#include "detector_plugins/sip_patterns.cc"

#include "framework/data_bus.h"
#include "framework/module.cc"
#include "framework/mpse_batch.h"
#include "network_inspectors/appid/appid_utils/sf_mlmp.cc"
#include "protocols/protocol_ids.h"
#include "utils/util_cstring.cc"

#include "appid_inspector.h"
#include "detector_plugins_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

static AppIdConfig config;
static AppIdContext context(config);
OdpContext* AppIdContext::odp_ctxt = nullptr;
static AppIdModule appid_mod;
static AppIdInspector appid_inspector(appid_mod);
static Packet pkt;
static SfIp sfip;
AppIdSession *session = nullptr;
THREAD_LOCAL AppIdDebug* appidDebug;
ClientDiscovery cdm;
SipUdpClientDetector cd(&cdm);
ClientSIPData* sip_data = nullptr;
MpseGroup mpse_group;
static bool prep_patterns = true;

namespace snort
{
AppIdApi appid_api;
AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) { }
Flow::Flow() = default;
Flow::~Flow() = default;
AppIdSession* AppIdApi::get_appid_session(snort::Flow const&) { return nullptr; }

MpseGroup::~MpseGroup() = default;
SearchTool::SearchTool(bool)
{
    mpsegrp = &mpse_group;
}
void SearchTool::reload() { }  // LCOV_EXCL_LINE
int SearchTool::find_all(const char*, unsigned, MpseMatch, bool, void*)
{
    // Seg-fault will be observed if this is called without initializing pattern matchers
    assert(mpsegrp);
    return 0;
}
}

AppIdInspector::AppIdInspector(AppIdModule&) { }

bool AppIdInspector::configure(snort::SnortConfig*)
{
    ctxt = &context;
    return true;
}

// LCOV_EXCL_START
void AppIdInspector::eval(Packet*) { }
void AppIdInspector::show(const SnortConfig*) const { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }
void AppIdInspector::tear_down(SnortConfig*) { }
AppIdContext& AppIdInspector::get_ctxt() const { return *ctxt; }
// LCOV_EXCL_STOP

AppIdInspector::~AppIdInspector() = default;

void AppIdContext::create_odp_ctxt()
{
    odp_ctxt = new OdpContext(config, nullptr);
}

void AppIdContext::pterm() { delete odp_ctxt; }

void OdpContext::initialize(AppIdInspector&)
{
    sip_matchers.finalize_patterns(*this);
}

void SipPatternMatchers::finalize_patterns(OdpContext&)
{
    sip_ua_matcher = mlmpCreate();
    sip_server_matcher = mlmpCreate();

    if (prep_patterns)
    {
        mlmpProcessPatterns(sip_ua_matcher);
        mlmpProcessPatterns(sip_server_matcher);
    }
}

AppIdSession* AppIdSession::allocate_session(snort::Packet const*, IpProtocol,
    AppidSessionDirection, AppIdInspector&, OdpContext& odp_ctxt)
{
    session = new AppIdSession(IpProtocol::IP, &sfip, 0, appid_inspector, odp_ctxt);
    return session;
}

void AppIdSession::publish_appid_event(AppidChangeBits&, const Packet&, bool, uint32_t) { }
AppIdDiscovery::~AppIdDiscovery() = default;

// LCOV_EXCL_START
void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection,
    AppId, AppidChangeBits&) { }
void ClientDiscovery::initialize(AppIdInspector&) { }
void ClientDiscovery::reload() { }
// LCOV_EXCL_STOP

void AppIdDiscovery::register_detector(const string&, AppIdDetector*, IpProtocol) { }

// LCOV_EXCL_START
void AppIdDiscovery::add_pattern_data(AppIdDetector*, snort::SearchTool&, int,
    unsigned char const*, unsigned int, unsigned int) { }
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, unsigned char const*, unsigned int,
    int, unsigned int) { }
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, unsigned char const*, unsigned int,
    int, unsigned int) { }
int AppIdDiscovery::add_service_port(AppIdDetector*, ServiceDetectorPort const&) { return 0; }
void AppIdModule::reset_stats() { }
// LCOV_EXCL_STOP

DnsPatternMatchers::~DnsPatternMatchers() = default;
EveCaPatternMatchers::~EveCaPatternMatchers() = default;
SslPatternMatchers::~SslPatternMatchers() = default;
HttpPatternMatchers::~HttpPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
CipPatternMatchers::~CipPatternMatchers() = default;

ClientDetector::ClientDetector() { }

// LCOV_EXCL_START
void ClientDetector::register_appid(int, unsigned int, OdpContext&) { }
int AppIdDetector::initialize(AppIdInspector&) { return 1; }
void AppIdDetector::reload() { }
int AppIdDetector::data_add(AppIdSession&, void*, void (*)(void*)) { return 1; }
void AppIdDetector::add_user(AppIdSession&, char const*, int, bool, AppidChangeBits&) { }
void AppIdDetector::add_payload(AppIdSession&, int) { }
void AppIdDetector::add_app(snort::Packet const&, AppIdSession&, AppidSessionDirection, int,
    int, char const*, AppidChangeBits&) { }
// LCOV_EXCL_STOP

SipEvent::SipEvent(snort::Packet const* p, SIPMsg const*, SIP_DialogData const*) { this->p = p; }
SipEvent::~SipEvent() = default;
bool SipEvent::is_invite() const { return false; }
bool SipEvent::is_dialog_established() const { return false; }
int SipPatternMatchers::get_client_from_ua(char const*, unsigned int, int&, char*&) { return 0; }  // LCOV_EXCL_LINE
void SipEventHandler::service_handler(SipEvent&, AppIdSession&, AppidChangeBits&) { }
SipUdpClientDetector* SipEventHandler::client = &cd;

void* AppIdDetector::data_get(AppIdSession&)
{
    sip_data = new ClientSIPData();
    sip_data->from = "<sip:1001@51.1.1.130:11810>";
    return (void*)sip_data;
}

TEST_GROUP(detector_sip_tests)
{
    void setup() override
    {
        appid_inspector.configure(nullptr);
    }
    void teardown() override
    {
        delete session;
        delete sip_data;
        context.pterm();
    }
};

TEST(detector_sip_tests, sip_event_handler)
{
    context.create_odp_ctxt();
    OdpContext* odpctxt = pkt_thread_odp_ctxt = &context.get_odp_ctxt();

    odpctxt->initialize(appid_inspector);
    SipEvent event(&pkt, nullptr, nullptr);
    SipEventHandler event_handler(appid_inspector);
    Flow* flow = new Flow();
    event_handler.handle(event, flow);
    delete sip_data;
    delete session;

    // Create and assign new ODP context to appid inspector without finalizing SIP patterns
    context.create_odp_ctxt();
    prep_patterns = false;
    context.get_odp_ctxt().initialize(appid_inspector);
    event_handler.handle(event, flow);
    delete flow;
    delete odpctxt;
    prep_patterns = true;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
