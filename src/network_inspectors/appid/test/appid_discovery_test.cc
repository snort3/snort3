//--------------------------------------------------------------------------
// Copyright (C) 2018-2019 Cisco and/or its affiliates. All rights reserved.
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
// appid_discovery_test.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define APPID_MOCK_INSPECTOR_H // avoiding mocked inspector

#include "host_tracker/host_cache.h"
#include "network_inspectors/appid/appid_discovery.cc"

#include "search_engines/search_tool.h"
#include "utils/sflsq.cc"

#include "appid_mock_session.h"
#include "tp_lib_handler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

namespace snort
{
// Stubs for packet
Packet::Packet(bool) {}
Packet::~Packet() {}

// Stubs for inspector
Inspector::Inspector()
{
    set_api(nullptr);
}
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

// Stubs for module
Module::Module(char const*, char const*) {}
bool Module::set(const char*, Value&, SnortConfig*) { return true; }
void Module::sum_stats(bool) {}
void Module::show_interval_stats(std::vector<unsigned>&, FILE*) {}
void Module::show_stats() {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const { return 0; }

// Stubs for logs
void LogMessage(const char*,...) {}
void ErrorMessage(const char*,...) {}
void LogLabel(const char*, FILE*) {}

// Stubs for utils
char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
char* snort_strndup(const char* src, size_t)
{
    return snort_strdup(src);
}
time_t packet_time() { return std::time(nullptr); }

// Stubs for search_tool
SearchTool::SearchTool(const char*, bool) {}
SearchTool::~SearchTool() {}
void SearchTool::add(const char*, unsigned, int, bool) {}
void SearchTool::add(const char*, unsigned, void*, bool) {}
void SearchTool::add(const uint8_t*, unsigned, int, bool) {}
void SearchTool::add(const uint8_t*, unsigned, void*, bool) {}

// Stubs for ip
namespace ip
{
void IpApi::set(const SfIp& sip, const SfIp& dip)
{
    type = IAT_DATA;
    src = sip;
    dst = dip;
    iph = nullptr;
}
} // namespace ip

} // namespace snort

// Stubs for publish
static bool databus_publish_called = false;
static char test_log[256];
void DataBus::publish(const char*, DataEvent& event, Flow*)
{
    databus_publish_called = true;
    AppidEvent* appid_event = (AppidEvent*)&event;
    snprintf(test_log, 256, "Published change_bits == %s",
        appid_event->get_change_bitset().to_string().c_str());
}

// Stubs for matchers
static HttpPatternMatchers* http_matchers;
HttpPatternMatchers::~HttpPatternMatchers() {}
void HttpPatternMatchers::get_http_offsets(Packet*, AppIdHttpSession*) {}
HttpPatternMatchers* HttpPatternMatchers::get_instance()
{
    return http_matchers;
}

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

// Stubs for AppIdModule
AppIdModule::AppIdModule(): Module("appid_mock", "appid_mock_help") {}
AppIdModule::~AppIdModule() {}
void AppIdModule::sum_stats(bool) {}
void AppIdModule::show_dynamic_stats() {}
bool AppIdModule::begin(char const*, int, SnortConfig*) { return true; }
bool AppIdModule::end(char const*, int, SnortConfig*) { return true; }
bool AppIdModule::set(char const*, Value&, SnortConfig*) { return true; }
const Command* AppIdModule::get_commands() const { return nullptr; }
const PegInfo* AppIdModule::get_pegs() const { return nullptr; }
PegCount* AppIdModule::get_counts() const { return nullptr; }
ProfileStats* AppIdModule::get_profile() const { return nullptr; }

// Stubs for config
AppIdModuleConfig::~AppIdModuleConfig() {}
static AppIdModuleConfig app_config;
static AppIdConfig my_app_config(&app_config);
AppId AppIdConfig::get_port_service_id(IpProtocol, uint16_t)
{
    return APP_ID_NONE;
}

AppId AppIdConfig::get_protocol_service_id(IpProtocol)
{
    return APP_ID_NONE;
}

// Stubs for AppIdInspector
AppIdInspector::AppIdInspector(AppIdModule&) {}
AppIdInspector::~AppIdInspector() = default;
void AppIdInspector::eval(Packet*) { }
bool AppIdInspector::configure(SnortConfig*) { return true; }
void AppIdInspector::show(SnortConfig*) { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }
AppIdConfig* AppIdInspector::get_appid_config()
{
    my_app_config.mod_config = &app_config;
    return &my_app_config;
}

// Stubs for AppInfoManager
AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId)
{
    return nullptr;
}
const char* AppInfoManager::get_app_name(int32_t)
{
    return nullptr;
}

// Stubs for AppIdSession
void AppIdSession::sync_with_snort_protocol_id(AppId, Packet*) {}
void AppIdSession::check_app_detection_restart(AppidChangeBits&) {}
void AppIdSession::set_client_appid_data(AppId, AppidChangeBits&, char*) {}
void AppIdSession::examine_rtmp_metadata(AppidChangeBits&) {}
void AppIdSession::examine_ssl_metadata(Packet*, AppidChangeBits&) {}
void AppIdSession::update_encrypted_app_id(AppId) {}
bool AppIdSession::is_tp_processing_done() const {return 0;}
AppIdSession* AppIdSession::allocate_session(const Packet*, IpProtocol,
    AppidSessionDirection, AppIdInspector*)
{
    return nullptr;
}
void AppIdHttpSession::set_tun_dest(){}

// Stubs for ServiceDiscovery
void ServiceDiscovery::initialize() {}
void ServiceDiscovery::finalize_service_patterns() {}
void ServiceDiscovery::match_by_pattern(AppIdSession&, const Packet*, IpProtocol) {}
void ServiceDiscovery::get_port_based_services(IpProtocol, uint16_t, AppIdSession&) {}
void ServiceDiscovery::get_next_service(const Packet*, const AppidSessionDirection, AppIdSession&) {}
int ServiceDiscovery::identify_service(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return 0; }
int ServiceDiscovery::add_ftp_service_state(AppIdSession&) { return 0; }
bool ServiceDiscovery::do_service_discovery(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return 0; }
int ServiceDiscovery::incompatible_data(AppIdSession&, const Packet*,AppidSessionDirection,
    ServiceDetector*) { return 0; }
int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection,
    ServiceDetector*, ServiceDiscoveryState*) { return 0; }
int ServiceDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
ServiceDiscovery::ServiceDiscovery() {}
void ServiceDiscovery::release_instance() {}
void ServiceDiscovery::release_thread_resources() {}
static AppIdModule* s_app_module = nullptr;
static AppIdInspector* s_ins = nullptr;
static ServiceDiscovery* s_discovery_manager = nullptr;
ServiceDiscovery& ServiceDiscovery::get_instance()
{
    if (!s_discovery_manager)
        s_discovery_manager = new ServiceDiscovery();
    return *s_discovery_manager;
}

HostCacheIp host_cache(50);
AppId HostTracker::get_appid(Port, IpProtocol, bool, bool)
{
    return APP_ID_NONE;
}

// Stubs for ClientDiscovery
ClientDiscovery::ClientDiscovery(){}
ClientDiscovery::~ClientDiscovery() {}
void ClientDiscovery::initialize() {}
void ClientDiscovery::finalize_client_plugins() {}
void ClientDiscovery::release_instance() {}
void ClientDiscovery::release_thread_resources() {}
static ClientDiscovery* c_discovery_manager = nullptr;
ClientDiscovery& ClientDiscovery::get_instance()
{
    if (!c_discovery_manager)
        c_discovery_manager = new ClientDiscovery();
    return *c_discovery_manager;
}
bool ClientDiscovery::do_client_discovery(AppIdSession&, Packet*,
    AppidSessionDirection, AppidChangeBits&)
{
    return false;
}

// Stubs for misc items
HostPortVal* HostPortCache::find(const SfIp*, uint16_t, IpProtocol)
{
    return nullptr;
}
void AppIdServiceState::check_reset(AppIdSession&, const SfIp*, uint16_t) {}
int dns_host_scan_hostname(const uint8_t*, size_t, AppId*, AppId*)
{
    return 0;
}
bool do_tp_discovery(AppIdSession&, IpProtocol,
    Packet*, AppidSessionDirection&, AppidChangeBits&)
{
    return true;
}
TPLibHandler* TPLibHandler::self = nullptr;
THREAD_LOCAL AppIdStats appid_stats;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
void AppIdDebug::activate(const Flow*, const AppIdSession*, bool) { active = false; }
AppId find_length_app_cache(const LengthKey&)
{
    return APP_ID_NONE;
}
void check_session_for_AF_indicator(Packet*, AppidSessionDirection, AppId) {}
AppId check_session_for_AF_forecast(AppIdSession&, Packet*, AppidSessionDirection, AppId)
{
    return APP_ID_UNKNOWN;
}

bool AppIdReloadTuner::tinit() { return false; }

bool AppIdReloadTuner::tune_resources(unsigned int)
{
    return true;
}

TEST_GROUP(appid_discovery_tests)
{
    void setup() override
    {
        appidDebug = new AppIdDebug();
        http_matchers = new HttpPatternMatchers;
        s_app_module = new AppIdModule;
        s_ins = new AppIdInspector(*s_app_module);
        AppIdPegCounts::init_pegs();
    }

    void teardown() override
    {
        delete appidDebug;
        delete http_matchers;
        if (s_discovery_manager)
        {
            delete s_discovery_manager;
            s_discovery_manager = nullptr;
        }
        if (c_discovery_manager)
        {
            delete c_discovery_manager;
            c_discovery_manager = nullptr;
        }
        delete s_ins;
        delete s_app_module;
        AppIdPegCounts::cleanup_pegs();
        AppIdPegCounts::cleanup_peg_info();
    }
};
TEST(appid_discovery_tests, event_published_when_ignoring_flow)
{
    // Testing event from do_pre_discovery() path
    databus_publish_called = false;
    test_log[0] = '\0';
    Packet p;
    p.packet_flags = 0;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;
    SfIp ip;
    p.ptrs.ip_api.set(ip, ip);
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, nullptr, 21, ins);
    Flow* flow = new Flow;
    flow->set_flow_data(asd);
    p.flow = flow;
    asd->config = &my_app_config;
    asd->common.initiator_port = 21;
    asd->common.initiator_ip.set("1.2.3.4");
    asd->set_session_flags(APPID_SESSION_IGNORE_FLOW);

    AppIdDiscovery::do_application_discovery(&p, ins);

    // Detect changes in service, client, payload, and misc appid
    CHECK_EQUAL(databus_publish_called, true);
    STRCMP_EQUAL(test_log, "Published change_bits == 0000000001111");
    delete asd;
    delete flow;
}

TEST(appid_discovery_tests, event_published_when_processing_flow)
{
    // Testing event from do_discovery() path
    databus_publish_called = false;
    test_log[0] = '\0';
    Packet p;
    p.packet_flags = 0;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;
    SfIp ip;
    p.ptrs.ip_api.set(ip, ip);
    p.ptrs.tcph = nullptr;
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, nullptr, 21, ins);
    Flow* flow = new Flow;
    flow->set_flow_data(asd);
    p.flow = flow;
    asd->config = &my_app_config;
    asd->common.initiator_port = 21;
    asd->common.initiator_ip.set("1.2.3.4");

    AppIdDiscovery::do_application_discovery(&p, ins);

    // Detect changes in service, client, payload, and misc appid
    CHECK_EQUAL(databus_publish_called, true);
    STRCMP_EQUAL(test_log, "Published change_bits == 0000000001111");
    delete asd;
    delete flow;
}

TEST(appid_discovery_tests, change_bits_for_client_version)
{
    // Testing set_version
    AppidChangeBits change_bits;
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, nullptr, 21, ins);
    const char* version = "3.0";
    asd->client.set_version(version, change_bits);

    // Detect changes in client version
    CHECK_EQUAL(change_bits.test(APPID_VERSION_BIT), true);
    delete asd;
}

TEST(appid_discovery_tests, change_bits_for_tls_host)
{
    // Testing set_tls_host
    AppidChangeBits change_bits;
    const char* host = "www.cisco.com";
    TlsSession tls;
    tls.set_tls_host(host, 0, change_bits);

    // Detect changes in tls_host
    CHECK_EQUAL(change_bits.test(APPID_TLSHOST_BIT), true);
}

TEST(appid_discovery_tests, change_bits_for_non_http_appid)
{
    // Testing FTP appid
    databus_publish_called = false;
    Packet p;
    p.packet_flags = 0;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;
    SfIp ip;
    p.ptrs.ip_api.set(ip, ip);
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, nullptr, 21, ins);
    Flow* flow = new Flow;
    flow->set_flow_data(asd);
    p.flow = flow;
    p.ptrs.tcph = nullptr;
    asd->config = &my_app_config;
    asd->common.initiator_port = 21;
    asd->common.initiator_ip.set("1.2.3.4");
    asd->misc_app_id = APP_ID_NONE;
    asd->payload.set_id(APP_ID_NONE);
    asd->client.set_id(APP_ID_CURL);
    asd->service.set_id(APP_ID_FTP);

    AppIdDiscovery::do_application_discovery(&p, ins);

    // Detect event for FTP service and CURL client
    CHECK_EQUAL(databus_publish_called, true);
    CHECK_EQUAL(asd->client.get_id(), APP_ID_CURL);
    CHECK_EQUAL(asd->service.get_id(), APP_ID_FTP);

    // Testing DNS appid
    databus_publish_called = false;
    asd->misc_app_id = APP_ID_NONE;
    asd->payload.set_id(APP_ID_NONE);
    asd->client.set_id(APP_ID_NONE);
    asd->service.set_id(APP_ID_DNS);
    AppIdDiscovery::do_application_discovery(&p, ins);

    // Detect event for DNS service
    CHECK_EQUAL(databus_publish_called, true);
    CHECK_EQUAL(asd->service.get_id(), APP_ID_DNS);

    delete asd;
    delete flow;
}

TEST(appid_discovery_tests, change_bits_to_string)
{
    // Testing that all bits from AppidChangeBit enum get translated
    AppidChangeBits change_bits;
    std::string str;

    // Detect empty
    change_bits_to_string(change_bits, str);
    STRCMP_EQUAL(str.c_str(), "");

    // Detect all; failure of this test means some bits from enum are missed in translation
    change_bits.set();
    change_bits_to_string(change_bits, str);
    STRCMP_EQUAL(str.c_str(), "service, client, payload, misc, referred, host,"
        " tls-host, url, user-agent, response, referrer, xff, client-version");

    // Failure of this test is a reminder that enum is changed, hence translator needs update
    CHECK_EQUAL(APPID_MAX_BIT, 13);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
