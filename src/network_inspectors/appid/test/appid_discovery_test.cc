//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "helpers/discovery_filter.h"
#include "host_tracker/host_cache.h"
#include "network_inspectors/appid/appid_discovery.cc"
#include "network_inspectors/appid/appid_peg_counts.h"
#include "network_inspectors/packet_tracer/packet_tracer.h"
#include "pub_sub/appid_event_ids.h"
#include "search_engines/search_tool.h"
#include "utils/sflsq.cc"

#include "appid_api.h"
#include "appid_mock_session.h"
#include "appid_session_api.h"
#include "tp_lib_handler.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

uint32_t ThirdPartyAppIdContext::next_version = 0;

namespace snort
{
// Stubs for appid api
AppIdApi appid_api;
const char* AppIdApi::get_application_name(AppId, OdpContext&) { return NULL; }

// Stubs for packet tracer
THREAD_LOCAL PacketTracer* s_pkt_trace = nullptr;
THREAD_LOCAL Stopwatch<SnortClock>* pt_timer = nullptr;
void PacketTracer::daq_log(const char*, ...) { }

// Stubs for packet
Packet::Packet(bool) {}
Packet::~Packet() = default;
bool Packet::get_ip_proto_next(unsigned char&, IpProtocol&) const { return true; }

// Stubs for inspector
Inspector::Inspector()
{
    set_api(nullptr);
}
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

// Stubs for module
Module::Module(char const*, char const*) {}
void Module::sum_stats(bool) {}
void Module::show_interval_stats(std::vector<unsigned>&, FILE*) {}
void Module::show_stats() {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const { return 0; }

// Stubs for logs
void LogMessage(const char*,...) {}
void ErrorMessage(const char*,...) {}
void LogLabel(const char*, FILE*) {}
void LogText(const char*, FILE*) {}


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
SearchTool::SearchTool(bool) {}
SearchTool::~SearchTool() = default;
void SearchTool::add(const char*, unsigned, int, bool) {}
void SearchTool::add(const char*, unsigned, void*, bool) {}
void SearchTool::add(const uint8_t*, unsigned, int, bool) {}
void SearchTool::add(const uint8_t*, unsigned, void*, bool) {}

// Mocks for ip
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

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
void AppIdSessionApi::get_first_stream_app_ids(AppId&, AppId&, AppId&, AppId&) const { }

// Mocks for publish
unsigned DataBus::get_id(const PubKey&)
{ return 0; }

void DataBus::publish(unsigned, unsigned, DataEvent& event, Flow*)
{
    AppidEvent* appid_event = (AppidEvent*)&event;
    char* test_log = (char*)mock().getData("test_log").getObjectPointer();
    snprintf(test_log, 256, "Published change_bits == %s",
        appid_event->get_change_bitset().to_string().c_str());
    mock().actualCall("publish");
}
} // namespace snort
void AppIdModule::reset_stats() {}
DiscoveryFilter::~DiscoveryFilter() {}

// Stubs for matchers
static HttpPatternMatchers* http_matchers;
DnsPatternMatchers::~DnsPatternMatchers() = default;
EveCaPatternMatchers::~EveCaPatternMatchers() = default;
HttpPatternMatchers::~HttpPatternMatchers() = default;
SipPatternMatchers::~SipPatternMatchers() = default;
SslPatternMatchers::~SslPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
CipPatternMatchers::~CipPatternMatchers() = default;

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
void ApplicationDescriptor::set_id(AppId app_id){my_id = app_id;}
void ServiceAppDescriptor::set_id(AppId app_id, OdpContext& odp_ctxt)
{
    set_id(app_id);
    deferred = odp_ctxt.get_app_info_mgr().get_app_info_flags(app_id, APPINFO_FLAG_DEFER);
}
void ServiceAppDescriptor::set_port_service_id(AppId){}
void ClientAppDescriptor::update_user(AppId, const char*, AppidChangeBits&){}

// Stubs for AppIdModule
AppIdModule::AppIdModule(): Module("appid_mock", "appid_mock_help") {}
AppIdModule::~AppIdModule() = default;
void AppIdModule::sum_stats(bool) {}
void AppIdModule::show_dynamic_stats() {}
bool AppIdModule::begin(char const*, int, SnortConfig*) { return true; }
bool AppIdModule::end(char const*, int, SnortConfig*) { return true; }
bool AppIdModule::set(char const*, Value&, SnortConfig*) { return true; }
const Command* AppIdModule::get_commands() const { return nullptr; }
const PegInfo* AppIdModule::get_pegs() const { return nullptr; }
PegCount* AppIdModule::get_counts() const { return nullptr; }
ProfileStats* AppIdModule::get_profile() const { return nullptr; }
void AppIdModule::set_trace(const Trace*) const { }
const TraceOption* AppIdModule::get_trace_options() const { return nullptr; }
THREAD_LOCAL bool ThirdPartyAppIdContext::tp_reload_in_progress = false;

// Stubs for config
static AppIdConfig app_config;
static AppIdContext app_ctxt(app_config);
AppId OdpContext::get_port_service_id(IpProtocol, uint16_t)
{
    return APP_ID_NONE;
}

AppId OdpContext::get_protocol_service_id(IpProtocol)
{
    return APP_ID_NONE;
}

// Stubs for AppIdInspector
AppIdInspector::AppIdInspector(AppIdModule&) { ctxt = &stub_ctxt; }
AppIdInspector::~AppIdInspector() = default;
void AppIdInspector::eval(Packet*) { }
bool AppIdInspector::configure(SnortConfig*) { return true; }
void AppIdInspector::show(const SnortConfig*) const { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }
void AppIdInspector::tear_down(SnortConfig*) { }
AppIdContext& AppIdInspector::get_ctxt() const
{
    assert(ctxt);
    return *ctxt;
}
bool DiscoveryFilter::is_app_monitored(const snort::Packet*, uint8_t*){return true;}

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
void AppIdSession::check_app_detection_restart(AppidChangeBits&, ThirdPartyAppIdContext*) {}
void AppIdSession::set_client_appid_data(AppId, AppidChangeBits&, char*) {}
void AppIdSession::examine_rtmp_metadata(AppidChangeBits&) {}
void AppIdSession::examine_ssl_metadata(AppidChangeBits&) {}
void AppIdSession::update_encrypted_app_id(AppId) {}
bool AppIdSession::is_tp_processing_done() const {return false;}
AppId AppIdSession::pick_ss_payload_app_id(AppId) const { return get_payload_id(); }
bool AppIdSession::need_to_delete_tp_conn(ThirdPartyAppIdContext*) const { return true; }
AppIdSession* AppIdSession::allocate_session(const Packet*, IpProtocol,
    AppidSessionDirection, AppIdInspector&, OdpContext&)
{
    return nullptr;
}

void AppIdSession::publish_appid_event(AppidChangeBits& change_bits, const Packet& p, bool, uint32_t)
{
    AppidEvent app_event(change_bits, false, 0, this->get_api(), p);
    DataBus::publish(0, AppIdEventIds::ANY_CHANGE, app_event, p.flow);
}

void AppIdHttpSession::set_tun_dest(){}

// Stubs for ServiceDiscovery
void ServiceDiscovery::initialize(AppIdInspector&) {}
void ServiceDiscovery::reload() {}
void ServiceDiscovery::finalize_service_patterns() {}
void ServiceDiscovery::match_by_pattern(AppIdSession&, const Packet*, IpProtocol) {}
void ServiceDiscovery::get_port_based_services(IpProtocol, uint16_t, AppIdSession&) {}
void ServiceDiscovery::get_next_service(const Packet*, const AppidSessionDirection, AppIdSession&) {}
int ServiceDiscovery::identify_service(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return 0; }
int ServiceDiscovery::add_ftp_service_state(AppIdSession&) { return 0; }
bool ServiceDiscovery::do_service_discovery(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return false; }
int ServiceDiscovery::incompatible_data(AppIdSession&, const Packet*,AppidSessionDirection,
    ServiceDetector*) { return 0; }
int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection,
    ServiceDetector*, ServiceDiscoveryState*) { return 0; }
int ServiceDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
static AppIdModule* s_app_module = nullptr;
static AppIdInspector* s_ins = nullptr;
static ServiceDiscovery* s_discovery_manager = nullptr;

HostCacheIp host_cache(50);
AppId HostTracker::get_appid(Port, IpProtocol, bool, bool)
{
    return APP_ID_NONE;
}

void HostTracker::remove_flows() {}

// Stubs for ClientDiscovery
void ClientDiscovery::initialize(AppIdInspector&) {}
void ClientDiscovery::reload() {}
void ClientDiscovery::finalize_client_patterns() {}
static ClientDiscovery* c_discovery_manager = new ClientDiscovery();
bool ClientDiscovery::do_client_discovery(AppIdSession&, Packet*,
    AppidSessionDirection, AppidChangeBits&)
{
    return false;
}

// Stubs for misc items
HostPortVal* HostPortCache::find(const SfIp*, uint16_t, IpProtocol, const OdpContext&)
{
    return nullptr;
}

HostAppIdsVal* HostPortCache::find_on_first_pkt(const SfIp*, uint16_t, IpProtocol, const OdpContext&)
{
    return nullptr;
}

void AppIdServiceState::check_reset(AppIdSession&, const SfIp*, uint16_t,
    int16_t, uint32_t) {}
bool do_tp_discovery(ThirdPartyAppIdContext& , AppIdSession&, IpProtocol,
    Packet*, AppidSessionDirection&, AppidChangeBits&)
{
    return true;
}
TPLibHandler* TPLibHandler::self = nullptr;
THREAD_LOCAL AppIdStats appid_stats;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
void AppIdDebug::activate(const Flow*, const AppIdSession*, bool) { active = false; }

bool AppIdReloadTuner::tinit() { return false; }

bool AppIdReloadTuner::tune_resources(unsigned int)
{
    return true;
}

void AppIdSession::set_ss_application_ids(AppId service_id, AppId client_id, AppId payload_id,
    AppId misc_id, AppId referred_id, AppidChangeBits& change_bits)
{
    if (api.application_ids[APP_PROTOID_SERVICE] != service_id)
    {
        api.application_ids[APP_PROTOID_SERVICE] = service_id;
        change_bits.set(APPID_SERVICE_BIT);
    }
    if (api.application_ids[APP_PROTOID_CLIENT] != client_id)
    {
        api.application_ids[APP_PROTOID_CLIENT] = client_id;
        change_bits.set(APPID_CLIENT_BIT);
    }
    if (api.application_ids[APP_PROTOID_PAYLOAD] != payload_id)
    {
        api.application_ids[APP_PROTOID_PAYLOAD] = payload_id;
        change_bits.set(APPID_PAYLOAD_BIT);
    }
    if (api.application_ids[APP_PROTOID_MISC] != misc_id)
    {
        api.application_ids[APP_PROTOID_MISC] = misc_id;
        change_bits.set(APPID_MISC_BIT);
    }
    if (api.application_ids[APP_PROTOID_REFERRED] != referred_id)
    {
        api.application_ids[APP_PROTOID_REFERRED] = referred_id;
        change_bits.set(APPID_REFERRED_BIT);
    }
}

AppIdHttpSession* AppIdSession::get_http_session(uint32_t) const { return nullptr; }

TEST_GROUP(appid_discovery_tests)
{
    char test_log[256];
    void setup() override
    {
        appidDebug = new AppIdDebug();
        http_matchers = new HttpPatternMatchers;
        s_app_module = new AppIdModule;
        s_ins = new AppIdInspector(*s_app_module);
        AppIdPegCounts::init_pegs();
        mock().setDataObject("test_log", "char", test_log);
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
        mock().clear();
    }
};

TEST(appid_discovery_tests, event_published_when_ignoring_flow)
{
    // Testing event from do_pre_discovery() path
    mock().expectOneCall("publish");
    test_log[0] = '\0';
    Packet p;
    p.packet_flags = 0;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;
    SfIp ip;
    ip.set("1.2.3.4");
    p.ptrs.ip_api.set(ip, ip);
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, &ip, 21, ins, app_ctxt.get_odp_ctxt());
    asd->flags |= APPID_SESSION_SPECIAL_MONITORED | APPID_SESSION_DISCOVER_USER |
        APPID_SESSION_DISCOVER_APP;
    Flow* flow = new Flow;
    flow->set_flow_data(asd);
    p.flow = flow;
    asd->initiator_port = 21;
    asd->set_session_flags(APPID_SESSION_FUTURE_FLOW);

    AppIdDiscovery::do_application_discovery(&p, ins, app_ctxt.get_odp_ctxt(), nullptr);

    // Detect changes in service, client, payload, and misc appid
    mock().checkExpectations();
    STRCMP_EQUAL("Published change_bits == 00000000000001111100", test_log);

    delete &asd->get_api();
    delete asd;
    delete flow;
}

TEST(appid_discovery_tests, event_published_when_processing_flow)
{
    // Testing event from do_discovery() path
    mock().expectOneCall("publish");
    test_log[0] = '\0';
    Packet p;
    p.packet_flags = 0;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;
    SfIp ip;
    ip.set("1.2.3.4");
    p.ptrs.ip_api.set(ip, ip);
    p.ptrs.tcph = nullptr;
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, &ip, 21, ins, app_ctxt.get_odp_ctxt());
    asd->flags |= APPID_SESSION_SPECIAL_MONITORED | APPID_SESSION_DISCOVER_USER |
        APPID_SESSION_DISCOVER_APP;
    Flow* flow = new Flow;
    flow->set_flow_data(asd);
    p.flow = flow;
    asd->initiator_port = 21;

    AppIdDiscovery::do_application_discovery(&p, ins, app_ctxt.get_odp_ctxt(), nullptr);

    // Detect changes in service, client, payload, and misc appid
    mock().checkExpectations();
    STRCMP_EQUAL("Published change_bits == 00000000000001111100", test_log);
    delete &asd->get_api();
    delete asd;
    delete flow;
}

TEST(appid_discovery_tests, change_bits_for_client_version)
{
    // Testing set_version
    AppidChangeBits change_bits;
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    SfIp ip;
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, &ip, 21, ins, app_ctxt.get_odp_ctxt());
    const char* version = "3.0";
    asd->set_client_version(version, change_bits);

    // Detect changes in client version
    CHECK_EQUAL(change_bits.test(APPID_CLIENT_INFO_BIT), true);
    delete &asd->get_api();
    delete asd;
}

TEST(appid_discovery_tests, change_bits_for_tls_host)
{
    // Testing set_tls_host
    AppidChangeBits change_bits;
    char* host = snort_strdup(APPID_UT_TLS_HOST);
    TlsSession tls;
    tls.set_tls_host(host, 0, change_bits);

    // Detect changes in tls_host
    CHECK_EQUAL(change_bits.test(APPID_TLSHOST_BIT), true);
}

TEST(appid_discovery_tests, change_bits_for_non_http_appid)
{
    // Testing FTP appid
    mock().expectNCalls(2, "publish");
    Packet p;
    p.packet_flags = 0;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;
    SfIp ip;
    ip.set("1.2.3.4");
    p.ptrs.ip_api.set(ip, ip);
    AppIdModule app_module;
    AppIdInspector ins(app_module);
    AppIdSession* asd = new AppIdSession(IpProtocol::TCP, &ip, 21, ins, app_ctxt.get_odp_ctxt());
    asd->flags |= APPID_SESSION_SPECIAL_MONITORED | APPID_SESSION_DISCOVER_USER |
        APPID_SESSION_DISCOVER_APP;
    Flow* flow = new Flow;
    flow->set_flow_data(asd);
    p.flow = flow;
    p.ptrs.tcph = nullptr;
    asd->initiator_port = 21;
    asd->misc_app_id = APP_ID_NONE;
    asd->set_payload_id(APP_ID_NONE);
    asd->set_client_id(APP_ID_CURL);
    asd->set_service_id(APP_ID_FTP, app_ctxt.get_odp_ctxt());

    AppIdDiscovery::do_application_discovery(&p, ins, app_ctxt.get_odp_ctxt(), nullptr);

    // Detect event for FTP service and CURL client
    CHECK_EQUAL(asd->get_client_id(), APP_ID_CURL);
    CHECK_EQUAL(asd->get_service_id(), APP_ID_FTP);

    // Testing DNS appid
    asd->misc_app_id = APP_ID_NONE;
    asd->set_payload_id(APP_ID_NONE);
    asd->set_client_id(APP_ID_NONE);
    asd->set_service_id(APP_ID_DNS, app_ctxt.get_odp_ctxt());
    AppIdDiscovery::do_application_discovery(&p, ins, app_ctxt.get_odp_ctxt(), nullptr);

    // Detect event for DNS service
    mock().checkExpectations();
    CHECK_EQUAL(asd->get_service_id(), APP_ID_DNS);

    delete &asd->get_api();
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
    STRCMP_EQUAL(str.c_str(), "created, reset, service, client, payload, misc, referred, host,"
        " tls-host, url, user-agent, response, referrer, dns-host, service-info, client-info,"
        " user-info, netbios-name, netbios-domain, finished");

    // Failure of this test is a reminder that enum is changed, hence translator needs update
    CHECK_EQUAL(APPID_MAX_BIT, 20);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
