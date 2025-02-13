//--------------------------------------------------------------------------
// Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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
// service_state.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/service_state.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include <vector>

THREAD_LOCAL bool TimeProfilerStats::enabled = false;

namespace snort
{
Packet::Packet(bool)
{
    memset((char*) this , 0, sizeof(*this));
    ip_proto_next = IpProtocol::PROTO_NOT_SET;
    packet_flags = PKT_FROM_CLIENT;
}
Packet::~Packet() = default;
Packet* DetectionEngine::get_current_packet() { return nullptr; }

// Stubs for logs
char test_log[256];
void LogMessage(const char* format, va_list& args)
{
    vsprintf(test_log, format, args);
}
void LogMessage(const char* format,...)
{
    va_list args;
    va_start(args, format);
    LogMessage(format, args);
    va_end(args);
}
void WarningMessage(const char*,...)
{ }

void LogLabel(const char*, FILE*) {}
void LogText(const char* s, FILE*) { LogMessage("%s\n", s); }

unsigned DataBus::get_id(const PubKey&)
{ return 0; }

// Stubs for utils
char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
time_t packet_time() { return std::time(nullptr); }

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
}

DiscoveryFilter::~DiscoveryFilter(){}
// Stubs for AppInfoManager
AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId)
{
    return nullptr;
}

// Stubs for appid classes
class AppIdInspector{};
FlowData::FlowData(unsigned, Inspector*) : next(nullptr), prev(nullptr), handler(nullptr), id(0)
{ }
FlowData::~FlowData() = default;

// Stubs for AppIdDebug
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
THREAD_LOCAL AppIdStats appid_stats;

void AppIdDebug::activate(const Flow*, const AppIdSession*, bool) { active = true; }

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
void ApplicationDescriptor::set_id(AppId){}
void ServiceAppDescriptor::set_id(AppId, OdpContext&){}
void ServiceAppDescriptor::set_port_service_id(AppId){}
void ClientAppDescriptor::update_user(AppId, const char*, AppidChangeBits&){}
AppIdConfig::~AppIdConfig() = default;
OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*) { }
AppIdConfig stub_config;
AppIdContext stub_ctxt(stub_config);
OdpContext stub_odp_ctxt(stub_config, nullptr);
AppIdSession::AppIdSession(IpProtocol, const SfIp* ip, uint16_t, AppIdInspector&,
    OdpContext&, uint32_t
#ifndef DISABLE_TENANT_ID
    ,uint32_t
#endif
    ) : FlowData(0), config(stub_config),
    api(*(new AppIdSessionApi(this, *ip))), odp_ctxt(stub_odp_ctxt) { }
AppIdSession::~AppIdSession() = default;
AppIdDiscovery::~AppIdDiscovery() = default;
void ClientDiscovery::initialize(AppIdInspector&) { }
void ClientDiscovery::reload() { }
void AppIdDiscovery::register_detector(const std::string&, AppIdDetector*,  IpProtocol) {}
void AppIdDiscovery::add_pattern_data(AppIdDetector*, SearchTool&, int, const uint8_t* const,
    unsigned, unsigned) {}
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned) {}
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned) {}
int AppIdDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
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
DnsPatternMatchers::~DnsPatternMatchers() = default;
EveCaPatternMatchers::~EveCaPatternMatchers() = default;
HttpPatternMatchers::~HttpPatternMatchers() = default;
SipPatternMatchers::~SipPatternMatchers() = default;
SslPatternMatchers::~SslPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
CipPatternMatchers::~CipPatternMatchers() = default;
UserDataMap::~UserDataMap() = default;
snort::SearchTool::SearchTool(bool, const char*) { }
snort::SearchTool::~SearchTool() = default;
void appid_log(const snort::Packet*, unsigned char, char const* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LogMessage(fmt, args);
    va_end(args);
}

TEST_GROUP(service_state_tests)
{
    void setup() override
    {
        appidDebug = new AppIdDebug();
        appidDebug->activate(nullptr, nullptr, false);
        AppIdServiceState::set_service_thresholds(0, 1);
    }

    void teardown() override
    {
        delete appidDebug;
        AppIdServiceState::clean();
    }
};

TEST(service_state_tests, select_detector_by_brute_force)
{
    ServiceDiscovery sd;
    ServiceDiscoveryState sds;
    // Testing end of brute-force walk for supported and unsupported protocols
    test_log[0] = '\0';
    sds.select_detector_by_brute_force(IpProtocol::TCP, sd);
    STRCMP_EQUAL(test_log, "Brute-force state failed - no more TCP detectors\n");

    test_log[0] = '\0';
    sds.select_detector_by_brute_force(IpProtocol::UDP, sd);
    STRCMP_EQUAL(test_log, "Brute-force state failed - no more UDP detectors\n");

    test_log[0] = '\0';
    sds.select_detector_by_brute_force(IpProtocol::IP, sd);
    STRCMP_EQUAL(test_log, "");
}

TEST(service_state_tests, set_service_id_failed)
{
    ServiceDiscoveryState sds;
    AppIdInspector inspector;
    SfIp client_ip;
    client_ip.set("1.2.3.4");
    AppIdSession asd(IpProtocol::PROTO_NOT_SET, &client_ip, 0, inspector, stub_odp_ctxt, 0
#ifndef DISABLE_TENANT_ID
    ,0
#endif
    );

    // Testing 3+ failures to exceed STATE_ID_NEEDED_DUPE_DETRACT_COUNT with valid_count = 0
    sds.set_state(ServiceState::VALID);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    CHECK_TRUE(sds.get_state() == ServiceState::SEARCHING_PORT_PATTERN);

    delete &asd.get_api();
}


TEST(service_state_tests, set_service_id_failed_with_valid)
{
    ServiceDiscoveryState sds;
    AppIdInspector inspector;
    SfIp client_ip;
    client_ip.set("1.2.3.4");
    AppIdSession asd(IpProtocol::PROTO_NOT_SET, &client_ip, 0, inspector, stub_odp_ctxt, 0
#ifndef DISABLE_TENANT_ID
    ,0
#endif
    );

    // Testing 3+ failures to exceed STATE_ID_NEEDED_DUPE_DETRACT_COUNT with valid_count > 1
    sds.set_state(ServiceState::VALID);
    sds.set_service_id_valid(nullptr);
    sds.set_service_id_valid(nullptr);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    CHECK_TRUE(sds.get_state() == ServiceState::VALID);

    delete &asd.get_api();
}

TEST(service_state_tests, appid_service_state_key_comparison_test)
{
    SfIp ip4, ip6;
    ip4.set("1.2.3.4");
    ip6.set("1111:2222:3333:4444:5555:6666:7777:8888");
    IpProtocol proto = IpProtocol::TCP;
    uint16_t port=3000;

    AppIdServiceStateKey A(&ip4, proto, port, 0, DAQ_PKTHDR_UNKNOWN, false);
    AppIdServiceStateKey B(&ip6, proto, port, 0, DAQ_PKTHDR_UNKNOWN, false);

    // We must never be in a situation where !( A<B ) and !( B<A ),
    // because then map will consider A=B.
    CHECK_TRUE(A<B || B<A);
}

TEST(service_state_tests, service_cache)
{
    size_t num_entries = 10, max_entries = 3;
    size_t memcap = max_entries*MapList::sz;
    MapList ServiceCache(memcap);

    IpProtocol proto = IpProtocol::TCP;
    uint16_t port = 3000;
    SfIp ip4, ip6;
    ip4.set("1.2.3.4");
    ip6.set("1111:2222:3333:4444:5555:6666:7777:8888");

    ServiceDiscoveryState* ss = nullptr;
    std::vector<ServiceDiscoveryState*> ssvec;


    // Insert (ipv4 and ipv6) past the memcap, and check the memcap is not exceeded.
    for( size_t i = 1; i <= num_entries; i++, port++ )
    {
        const SfIp* ip = ( i%2 == 1 ? &ip4 : &ip6 );
        ss = ServiceCache.add( AppIdServiceStateKey(ip, proto, port, 0, DAQ_PKTHDR_UNKNOWN, false) );
        CHECK_TRUE(ServiceCache.size() == ( i <= max_entries ? i : max_entries));
        ssvec.push_back(ss);
    }

    // The cache should now be  ip6:3007, ip4:3008, ip6:3009.
    // Check that the order in the cache is correct.
    Queue_t::iterator it = ServiceCache.newest();
    std::vector<ServiceDiscoveryState*>::iterator vit = --ssvec.end();
    for( size_t i=0; i<max_entries; i++, --it, --vit )
    {
        Map_t::iterator mit = *it;
        CHECK_TRUE( mit->second == *vit );
    }

    // Now get e.g. the oldest from the cache and check that it got touched:
    it = ServiceCache.oldest();
    ss = ServiceCache.get( (*it)->first, true );
    CHECK_TRUE( ss != nullptr );
    CHECK_TRUE( ss->qptr == ServiceCache.newest() );
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
