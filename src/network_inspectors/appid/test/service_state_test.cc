//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

namespace snort
{
// Stubs for logs
char test_log[256];
void LogMessage(const char* format,...)
{
    va_list args;
    va_start(args, format);
    vsprintf(test_log, format, args);
    va_end(args);
}
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
time_t packet_time() { return std::time(0); }
}

// Stubs for AppInfoManager
AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId)
{
    return nullptr;
}

// Stubs for appid classes
class AppIdInspector{};
FlowData::FlowData(unsigned, Inspector*) {}
FlowData::~FlowData() = default;

// Stubs for AppIdDebug
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
THREAD_LOCAL AppIdStats appid_stats;

void AppIdDebug::activate(const Flow*, const AppIdSession*, bool) { active = true; }

AppIdSession::AppIdSession(IpProtocol, const SfIp*, uint16_t, AppIdInspector& inspector)
    : FlowData(0), inspector(inspector) {}
AppIdSession::~AppIdSession() = default;
AppIdDiscovery::AppIdDiscovery(AppIdInspector& ins) : inspector(ins) {}
AppIdDiscovery::~AppIdDiscovery() {}
void AppIdDiscovery::register_detector(const std::string&, AppIdDetector*,  IpProtocol) {}
void AppIdDiscovery::add_pattern_data(AppIdDetector*, SearchTool*, int, const uint8_t* const,
    unsigned, unsigned) {}
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned) {}
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned) {}
int AppIdDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
void ServiceDiscovery::initialize() {}
void ServiceDiscovery::finalize_service_patterns() {}
void ServiceDiscovery::match_by_pattern(AppIdSession&, const Packet*, IpProtocol) {}
void ServiceDiscovery::get_port_based_services(IpProtocol, uint16_t, AppIdSession&) {}
void ServiceDiscovery::get_next_service(const Packet*, const AppidSessionDirection, AppIdSession&) {}
int ServiceDiscovery::identify_service(AppIdSession&, Packet*, AppidSessionDirection) { return 0; }
int ServiceDiscovery::add_ftp_service_state(AppIdSession&) { return 0; }
bool ServiceDiscovery::do_service_discovery(AppIdSession&, Packet*, AppidSessionDirection) { return 0; }
int ServiceDiscovery::incompatible_data(AppIdSession&, const Packet*,AppidSessionDirection,
    ServiceDetector*) { return 0; }
int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection,
    ServiceDetector*, ServiceDiscoveryState*) { return 0; }
int ServiceDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
ServiceDiscovery::ServiceDiscovery(AppIdInspector& ins)
    : AppIdDiscovery(ins) {}

ServiceDiscovery& ServiceDiscovery::get_instance(AppIdInspector* ins)
{
    static ServiceDiscovery discovery_manager(*ins);
    return discovery_manager;
}

TEST_GROUP(service_state_tests)
{
    void setup() override
    {
        appidDebug = new AppIdDebug();
        appidDebug->activate(nullptr, nullptr, 0);
    }

    void teardown() override
    {
        delete appidDebug;
    }
};

TEST(service_state_tests, select_detector_by_brute_force)
{
    ServiceDiscoveryState sds;
    AppIdInspector ins;
    ServiceDiscovery::get_instance(&ins);

    // Testing end of brute-force walk for supported and unsupported protocols
    test_log[0] = '\0';
    sds.select_detector_by_brute_force(IpProtocol::TCP);
    STRCMP_EQUAL(test_log, "AppIdDbg  Brute-force state failed - no more TCP detectors\n");

    test_log[0] = '\0';
    sds.select_detector_by_brute_force(IpProtocol::UDP);
    STRCMP_EQUAL(test_log, "AppIdDbg  Brute-force state failed - no more UDP detectors\n");

    test_log[0] = '\0';
    sds.select_detector_by_brute_force(IpProtocol::IP);
    STRCMP_EQUAL(test_log, "");
}

TEST(service_state_tests, set_service_id_failed)
{
    ServiceDiscoveryState sds;
    AppIdInspector inspector;
    AppIdSession asd(IpProtocol::PROTO_NOT_SET, nullptr, 0, inspector);
    SfIp client_ip;
    AppIdInspector ins;
    ServiceDiscovery::get_instance(&ins);

    // Testing 3+ failures to exceed STATE_ID_NEEDED_DUPE_DETRACT_COUNT with valid_count = 0
    client_ip.set("1.2.3.4");
    sds.set_state(SERVICE_ID_STATE::VALID);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    CHECK_TRUE(sds.get_state() == SERVICE_ID_STATE::SEARCHING_PORT_PATTERN);
}


TEST(service_state_tests, set_service_id_failed_with_valid)
{
    ServiceDiscoveryState sds;
    AppIdInspector inspector;
    AppIdSession asd(IpProtocol::PROTO_NOT_SET, nullptr, 0, inspector);
    SfIp client_ip;
    AppIdInspector ins;
    ServiceDiscovery::get_instance(&ins);

    // Testing 3+ failures to exceed STATE_ID_NEEDED_DUPE_DETRACT_COUNT with valid_count > 1
    client_ip.set("1.2.3.4");
    sds.set_state(SERVICE_ID_STATE::VALID);
    sds.set_service_id_valid(0);
    sds.set_service_id_valid(0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    sds.set_service_id_failed(asd, &client_ip, 0);
    CHECK_TRUE(sds.get_state() == SERVICE_ID_STATE::VALID);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
