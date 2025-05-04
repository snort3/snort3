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

// tp_lib_handler_test.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <string>

#define TP_SUPPORTED 1

#include "tp_lib_handler.h"

#include "profiler/profiler.h"

#include "appid_config.h"
#include "log_message_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace std;
using namespace snort;

static TPLibHandler* tph = nullptr;
static AppIdConfig config;
static AppIdContext ctxt(config);
static OdpContext stub_odp_ctxt(config, nullptr);
OdpContext* AppIdContext::odp_ctxt = &stub_odp_ctxt;
ThirdPartyAppIdContext* AppIdContext::tp_appid_ctxt = nullptr;

snort::SearchTool::SearchTool(bool multi, const char*) : mpsegrp(nullptr), max_len(0), multi_match(multi)
{ }
snort::SearchTool::~SearchTool() = default;

AppIdDiscovery::~AppIdDiscovery() = default;
DiscoveryFilter::~DiscoveryFilter(){}
void ClientDiscovery::initialize(AppIdInspector&) { }
void ClientDiscovery::reload() { }
void AppIdDiscovery::register_detector(const string&, AppIdDetector*, IpProtocol) { }
void AppIdDiscovery::add_pattern_data(AppIdDetector*, snort::SearchTool&, int, unsigned char const*, unsigned int, unsigned int) { }
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, unsigned char const*, unsigned int, int, unsigned int) { }
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, unsigned char const*, unsigned int, int, unsigned int) { }
int AppIdDiscovery::add_service_port(AppIdDetector*, ServiceDetectorPort const&) { return 0; }
DnsPatternMatchers::~DnsPatternMatchers() = default;
EveCaPatternMatchers::~EveCaPatternMatchers() = default;
HttpPatternMatchers::~HttpPatternMatchers() = default;
SipPatternMatchers::~SipPatternMatchers() = default;
SslPatternMatchers::~SslPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
CipPatternMatchers::~CipPatternMatchers() = default;
UserDataMap::~UserDataMap() = default;
AppIdConfig::~AppIdConfig() = default;
OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*) { }
void ServiceDiscovery::initialize(AppIdInspector&) { }
void ServiceDiscovery::reload() { }
int ServiceDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&)
{ return 0; }
void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

THREAD_LOCAL ProfileStats tp_appid_perf_stats;
THREAD_LOCAL bool TimeProfilerStats::enabled = false;

TEST_GROUP(tp_lib_handler)
{
};

TEST(tp_lib_handler, load_unload)
{
    config.tp_appid_path="./libtp_mock.so";
    config.tp_appid_config="./tp.config";

    tph = TPLibHandler::get();
    ThirdPartyAppIdContext* tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(config, ctxt.get_odp_ctxt());
    CHECK_TRUE(tp_appid_ctxt != nullptr);

    TPLibHandler::tp_mp_init(*tp_appid_ctxt);

    TpAppIdCreateSession asf = tph->tpsession_factory();
    ThirdPartyAppIdSession* tpsession = asf(*tp_appid_ctxt);

    CHECK_TRUE(tpsession != nullptr);

    delete tpsession;
    delete tp_appid_ctxt;

    TPLibHandler::pfini();
}

TEST(tp_lib_handler, tp_lib_handler_get)
{
    tph = TPLibHandler::get();
    TPLibHandler* tph2 = TPLibHandler::get();
    CHECK_EQUAL(tph, tph2);
    TPLibHandler::pfini();
}

TEST(tp_lib_handler, tp_mp_init)
{
    config.tp_appid_path="./libtp_mock.so";
    config.tp_appid_config="./tp.config";

    tph = TPLibHandler::get();
    ThirdPartyAppIdContext* tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(config, ctxt.get_odp_ctxt());

    TPLibHandler::tp_mp_init(*tp_appid_ctxt);
    CHECK_TRUE(tp_appid_ctxt != nullptr);

    delete tp_appid_ctxt;
    TPLibHandler::pfini();
}

TEST(tp_lib_handler, load_error)
{
    // Trigger load error:
    config.tp_appid_path="nonexistent.so";
    TPLibHandler::get();
    ThirdPartyAppIdContext* tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(config, ctxt.get_odp_ctxt());
    CHECK_TRUE(tp_appid_ctxt == nullptr);
    TPLibHandler::pfini();
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);

    return rc;
}
