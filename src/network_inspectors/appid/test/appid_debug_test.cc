//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

// appid_debug_test.cc author Mike Stepanek <mstepane@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_debug.cc"

#include <cstdio>
#include <cstring>

#include "flow/flow.h"
#include "network_inspectors/appid/appid_session.h"

#include "appid_mock_definitions.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
THREAD_LOCAL bool TimeProfilerStats::enabled = false;

// Mocks

namespace snort
{
unsigned get_instance_id() { return 3; }

Packet::Packet(bool) {}
Packet::~Packet() = default;
FlowData::FlowData(unsigned, Inspector*) { }
FlowData::~FlowData() = default;
AppIdSessionApi::AppIdSessionApi(const AppIdSession* asd, const SfIp& ip) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID), asd(asd), initiator_ip(ip) {}
[[noreturn]] void FatalError(const char*,...) {  exit(-1); }
void ErrorMessage(const char*, va_list&) { }
void WarningMessage(const char*, va_list&) { }
void LogMessage(const char*, va_list&) { }
void TraceApi::filter(snort::Packet const&) { }
void trace_vprintf(const char*, unsigned char, const char*, const Packet*, const char*, va_list) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
std::string int_vector_to_str(const std::vector<uint32_t>&, char) { return ""; }
}


THREAD_LOCAL const snort::Trace* appid_trace;

void ApplicationDescriptor::set_id(const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
class AppIdInspector
{
public:
    AppIdInspector() = default;
};

AppIdConfig::~AppIdConfig() = default;
OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*) { }
AppidCPUProfilingManager::AppidCPUProfilingManager() {}

AppIdConfig stub_config;
AppIdContext stub_ctxt(stub_config);
OdpContext stub_odp_ctxt(stub_config, nullptr);
AppIdSession::AppIdSession(IpProtocol, const SfIp* ip, uint16_t, AppIdInspector&,
    OdpContext&, uint32_t, uint32_t) : FlowData(0), config(stub_config),
    api(*(new AppIdSessionApi(this, *ip))), odp_ctxt(stub_odp_ctxt) { }
AppIdSession::~AppIdSession() = default;

// Utility functions

static void SetConstraints(IpProtocol protocol,    // use IpProtocol::PROTO_NOT_SET for "any"
                const char* sipstr, uint16_t sport, const char* dipstr, uint16_t dport,
                AppIdDebugSessionConstraints& constraints)
{
    if (sipstr)
    {
        constraints.sip.set(sipstr);
        if (constraints.sip.is_set())
            constraints.sip_flag = true;
    }
    if (dipstr)
    {
        constraints.dip.set(dipstr);
        if (constraints.dip.is_set())
            constraints.dip_flag = true;
    }

    constraints.protocol = protocol;
    constraints.sport = sport;
    constraints.dport = dport;
}

// Tests

TEST_GROUP(appid_debug)
{
    void setup() override
    {
        appidDebug = new AppIdDebug();
    }

    void teardown() override
    {
        delete appidDebug;
    }
};

// This matches the basic pcap/expect regression test that we have for this command.
TEST(appid_debug, basic_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 0, "10.9.8.7", 80, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Test matching a packet in reverse direction (from constraints).
TEST(appid_debug, reverse_direction_activate_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 0, "10.9.8.7", 80, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    SfIp dip;
    dip.set("10.1.2.3");
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &dip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    sip.set("10.9.8.7");    // this would be a reply back
    uint16_t sport = 80;
    uint16_t dport = 48620;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = dport;    // session initiator is now dst
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Test IPv6 matches.
TEST(appid_debug, ipv6_test)
{
    // set_constraints()
    SfIp::test_features = true;
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::UDP, "2001:db8:85a3::8a2e:370:7334", 1234,
        "2001:db8:85a3::8a2e:370:7335", 443, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("2001:db8:85a3::8a2e:370:7334");    // IPv6
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("2001:db8:85a3::8a2e:370:7335");
    uint16_t sport = 1234;
    uint16_t dport = 443;
    IpProtocol protocol = IpProtocol::UDP;    // also threw in UDP and address space ID for kicks
    uint32_t address_space_id = 100;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 6, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "2001:0db8:85a3:0000:0000:8a2e:0370:7334 1234 -> "
            "2001:0db8:85a3:0000:0000:8a2e:0370:7335 443 17 AS=100 ID=3";

    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Test matching on session initiator IP (rather than port).
TEST(appid_debug, no_initiator_port_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 0, "10.9.8.7", 80, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = 0;    // no initiator port yet (uses IPs)
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Test matching on session initiator IP (reverse direction packet).
TEST(appid_debug, no_initiator_port_reversed_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 0, "10.9.8.7", 80, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    SfIp dip;
    dip.set("10.1.2.3");
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &dip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    sip.set("10.9.8.7");
    uint16_t sport = 80;
    uint16_t dport = 48620;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = 0;    // no initiator port yet (uses IPs)... and reversed packet dir from above
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Check for null session pointer (won't activate).
TEST(appid_debug, null_session_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 0, "10.9.8.7", 80, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    SfIp dip;
    uint16_t sport = 0;
    uint16_t dport = 0;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    uint32_t address_space_id = 0;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, nullptr, false, 0);    // null session
    CHECK_EQUAL(appidDebug->is_active(), false);    // not active
}

// Check for null flow pointer (won't activate).
TEST(appid_debug, null_flow_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 0, "10.9.8.7", 80, constraints);
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    // activate()
    appidDebug->activate(nullptr, nullptr, false);    // null flow (and session)
    CHECK_EQUAL(appidDebug->is_active(), false);    // not active
}

// Check a packet that doesn't get a match to constraints (won't activate).
TEST(appid_debug, no_match_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, nullptr, 0, nullptr, 0, constraints);    // just TCP
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::UDP;    // but this packet is UDP instead
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), false);    // not active (no match)

    delete &session.get_api();
}

// Set all constraints (must match all).
TEST(appid_debug, all_constraints_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, "10.1.2.3", 48620, "10.9.8.7", 80, constraints);    // must match all constraints
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Only set protocol in constraints.
TEST(appid_debug, just_proto_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::TCP, nullptr, 0, nullptr, 0, constraints);    // only need to match proto
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Only set IP in constraints.
TEST(appid_debug, just_ip_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::PROTO_NOT_SET, nullptr, 0, "10.9.8.7", 0, constraints);    // only need to match (dst) IP
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

// Only set port in constraints.
TEST(appid_debug, just_port_test)
{
    // set_constraints()
    AppIdDebugSessionConstraints constraints = { };
    SetConstraints(IpProtocol::PROTO_NOT_SET, nullptr, 0, nullptr, 80, constraints);    // just need to match (dst) port
    appidDebug->set_constraints("appid", &constraints);
    CHECK_EQUAL(appidDebug->is_enabled(), true);

    SfIp sip;
    sip.set("10.1.2.3");
    SfIp dip;
    AppIdInspector inspector;
    AppIdSession session(IpProtocol::PROTO_NOT_SET, &sip, 0, inspector, stub_odp_ctxt, 0, 0);
    // This packet...
    dip.set("10.9.8.7");
    uint16_t sport = 48620;
    uint16_t dport = 80;
    IpProtocol protocol = IpProtocol::TCP;
    uint32_t address_space_id = 0;
    // The session...
    session.initiator_port = sport;
    // activate()
    appidDebug->activate(sip.get_ip6_ptr(), dip.get_ip6_ptr(), sport, dport,
        protocol, 4, address_space_id, &session, false, 0);
    CHECK_EQUAL(appidDebug->is_active(), true);

    // get_debug_session()
    const char* str = "10.1.2.3 48620 -> 10.9.8.7 80 6 AS=0 ID=3";
    CHECK_TRUE(strcmp(appidDebug->get_debug_session(), str) == 0);

    delete &session.get_api();
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}
