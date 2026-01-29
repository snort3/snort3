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

// socks_negative_test.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../socks_flow_data.h"
#include "../socks_module.h"
#include "../socks.h"

#include "detection/detection_engine.h"
#include "packet_io/packet_tracer.h"
#include "packet_io/active.h"
#include "framework/data_bus.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "main/analyzer.h"
#include "main/thread_config.h"
#include "main/snort_config.h"
#include "log/unified2.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

// Test helper class - exposes protected methods for testing
class SocksInspectorTestHelper : public SocksInspector
{
public:
    SocksInspectorTestHelper(const SocksModule* mod) : SocksInspector(mod) {}
    
    // Expose protected methods as public for testing
    using SocksInspector::parse_socks4_request;
    using SocksInspector::parse_socks4_response;
    using SocksInspector::parse_socks5_auth_response;
    using SocksInspector::validate_socks5_request_header;
    using SocksInspector::process_client_data;
    using SocksInspector::process_server_data;
    using SocksInspector::process_reverse_client_data;
    using SocksInspector::process_reverse_server_data;
    using SocksInspector::detect_protocol_initiator;
};

// Mock implementations
namespace snort
{
    unsigned FlowData::flow_data_id = 0;
    
    FlowData::FlowData(unsigned u, Inspector* i) : handler(i), id(u) {}
    FlowData::~FlowData() = default;
    
    char* snort_strdup(const char* s)
    {
        if (!s)
            return nullptr;
        size_t len = strlen(s) + 1;
        char* dup = new char[len];
        memcpy(dup, s, len);
        return dup;
    }
    
    // Mock Snort framework functions
    Inspector::Inspector() = default;
    Inspector::~Inspector() = default;
    void Inspector::rem_ref() {}
    bool Inspector::likes(Packet*) { return true; }
    bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
    
    // cppcheck-suppress uninitMemberVar ; mock class - only data/dsize used in tests
    Packet::Packet(bool) {}
    Packet::~Packet() = default;
    
    void Flow::set_service(Packet*, const char*) {}
    
    // Simple mock FlowDataStore that stores one FlowData
    static FlowData* stored_flow_data = nullptr;
    FlowData* FlowDataStore::get(unsigned) const { return stored_flow_data; }
    void FlowDataStore::set(FlowData* fd) { stored_flow_data = fd; }
    FlowDataStore::~FlowDataStore() = default;
    
    // Helper to clear stored flow data (prevents use-after-free in tests)
    static void clear_stored_flow_data() { stored_flow_data = nullptr; }
    
    unsigned get_instance_id() { return 0; }
    
    // Mock DetectionEngine
    Packet* DetectionEngine::get_current_packet() { return nullptr; }
    int DetectionEngine::queue_event(unsigned, unsigned) { return 0; }
    Packet* DetectionEngine::set_next_packet(const Packet*, Flow*) { return nullptr; }
    DetectionEngine::DetectionEngine() = default;
    DetectionEngine::~DetectionEngine() = default;
    void DetectionEngine::set_encode_packet(Packet*) {}
    void DetectionEngine::disable_all(Packet*) {}
    
    // Mock Active
    void Active::block_session(Packet*, bool) {}
    void Active::set_drop_reason(const char*) {}
    
    // Mock PacketTracer
    bool PacketTracer::is_active() { return false; }
    void PacketTracer::log(const char*, ...) {}
    
    // Mock DataBus
    void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) {}
    void DataBus::publish(unsigned, unsigned, Packet*, Flow*) {}
    unsigned DataBus::get_id(const PubKey&) { return 0; }
    
    // Mock Stream
    uint32_t Stream::reg_xtra_data_cb(int (*)(Flow*, uint8_t**, uint32_t*, uint32_t*)) { return 0; }
    void Stream::set_extra_data(Flow*, Packet*, uint32_t) {}
    int Stream::set_snort_protocol_id_expected(const Packet*, PktType, IpProtocol,
        const SfIp*, uint16_t, const SfIp*, uint16_t, SnortProtocolId, FlowData*,
        bool, bool, bool, bool) { return 0; }
    uint32_t Stream::get_paf_position(Flow*, bool) { return 0; }
    void Stream::set_splitter_with_rescan(Flow*, bool, StreamSplitter*, uint32_t) {}
    
    // Mock ProtocolReference
    SnortProtocolId ProtocolReference::add(const char*) { return 1; }
    
    // Mock ThreadConfig
    unsigned ThreadConfig::get_instance_max() { return 1; }
    
    // Mock Inspector vtable
    StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
    
    // Mock Config Logger
    namespace ConfigLogger
    {
        void log_flag(const char*, bool, bool) {}
    }
    
    // Mock StreamSplitter pure virtual methods
    const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned, unsigned, const uint8_t*, unsigned, uint32_t, unsigned&)
    {
        return StreamBuffer();
    }
    unsigned StreamSplitter::max(Flow*) { return 0; }
    
    // Mock Flow destructor
    Flow::~Flow() = default;
    
    // Mock Profiler
    THREAD_LOCAL bool TimeProfilerStats::enabled = false;
}

// Mock Analyzer
Analyzer* Analyzer::get_local_analyzer() { return nullptr; }
bool Analyzer::process_rebuilt_packet(Packet*, const DAQ_PktHdr_t*, const uint8_t*, uint32_t) { return true; }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) {}
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) {}

// Mock IPS option symbols
const BaseApi* ips_socks_version = nullptr;
const BaseApi* ips_socks_state = nullptr;
const BaseApi* ips_socks_command = nullptr;
const BaseApi* ips_socks_address_type = nullptr;
const BaseApi* ips_socks_remote_address = nullptr;
const BaseApi* ips_socks_remote_port = nullptr;

// Note: socks_stats is defined in socks_module.cc which is linked

//=============================================================================
// Test Group: SOCKS Flow Data Boundary Conditions
//=============================================================================
TEST_GROUP(SocksFlowDataBoundaryTests)
{
    void setup()
    {
        SocksFlowData::init();
    }
};

// Test initial state - covers lines with default values
TEST(SocksFlowDataBoundaryTests, test_initial_state)
{
    SocksFlowData fd;
    
    // State checks
    CHECK_EQUAL(SOCKS_STATE_INIT, fd.get_state());
    CHECK_EQUAL(SOCKS_INITIATOR_UNKNOWN, fd.get_initiator());
    CHECK_EQUAL(SOCKS_DIR_CLIENT_TO_SERVER, fd.get_direction()); // Default per socks_flow_data.cc:40
    
    // Flags
    CHECK_FALSE(fd.is_session_counted());
    CHECK_FALSE(fd.is_handoff_pending());
    CHECK_FALSE(fd.is_handoff_completed());
    CHECK_FALSE(fd.is_socks4a());
    
    // Counters
    CHECK_EQUAL(0, fd.get_request_count());
    CHECK_EQUAL(0, fd.get_response_count());
    
    // Strings
    CHECK_TRUE(fd.get_target_address().empty());
    CHECK_TRUE(fd.get_bind_address().empty());
    CHECK_TRUE(fd.get_userid().empty());
    
    // Ports
    CHECK_EQUAL(0, fd.get_target_port());
    CHECK_EQUAL(0, fd.get_bind_port());
    
    // Pointers - target_ip is nullptr initially
    CHECK_TRUE(fd.get_target_ip() == nullptr);
    // Note: udp_reassembly is created on first get_udp_reassembly() call
}

// Test all state transitions
TEST(SocksFlowDataBoundaryTests, test_all_state_transitions)
{
    SocksFlowData fd;
    
    const SocksState states[] = {
        SOCKS_STATE_INIT,
        SOCKS_STATE_V4_CONNECT_RESPONSE,
        SOCKS_STATE_V4_BIND_SECOND_RESPONSE,
        SOCKS_STATE_V5_AUTH_NEGOTIATION,
        SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH,
        SOCKS_STATE_V5_CONNECT_REQUEST,
        SOCKS_STATE_V5_CONNECT_RESPONSE,
        SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION,
        SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE,
        SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST,
        SOCKS_STATE_ESTABLISHED,
        SOCKS_STATE_ERROR
    };
    
    for (auto state : states)
    {
        fd.set_state(state);
        CHECK_EQUAL(state, fd.get_state());
    }
}

// Test all command values
TEST(SocksFlowDataBoundaryTests, test_all_commands)
{
    SocksFlowData fd;
    
    fd.set_command(SOCKS_CMD_CONNECT);
    CHECK_EQUAL(SOCKS_CMD_CONNECT, fd.get_command());
    
    fd.set_command(SOCKS_CMD_BIND);
    CHECK_EQUAL(SOCKS_CMD_BIND, fd.get_command());
    
    fd.set_command(SOCKS_CMD_UDP_ASSOCIATE);
    CHECK_EQUAL(SOCKS_CMD_UDP_ASSOCIATE, fd.get_command());
}

// Test all address types
TEST(SocksFlowDataBoundaryTests, test_all_address_types)
{
    SocksFlowData fd;
    
    fd.set_address_type(SOCKS_ATYP_IPV4);
    CHECK_EQUAL(SOCKS_ATYP_IPV4, fd.get_address_type());
    
    fd.set_address_type(SOCKS_ATYP_DOMAIN);
    CHECK_EQUAL(SOCKS_ATYP_DOMAIN, fd.get_address_type());
    
    fd.set_address_type(SOCKS_ATYP_IPV6);
    CHECK_EQUAL(SOCKS_ATYP_IPV6, fd.get_address_type());
    
    fd.set_bind_address_type(SOCKS_ATYP_IPV4);
    CHECK_EQUAL(SOCKS_ATYP_IPV4, fd.get_bind_address_type());
}

// Test all auth methods
TEST(SocksFlowDataBoundaryTests, test_all_auth_methods)
{
    SocksFlowData fd;
    
    fd.set_auth_method(SOCKS5_AUTH_NONE);
    CHECK_EQUAL(SOCKS5_AUTH_NONE, fd.get_auth_method());
    
    fd.set_auth_method(SOCKS5_AUTH_GSSAPI);
    CHECK_EQUAL(SOCKS5_AUTH_GSSAPI, fd.get_auth_method());
    
    fd.set_auth_method(SOCKS5_AUTH_USERNAME_PASSWORD);
    CHECK_EQUAL(SOCKS5_AUTH_USERNAME_PASSWORD, fd.get_auth_method());
    
    fd.set_auth_method(SOCKS5_AUTH_NO_ACCEPTABLE);
    CHECK_EQUAL(SOCKS5_AUTH_NO_ACCEPTABLE, fd.get_auth_method());
}

// Test all reply codes
TEST(SocksFlowDataBoundaryTests, test_all_reply_codes)
{
    SocksFlowData fd;
    
    const SocksReplyCode codes[] = {
        SOCKS4_REP_GRANTED,
        SOCKS4_REP_REJECTED,
        SOCKS4_REP_NO_IDENTD,
        SOCKS4_REP_IDENTD_FAILED,
        SOCKS5_REP_SUCCESS,
        SOCKS5_REP_GENERAL_FAILURE,
        SOCKS5_REP_NOT_ALLOWED,
        SOCKS5_REP_NETWORK_UNREACHABLE,
        SOCKS5_REP_HOST_UNREACHABLE,
        SOCKS5_REP_CONNECTION_REFUSED,
        SOCKS5_REP_TTL_EXPIRED,
        SOCKS5_REP_COMMAND_NOT_SUPPORTED,
        SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED
    };
    
    for (auto code : codes)
    {
        fd.set_last_error(code);
        CHECK_EQUAL(code, fd.get_last_error());
    }
}

// Test port boundary values
TEST(SocksFlowDataBoundaryTests, test_port_boundaries)
{
    SocksFlowData fd;
    
    // Minimum port
    fd.set_target_port(0);
    CHECK_EQUAL(0, fd.get_target_port());
    
    // Maximum port
    fd.set_target_port(65535);
    CHECK_EQUAL(65535, fd.get_target_port());
    
    // Common ports
    const uint16_t common_ports[] = {21, 22, 23, 25, 80, 443, 1080, 3128, 8080};
    for (auto port : common_ports)
    {
        fd.set_target_port(port);
        CHECK_EQUAL(port, fd.get_target_port());
    }
    
    // Bind port
    fd.set_bind_port(0);
    CHECK_EQUAL(0, fd.get_bind_port());
    
    fd.set_bind_port(65535);
    CHECK_EQUAL(65535, fd.get_bind_port());
}

// Test empty and null string handling
TEST(SocksFlowDataBoundaryTests, test_empty_strings)
{
    SocksFlowData fd;
    
    // Empty target address
    fd.set_target_address("");
    CHECK_TRUE(fd.get_target_address().empty());
    
    // Empty bind address
    fd.set_bind_address("");
    CHECK_TRUE(fd.get_bind_address().empty());
    
    // Empty userid
    fd.set_userid("");
    CHECK_TRUE(fd.get_userid().empty());
    
    // Non-empty strings
    fd.set_target_address("example.com");
    STRCMP_EQUAL("example.com", fd.get_target_address().c_str());
    
    fd.set_bind_address("0.0.0.0");
    STRCMP_EQUAL("0.0.0.0", fd.get_bind_address().c_str());
    
    fd.set_userid("testuser");
    STRCMP_EQUAL("testuser", fd.get_userid().c_str());
}

// Test very long strings
TEST(SocksFlowDataBoundaryTests, test_long_strings)
{
    SocksFlowData fd;
    
    // 253 character domain (RFC 1035 max)
    std::string long_domain(253, 'a');
    fd.set_target_address(long_domain);
    CHECK_EQUAL(253, fd.get_target_address().length());
    
    // 255 character userid (SOCKS4 max)
    std::string long_userid(255, 'u');
    fd.set_userid(long_userid);
    CHECK_EQUAL(255, fd.get_userid().length());
}

// Test IPv4 address handling
TEST(SocksFlowDataBoundaryTests, test_ipv4_addresses)
{
    SocksFlowData fd;
    
    // Null initially
    CHECK_TRUE(fd.get_target_ip() == nullptr);
    
    // Set valid IPv4
    SfIp ip;
    ip.set("10.0.0.1");
    fd.set_target_ip(ip);
    
    // Verify it was set
    auto target_ip = fd.get_target_ip();
    if (target_ip)
    {
        CHECK_TRUE(target_ip->is_ip4());
    }
}

// Test IPv6 address handling
TEST(SocksFlowDataBoundaryTests, test_ipv6_addresses)
{
    SocksFlowData fd;
    
    // Set valid IPv6
    SfIp ip;
    ip.set("2001:db8::1");
    fd.set_target_ip(ip);
    
    // Verify it was set
    auto target_ip = fd.get_target_ip();
    if (target_ip)
    {
        CHECK_TRUE(target_ip->is_ip6());
    }
}

// Test counter overflow
TEST(SocksFlowDataBoundaryTests, test_counter_overflow)
{
    SocksFlowData fd;
    
    // Increment many times
    for (int i = 0; i < 1000; i++)
    {
        fd.increment_request_count();
        fd.increment_response_count();
    }
    
    CHECK_EQUAL(1000, fd.get_request_count());
    CHECK_EQUAL(1000, fd.get_response_count());
}

// Test flag toggling
TEST(SocksFlowDataBoundaryTests, test_flag_toggling)
{
    SocksFlowData fd;
    
    // Session counted
    CHECK_FALSE(fd.is_session_counted());
    fd.set_session_counted(true);
    CHECK_TRUE(fd.is_session_counted());
    fd.set_session_counted(false);
    CHECK_FALSE(fd.is_session_counted());
    
    // Handoff pending
    CHECK_FALSE(fd.is_handoff_pending());
    fd.set_handoff_pending(true);
    CHECK_TRUE(fd.is_handoff_pending());
    fd.set_handoff_pending(false);
    CHECK_FALSE(fd.is_handoff_pending());
    
    // Handoff completed
    CHECK_FALSE(fd.is_handoff_completed());
    fd.set_handoff_completed(true);
    CHECK_TRUE(fd.is_handoff_completed());
    fd.set_handoff_completed(false);
    CHECK_FALSE(fd.is_handoff_completed());
    
    // SOCKS4a
    CHECK_FALSE(fd.is_socks4a());
    fd.set_socks4a(true);
    CHECK_TRUE(fd.is_socks4a());
    fd.set_socks4a(false);
    CHECK_FALSE(fd.is_socks4a());
}

// Test version values
TEST(SocksFlowDataBoundaryTests, test_version_values)
{
    SocksFlowData fd;
    
    fd.set_socks_version(SOCKS4_VERSION);
    CHECK_EQUAL(SOCKS4_VERSION, fd.get_socks_version());
    
    fd.set_socks_version(SOCKS5_VERSION);
    CHECK_EQUAL(SOCKS5_VERSION, fd.get_socks_version());
    
    // Invalid version (should still store it)
    fd.set_socks_version(0x03);
    CHECK_EQUAL(0x03, fd.get_socks_version());
}

// Test initiator values - IMPORTANT: initiator is write-once!
// Per socks_flow_data.h:293-297, set_initiator() only works if initiator == UNKNOWN
// This is by design - first detection wins, cannot be changed after
TEST(SocksFlowDataBoundaryTests, test_initiator_write_once_behavior)
{
    SocksFlowData fd;
    
    // Initially UNKNOWN
    CHECK_EQUAL(SOCKS_INITIATOR_UNKNOWN, fd.get_initiator());
    CHECK_FALSE(fd.initiator_detected());
    
    // First set works
    fd.set_initiator(SOCKS_INITIATOR_CLIENT);
    CHECK_EQUAL(SOCKS_INITIATOR_CLIENT, fd.get_initiator());
    CHECK_TRUE(fd.initiator_detected());
    
    // Second set is IGNORED (write-once behavior)
    fd.set_initiator(SOCKS_INITIATOR_SERVER);
    CHECK_EQUAL(SOCKS_INITIATOR_CLIENT, fd.get_initiator()); // Still CLIENT!
    
    // Test with fresh object - set to SERVER
    SocksFlowData fd2;
    fd2.set_initiator(SOCKS_INITIATOR_SERVER);
    CHECK_EQUAL(SOCKS_INITIATOR_SERVER, fd2.get_initiator());
    CHECK_TRUE(fd2.initiator_detected());
}

// Test direction values
TEST(SocksFlowDataBoundaryTests, test_direction_values)
{
    SocksFlowData fd;
    
    fd.set_direction(SOCKS_DIR_CLIENT_TO_SERVER);
    CHECK_EQUAL(SOCKS_DIR_CLIENT_TO_SERVER, fd.get_direction());
    
    fd.set_direction(SOCKS_DIR_SERVER_TO_CLIENT);
    CHECK_EQUAL(SOCKS_DIR_SERVER_TO_CLIENT, fd.get_direction());
}

// Test error state with all error codes
TEST(SocksFlowDataBoundaryTests, test_error_state_with_codes)
{
    SocksFlowData fd;
    
    fd.set_state(SOCKS_STATE_ERROR);
    CHECK_EQUAL(SOCKS_STATE_ERROR, fd.get_state());
    
    // Test with each error code
    fd.set_last_error(SOCKS5_REP_GENERAL_FAILURE);
    CHECK_EQUAL(SOCKS5_REP_GENERAL_FAILURE, fd.get_last_error());
}

// Test UDP reassembly pointer

// Test state machine: SOCKS4 flow
TEST(SocksFlowDataBoundaryTests, test_socks4_state_flow)
{
    SocksFlowData fd;
    
    fd.set_socks_version(SOCKS4_VERSION);
    fd.set_state(SOCKS_STATE_INIT);
    fd.set_command(SOCKS_CMD_CONNECT);
    fd.increment_request_count();
    
    fd.set_state(SOCKS_STATE_V4_CONNECT_RESPONSE);
    fd.increment_response_count();
    
    fd.set_state(SOCKS_STATE_ESTABLISHED);
    
    CHECK_EQUAL(SOCKS4_VERSION, fd.get_socks_version());
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, fd.get_state());
    CHECK_EQUAL(1, fd.get_request_count());
    CHECK_EQUAL(1, fd.get_response_count());
}

// Test state machine: SOCKS5 with no auth
TEST(SocksFlowDataBoundaryTests, test_socks5_no_auth_flow)
{
    SocksFlowData fd;
    
    fd.set_socks_version(SOCKS5_VERSION);
    fd.set_state(SOCKS_STATE_V5_AUTH_NEGOTIATION);
    fd.increment_request_count();
    
    fd.set_auth_method(SOCKS5_AUTH_NONE);
    fd.increment_response_count();
    
    fd.set_state(SOCKS_STATE_V5_CONNECT_REQUEST);
    fd.set_command(SOCKS_CMD_CONNECT);
    fd.increment_request_count();
    
    fd.set_state(SOCKS_STATE_V5_CONNECT_RESPONSE);
    fd.set_last_error(SOCKS5_REP_SUCCESS);
    fd.increment_response_count();
    
    fd.set_state(SOCKS_STATE_ESTABLISHED);
    
    CHECK_EQUAL(SOCKS5_VERSION, fd.get_socks_version());
    CHECK_EQUAL(SOCKS5_AUTH_NONE, fd.get_auth_method());
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, fd.get_state());
    CHECK_EQUAL(2, fd.get_request_count());
    CHECK_EQUAL(2, fd.get_response_count());
}

// Test state machine: SOCKS5 with username/password auth
TEST(SocksFlowDataBoundaryTests, test_socks5_userpass_auth_flow)
{
    SocksFlowData fd;
    
    fd.set_socks_version(SOCKS5_VERSION);
    fd.set_state(SOCKS_STATE_V5_AUTH_NEGOTIATION);
    fd.increment_request_count();
    
    fd.set_auth_method(SOCKS5_AUTH_USERNAME_PASSWORD);
    fd.increment_response_count();
    
    fd.set_state(SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH);
    fd.set_userid("testuser");
    fd.increment_request_count();
    fd.increment_response_count();
    
    fd.set_state(SOCKS_STATE_V5_CONNECT_REQUEST);
    fd.set_command(SOCKS_CMD_CONNECT);
    fd.increment_request_count();
    
    fd.set_state(SOCKS_STATE_V5_CONNECT_RESPONSE);
    fd.set_last_error(SOCKS5_REP_SUCCESS);
    fd.increment_response_count();
    
    fd.set_state(SOCKS_STATE_ESTABLISHED);
    
    CHECK_EQUAL(SOCKS5_AUTH_USERNAME_PASSWORD, fd.get_auth_method());
    STRCMP_EQUAL("testuser", fd.get_userid().c_str());
    CHECK_EQUAL(3, fd.get_request_count());
    CHECK_EQUAL(3, fd.get_response_count());
}

// Test BIND command flow
TEST(SocksFlowDataBoundaryTests, test_bind_command_flow)
{
    SocksFlowData fd;
    
    fd.set_command(SOCKS_CMD_BIND);
    fd.set_bind_address("0.0.0.0");
    fd.set_bind_port(0);
    fd.set_bind_address_type(SOCKS_ATYP_IPV4);
    
    CHECK_EQUAL(SOCKS_CMD_BIND, fd.get_command());
    STRCMP_EQUAL("0.0.0.0", fd.get_bind_address().c_str());
    CHECK_EQUAL(0, fd.get_bind_port());
    CHECK_EQUAL(SOCKS_ATYP_IPV4, fd.get_bind_address_type());
}

// Test UDP ASSOCIATE command flow
TEST(SocksFlowDataBoundaryTests, test_udp_associate_flow)
{
    SocksFlowData fd;
    
    fd.set_command(SOCKS_CMD_UDP_ASSOCIATE);
    fd.set_bind_address("0.0.0.0");
    fd.set_bind_port(1080);
    fd.set_state(SOCKS_STATE_ESTABLISHED);
    
    CHECK_EQUAL(SOCKS_CMD_UDP_ASSOCIATE, fd.get_command());
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, fd.get_state());
}

//-------------------------------------------------------------------------
// get_xtra_target_ip Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(GetXtraTargetIpTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - modified in tests
    Flow* flow = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - modified in tests
    SocksFlowData* flow_data = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - assigned in tests
    // cppcheck-suppress unreadVariable ; false positive - used in tests
    uint8_t* buf = nullptr;
    // cppcheck-suppress unreadVariable ; false positive - used in tests
    uint32_t len = 0;
    // cppcheck-suppress unreadVariable ; false positive - used in tests
    uint32_t type = 0;

    void setup() override
    {
        SocksFlowData::init();
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow = new Flow();
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
    }

    void teardown() override
    {
        delete flow_data;
        delete flow;
        clear_stored_flow_data();
    }
};

TEST(GetXtraTargetIpTests, null_flow_returns_zero)
{
    int result = SocksInspector::get_xtra_target_ip(nullptr, &buf, &len, &type);
    CHECK_EQUAL(0, result);
}

TEST(GetXtraTargetIpTests, no_flow_data_returns_zero)
{
    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);
    CHECK_EQUAL(0, result);
}

TEST(GetXtraTargetIpTests, no_target_ip_returns_zero)
{
    flow->set_flow_data(flow_data);
    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);
    CHECK_EQUAL(0, result);
}

TEST(GetXtraTargetIpTests, unset_target_ip_returns_zero)
{
    flow->set_flow_data(flow_data);

    flow_data->set_target_address("example.com");
    flow_data->set_target_port(80);

    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);
    CHECK_EQUAL(0, result);
}

TEST(GetXtraTargetIpTests, ipv4_target_returns_success)
{
    flow->set_flow_data(flow_data);

    SfIp target_ip;
    target_ip.set("192.168.1.100");
    flow_data->set_target_ip(target_ip);
    flow_data->set_target_port(80);

    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);
    
    CHECK_EQUAL(1, result);
    CHECK(buf != nullptr);
    CHECK_EQUAL(4, len);
    CHECK_EQUAL(EVENT_INFO_XFF_IPV4, type);

    CHECK_EQUAL(192, buf[0]);
    CHECK_EQUAL(168, buf[1]);
    CHECK_EQUAL(1, buf[2]);
    CHECK_EQUAL(100, buf[3]);
}

TEST(GetXtraTargetIpTests, ipv6_target_returns_success)
{
    flow->set_flow_data(flow_data);

    SfIp target_ip;
    target_ip.set("2001:db8::1");
    flow_data->set_target_ip(target_ip);
    flow_data->set_target_port(443);
    
    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);
    
    CHECK_EQUAL(1, result);
    CHECK(buf != nullptr);
    CHECK_EQUAL(16, len);
    CHECK_EQUAL(EVENT_INFO_XFF_IPV6, type);

    CHECK_EQUAL(0x20, buf[0]);
    CHECK_EQUAL(0x01, buf[1]);
    CHECK_EQUAL(0x0d, buf[2]);
    CHECK_EQUAL(0xb8, buf[3]);
}

TEST(GetXtraTargetIpTests, various_ipv4_addresses)
{
    flow->set_flow_data(flow_data);

    SfIp target_ip;
    target_ip.set("10.0.0.1");
    flow_data->set_target_ip(target_ip);
    flow_data->set_target_port(22);

    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);

    CHECK_EQUAL(1, result);
    CHECK_EQUAL(4, len);
    CHECK_EQUAL(EVENT_INFO_XFF_IPV4, type);
    CHECK_EQUAL(10, buf[0]);
    CHECK_EQUAL(0, buf[1]);
    CHECK_EQUAL(0, buf[2]);
    CHECK_EQUAL(1, buf[3]);
}

TEST(GetXtraTargetIpTests, ipv4_loopback)
{
    flow->set_flow_data(flow_data);

    SfIp target_ip;
    target_ip.set("127.0.0.1");
    flow_data->set_target_ip(target_ip);
    flow_data->set_target_port(8080);

    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);

    CHECK_EQUAL(1, result);
    CHECK_EQUAL(4, len);
    CHECK_EQUAL(EVENT_INFO_XFF_IPV4, type);
    CHECK_EQUAL(127, buf[0]);
    CHECK_EQUAL(0, buf[1]);
    CHECK_EQUAL(0, buf[2]);
    CHECK_EQUAL(1, buf[3]);
}

TEST(GetXtraTargetIpTests, ipv6_loopback)
{
    flow->set_flow_data(flow_data);

    SfIp target_ip;
    target_ip.set("::1");
    flow_data->set_target_ip(target_ip);
    flow_data->set_target_port(8080);

    int result = SocksInspector::get_xtra_target_ip(flow, &buf, &len, &type);

    CHECK_EQUAL(1, result);
    CHECK_EQUAL(16, len);
    CHECK_EQUAL(EVENT_INFO_XFF_IPV6, type);

    for (int i = 0; i < 15; i++)
        CHECK_EQUAL(0, buf[i]);
    CHECK_EQUAL(1, buf[15]);
}

//-------------------------------------------------------------------------
// detect_protocol_initiator Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(DetectProtocolInitiatorTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    Packet* packet = nullptr;
    uint8_t packet_data[256];

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        packet = new Packet();
        packet->data = packet_data;
        packet->packet_flags = 0;
        packet->proto_bits = 0;
        packet->dsize = 0;
        memset(packet_data, 0, sizeof(packet_data));
    }

    void teardown() override
    {
        delete packet;
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(DetectProtocolInitiatorTests, null_data_returns_early)
{
    packet->data = nullptr;
    packet->dsize = 10;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    CHECK_FALSE(flow_data->initiator_detected());
}

TEST(DetectProtocolInitiatorTests, packet_too_short)
{
    packet->dsize = 1;  // Less than 2
    
    inspector->detect_protocol_initiator(packet, flow_data);
    CHECK_FALSE(flow_data->initiator_detected());
}

TEST(DetectProtocolInitiatorTests, client_socks4_detected)
{
    packet->packet_flags |= PKT_FROM_CLIENT;
    
    packet_data[0] = SOCKS4_VERSION;  // 0x04
    packet_data[1] = 0x01;
    packet->dsize = 10;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    
    CHECK_EQUAL(SOCKS_INITIATOR_CLIENT, flow_data->get_initiator());
}

TEST(DetectProtocolInitiatorTests, client_socks5_detected)
{
    packet->packet_flags |= PKT_FROM_CLIENT;
    
    packet_data[0] = SOCKS5_VERSION;  // 0x05
    packet_data[1] = 0x01;
    packet->dsize = 10;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    
    CHECK_EQUAL(SOCKS_INITIATOR_CLIENT, flow_data->get_initiator());
}

// Client with unknown version
TEST(DetectProtocolInitiatorTests, client_unknown_version)
{
    packet->packet_flags |= PKT_FROM_CLIENT;
    
    packet_data[0] = 0x03;  // Unknown version
    packet_data[1] = 0x01;
    packet->dsize = 10;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    CHECK_FALSE(flow_data->initiator_detected());
}

TEST(DetectProtocolInitiatorTests, server_socks5_detected)
{
    packet->packet_flags &= ~PKT_FROM_CLIENT;  // From server
    
    packet_data[0] = SOCKS5_VERSION;  // 0x05
    packet_data[1] = 0x00;
    packet->dsize = 2;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    
    CHECK_EQUAL(SOCKS_INITIATOR_SERVER, flow_data->get_initiator());
    CHECK_EQUAL(SOCKS5_VERSION, flow_data->get_socks_version());
}

TEST(DetectProtocolInitiatorTests, server_socks4_response_not_supported)
{
    // Reverse SOCKS4 (server-initiated) is not supported.
    // SOCKS4 responses start with 0x00 which is ambiguous, and the reverse
    // processing path only handles SOCKS5.
    packet->packet_flags &= ~PKT_FROM_CLIENT;  // From server
    
    packet_data[0] = SOCKS4_RESPONSE_VERSION;  // 0x00
    packet_data[1] = 0x5A;  // Request granted
    packet->dsize = 8;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    
    // Initiator should NOT be set - reverse SOCKS4 is unsupported
    CHECK_FALSE(flow_data->initiator_detected());
}

TEST(DetectProtocolInitiatorTests, server_unknown_version)
{
    packet->packet_flags &= ~PKT_FROM_CLIENT;  // From server
    
    packet_data[0] = 0x03;  // Unknown version
    packet_data[1] = 0x00;
    packet->dsize = 10;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    CHECK_FALSE(flow_data->initiator_detected());
}

TEST(DetectProtocolInitiatorTests, already_detected_not_changed)
{
    flow_data->set_initiator(SOCKS_INITIATOR_CLIENT);
    
    packet->packet_flags &= ~PKT_FROM_CLIENT;  // From server
    packet_data[0] = SOCKS5_VERSION;
    packet->dsize = 2;
    
    inspector->detect_protocol_initiator(packet, flow_data);
    
    // Should still be CLIENT (write-once behavior)
    CHECK_EQUAL(SOCKS_INITIATOR_CLIENT, flow_data->get_initiator());
}

//-------------------------------------------------------------------------
// process_reverse_server_data Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ProcessReverseServerDataTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    Packet* packet = nullptr;
    uint8_t packet_data[256];

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        packet = new Packet();
        packet->data = packet_data;
        memset(packet_data, 0, sizeof(packet_data));
    }

    void teardown() override
    {
        delete packet;
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ProcessReverseServerDataTests, established_state_processes_tunneled_data)
{
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_command(SOCKS_CMD_BIND);
    
    packet_data[0] = 0x05;
    packet_data[1] = 0x00;
    packet->dsize = 10;

    inspector->process_reverse_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, error_state_handled)
{
    flow_data->set_state(SOCKS_STATE_ERROR);

    packet_data[0] = 0x05;
    packet->dsize = 2;

    inspector->process_reverse_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, packet_too_short)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    
    packet_data[0] = 0x05;
    packet->dsize = 1;  // Too short
    
    inspector->process_reverse_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, socks5_auth_response_no_auth)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // No auth
    packet->dsize = 2;
    
    inspector->process_reverse_server_data(packet, flow_data);
    // Server sends auth response, transitions to AUTH_RESPONSE state
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, socks5_auth_response_error)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0xFF;  // No acceptable methods
    packet->dsize = 2;
    
    inspector->process_reverse_server_data(packet, flow_data);
    // Server sends error auth response, transitions to ERROR state
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, ignores_connect_response_from_client)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // Success
    packet_data[2] = 0x00;  // Reserved
    packet_data[3] = 0x01;  // IPv4
    packet_data[4] = 192;   // IP: 192.168.1.1
    packet_data[5] = 168;
    packet_data[6] = 1;
    packet_data[7] = 1;
    packet_data[8] = 0x04;  // Port: 1080
    packet_data[9] = 0x38;
    packet->dsize = 10;
    
    inspector->process_reverse_server_data(packet, flow_data);
    // Connect response should be ignored by server-side processing (client sends this)
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, ignores_connect_response_failure_from_client)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x01;  // General failure
    packet_data[2] = 0x00;  // Reserved
    packet_data[3] = 0x01;  // IPv4
    packet_data[4] = 0;
    packet_data[5] = 0;
    packet_data[6] = 0;
    packet_data[7] = 0;
    packet_data[8] = 0;
    packet_data[9] = 0;
    packet->dsize = 10;
    
    inspector->process_reverse_server_data(packet, flow_data);
    // Connect response should be ignored by server-side processing (client sends this)
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, ignores_bind_response_from_client)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
    flow_data->set_command(SOCKS_CMD_BIND);  // Not CONNECT
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // Success
    packet_data[2] = 0x00;  // Reserved
    packet_data[3] = 0x01;  // IPv4
    packet_data[4] = 10;
    packet_data[5] = 0;
    packet_data[6] = 0;
    packet_data[7] = 1;
    packet_data[8] = 0x00;
    packet_data[9] = 0x50;
    packet->dsize = 10;
    
    inspector->process_reverse_server_data(packet, flow_data);
    // Bind response should be ignored by server-side processing (client sends this)
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, socks5_invalid_reserved_byte)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;
    packet_data[2] = 0xFF;  // Invalid reserved byte (should be 0x00)
    packet_data[3] = 0x01;
    packet->dsize = 10;
    
    inspector->process_reverse_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, socks4_response_success)
{
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_REQUEST);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_socks_version(SOCKS4_VERSION);
    
    packet_data[0] = 0x00;  // SOCKS4 response version (0x00, NOT 0x04!)
    packet_data[1] = 0x5A;  // Request granted
    packet_data[2] = 0x04;  // Port high byte
    packet_data[3] = 0x38;  // Port low byte (1080)
    packet_data[4] = 192;   // IP: 192.168.1.1
    packet_data[5] = 168;
    packet_data[6] = 1;
    packet_data[7] = 1;
    packet->dsize = 8;
    
    inspector->process_reverse_server_data(packet, flow_data);
    
    // Server processes SOCKS4, stays in CONNECT_REQUEST state
    CHECK_EQUAL(SOCKS_STATE_V4_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, socks4_response_too_short)
{
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_REQUEST);
    
    packet_data[0] = 0x00;  // Correct SOCKS4 response version
    packet_data[1] = 0x5A;
    packet->dsize = 7;  // Too short
    
    inspector->process_reverse_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_V4_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, socks4_bind_response_no_handoff)
{
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_REQUEST);
    flow_data->set_command(SOCKS_CMD_BIND);  // BIND, not CONNECT
    flow_data->set_socks_version(SOCKS4_VERSION);
    
    packet_data[0] = 0x00;  // SOCKS4 response version
    packet_data[1] = 0x5A;  // Request granted
    packet_data[2] = 0x04;
    packet_data[3] = 0x38;
    packet_data[4] = 10;
    packet_data[5] = 0;
    packet_data[6] = 0;
    packet_data[7] = 1;
    packet->dsize = 8;
    
    inspector->process_reverse_server_data(packet, flow_data);
    
    // Server processes SOCKS4, stays in CONNECT_REQUEST state
    CHECK_EQUAL(SOCKS_STATE_V4_CONNECT_REQUEST, flow_data->get_state());
}

TEST(ProcessReverseServerDataTests, unknown_version)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    
    packet_data[0] = 0x03;  // Unknown version
    packet_data[1] = 0x00;
    packet->dsize = 10;
    
    inspector->process_reverse_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION, flow_data->get_state());
}

//-------------------------------------------------------------------------
// process_reverse_client_data Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ProcessReverseClientDataTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    Packet* packet = nullptr;
    uint8_t packet_data[256];

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        packet = new Packet();
        packet->data = packet_data;
        memset(packet_data, 0, sizeof(packet_data));
    }

    void teardown() override
    {
        delete packet;
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ProcessReverseClientDataTests, established_state_processes_tunneled_data)
{
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_command(SOCKS_CMD_BIND);
    
    packet_data[0] = 0x05;
    packet_data[1] = 0x01;
    packet->dsize = 10;

    inspector->process_reverse_client_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, error_state_handled)
{
    flow_data->set_state(SOCKS_STATE_ERROR);

    packet_data[0] = 0x05;
    packet->dsize = 2;

    inspector->process_reverse_client_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, packet_too_short)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    
    packet_data[0] = 0x05;
    packet->dsize = 1;  // Too short
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, wrong_version)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    
    packet_data[0] = 0x04;  // SOCKS4, not SOCKS5
    packet_data[1] = 0x01;
    packet->dsize = 10;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, username_password_auth_in_auth_response_state)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    flow_data->set_auth_method(SOCKS5_AUTH_USERNAME_PASSWORD);

    packet_data[0] = 0x01;  // Auth version
    packet_data[1] = 0x04;  // Username length
    packet_data[2] = 'u';
    packet_data[3] = 's';
    packet_data[4] = 'e';
    packet_data[5] = 'r';
    packet_data[6] = 0x04;  // Password length
    packet_data[7] = 'p';
    packet_data[8] = 'a';
    packet_data[9] = 's';
    packet_data[10] = 's';
    packet->dsize = 11;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, ignores_auth_negotiation_from_server)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    flow_data->set_auth_method(SOCKS5_AUTH_NONE);

    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x02;  // 2 methods
    packet_data[2] = 0x00;  // No auth
    packet_data[3] = 0x02;  // Username/password
    packet->dsize = 4;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Auth negotiation should be ignored by client-side processing (server sends this)
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, connect_response_success)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    flow_data->set_auth_method(SOCKS5_AUTH_NONE);

    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // Reply code: Success
    packet_data[2] = 0x00;  // Reserved (must be 0)
    packet_data[3] = 0x01;  // IPv4
    packet_data[4] = 192;   // IP: 192.168.1.1
    packet_data[5] = 168;
    packet_data[6] = 1;
    packet_data[7] = 1;
    packet_data[8] = 0x00;  // Port: 80
    packet_data[9] = 0x50;
    packet->dsize = 10;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Client sends connect response, transitions to ESTABLISHED for CONNECT
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
    CHECK_TRUE(flow_data->is_handoff_pending());
}

TEST(ProcessReverseClientDataTests, bind_response_success)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);

    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // Reply code: Success
    packet_data[2] = 0x00;  // Reserved
    packet_data[3] = 0x01;  // IPv4
    packet_data[4] = 10;    // IP: 10.0.0.1
    packet_data[5] = 0;
    packet_data[6] = 0;
    packet_data[7] = 1;
    packet_data[8] = 0x1F;  // Port: 8080
    packet_data[9] = 0x90;
    packet->dsize = 10;
    
    flow_data->set_command(SOCKS_CMD_BIND);  // Set command to BIND
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Client sends bind response, transitions to ESTABLISHED for BIND (no handoff)
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
    CHECK_FALSE(flow_data->is_handoff_pending());
}

TEST(ProcessReverseClientDataTests, udp_associate_response_success)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);

    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // Reply code: Success
    packet_data[2] = 0x00;  // Reserved
    packet_data[3] = 0x01;  // IPv4
    packet_data[4] = 0;     // IP: 0.0.0.0
    packet_data[5] = 0;
    packet_data[6] = 0;
    packet_data[7] = 0;
    packet_data[8] = 0x04;  // Port: 1080
    packet_data[9] = 0x38;
    packet->dsize = 10;
    
    flow_data->set_command(SOCKS_CMD_UDP_ASSOCIATE);  // Set command to UDP_ASSOCIATE
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Client sends UDP associate response, transitions to ESTABLISHED (no handoff)
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
    CHECK_FALSE(flow_data->is_handoff_pending());
}

TEST(ProcessReverseClientDataTests, username_password_auth_fallback)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    flow_data->set_auth_method(SOCKS5_AUTH_USERNAME_PASSWORD);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // 0 methods (invalid for auth negotiation)
    packet->dsize = 2;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Invalid auth negotiation, stays in AUTH_RESPONSE state
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, ignores_auth_negotiation_single_method_from_server)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x01;  // 1 method
    packet_data[2] = 0x00;  // No auth
    packet->dsize = 3;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Client sends auth response, stays in AUTH_RESPONSE state
    CHECK_EQUAL(SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE, flow_data->get_state());
}

TEST(ProcessReverseClientDataTests, connect_response_with_domain)
{
    flow_data->set_state(SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    flow_data->set_command(SOCKS_CMD_CONNECT);  // Set command to CONNECT
    
    packet_data[0] = 0x05;  // SOCKS5
    packet_data[1] = 0x00;  // Reply code: Success
    packet_data[2] = 0x00;  // Reserved
    packet_data[3] = 0x03;  // Domain name
    packet_data[4] = 0x0B;  // Length: 11
    memcpy(&packet_data[5], "example.com", 11);
    packet_data[16] = 0x00; // Port: 443
    packet_data[17] = 0xBB;
    packet->dsize = 18;
    
    inspector->process_reverse_client_data(packet, flow_data);
    
    // Client sends connect response with domain, transitions to ESTABLISHED
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
    CHECK_TRUE(flow_data->is_handoff_pending());
}

//-------------------------------------------------------------------------
// process_client_data and process_server_data State Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ProcessDataStateTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    Packet* packet = nullptr;
    uint8_t packet_data[256];

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        packet = new Packet();
        packet->data = packet_data;
        memset(packet_data, 0, sizeof(packet_data));
        packet->dsize = 10;
    }

    void teardown() override
    {
        delete packet;
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ProcessDataStateTests, client_established_state)
{
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    
    inspector->process_client_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
}

TEST(ProcessDataStateTests, server_established_state)
{
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    
    inspector->process_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
}

TEST(ProcessDataStateTests, client_error_state)
{
    flow_data->set_state(SOCKS_STATE_ERROR);
    packet_data[0] = 0x05;
    
    inspector->process_client_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

TEST(ProcessDataStateTests, server_error_state)
{
    flow_data->set_state(SOCKS_STATE_ERROR);
    packet_data[0] = 0x05;
    
    inspector->process_server_data(packet, flow_data);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

//-------------------------------------------------------------------------
// validate_socks5_request_header Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ValidateSocks5RequestHeaderTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    uint8_t data[256];

    void setup() override
    {
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        memset(data, 0, sizeof(data));
    }

    void teardown() override
    {
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ValidateSocks5RequestHeaderTests, valid_request_returns_true)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x01;  // CONNECT
    req.reserved = 0x00;
    req.address_type = 0x01;  // IPv4
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_TRUE(result);
}

TEST(ValidateSocks5RequestHeaderTests, invalid_version_returns_false)
{
    Socks5ConnectRequest req;
    req.version = 0x04;  // Invalid - should be 0x05
    req.command = 0x01;
    req.reserved = 0x00;
    req.address_type = 0x01;
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_FALSE(result);
}

TEST(ValidateSocks5RequestHeaderTests, invalid_command_returns_false)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0xFF;  // Invalid command
    req.reserved = 0x00;
    req.address_type = 0x01;
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_FALSE(result);
}

TEST(ValidateSocks5RequestHeaderTests, nonzero_reserved_still_validates)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x01;
    req.reserved = 0x01;  // Non-zero reserved (protocol violation but not fatal)
    req.address_type = 0x01;
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_TRUE(result);  // Should still return true (warning only)
}

TEST(ValidateSocks5RequestHeaderTests, invalid_address_type_returns_false)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x01;
    req.reserved = 0x00;
    req.address_type = 0xFF;  // Invalid address type
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_FALSE(result);
}

TEST(ValidateSocks5RequestHeaderTests, valid_bind_command)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x02;  // BIND
    req.reserved = 0x00;
    req.address_type = 0x01;
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_TRUE(result);
}

TEST(ValidateSocks5RequestHeaderTests, valid_udp_associate_command)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x03;  // UDP_ASSOCIATE
    req.reserved = 0x00;
    req.address_type = 0x01;
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_TRUE(result);
}

TEST(ValidateSocks5RequestHeaderTests, valid_domain_address_type)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x01;
    req.reserved = 0x00;
    req.address_type = 0x03;  // Domain name
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_TRUE(result);
}

TEST(ValidateSocks5RequestHeaderTests, valid_ipv6_address_type)
{
    Socks5ConnectRequest req;
    req.version = 0x05;
    req.command = 0x01;
    req.reserved = 0x00;
    req.address_type = 0x04;  // IPv6
    
    bool result = inspector->validate_socks5_request_header(&req);
    CHECK_TRUE(result);
}

//-------------------------------------------------------------------------
// parse_socks5_auth_response Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ParseSocks5AuthResponseTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    uint8_t data[256];

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        memset(data, 0, sizeof(data));
    }

    void teardown() override
    {
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ParseSocks5AuthResponseTests, insufficient_length_returns_false)
{
    data[0] = 0x05;
    bool result = inspector->parse_socks5_auth_response(data, 1, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks5AuthResponseTests, no_acceptable_methods_triggers_auth_failure)
{
    data[0] = 0x05;
    data[1] = 0xFF;  // SOCKS5_AUTH_NO_ACCEPTABLE
    
    bool result = inspector->parse_socks5_auth_response(data, 2, flow_data);
    
    CHECK_FALSE(result);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

TEST(ParseSocks5AuthResponseTests, session_counted_when_server_initiator)
{
    flow_data->set_initiator(SOCKS_INITIATOR_SERVER);
    flow_data->set_session_counted(false);
    
    data[0] = 0x05;
    data[1] = 0x00;  // SOCKS5_AUTH_NONE
    
    bool result = inspector->parse_socks5_auth_response(data, 2, flow_data);
    
    CHECK_TRUE(result);
    CHECK_TRUE(flow_data->is_session_counted());
}

TEST(ParseSocks5AuthResponseTests, unsupported_auth_method_skips_to_connect_request)
{
    data[0] = 0x05;
    data[1] = 0x01;  // GSSAPI (unsupported)
    
    bool result = inspector->parse_socks5_auth_response(data, 2, flow_data);
    
    CHECK_TRUE(result);
    // skips auth phase and waits for CONNECT/BIND/UDP_ASSOCIATE
    CHECK_EQUAL(SOCKS_STATE_V5_CONNECT_REQUEST, flow_data->get_state());
    CHECK_FALSE(flow_data->is_handoff_pending());
}

TEST(ParseSocks5AuthResponseTests, private_auth_method_skips_to_connect_request)
{
    data[0] = 0x05;
    data[1] = 0x80;  // Private method (0x80-0xFE)
    
    bool result = inspector->parse_socks5_auth_response(data, 2, flow_data);
    
    CHECK_TRUE(result);
    // skips auth phase and waits for CONNECT/BIND/UDP_ASSOCIATE
    CHECK_EQUAL(SOCKS_STATE_V5_CONNECT_REQUEST, flow_data->get_state());
    CHECK_FALSE(flow_data->is_handoff_pending());
}

//-------------------------------------------------------------------------
// parse_socks4_response Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ParseSocks4ResponseTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    uint8_t data[256];

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        memset(data, 0, sizeof(data));
    }

    void teardown() override
    {
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ParseSocks4ResponseTests, null_data_returns_false)
{
    bool result = inspector->parse_socks4_response(nullptr, 10, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4ResponseTests, insufficient_length_returns_false)
{
    data[0] = 0x00;
    bool result = inspector->parse_socks4_response(data, 7, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4ResponseTests, invalid_version_returns_false)
{
    data[0] = 0x04;  // Should be 0x00
    data[1] = 0x5A;  // GRANTED
    bool result = inspector->parse_socks4_response(data, 8, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4ResponseTests, bind_first_response_transitions_to_bind_second)
{
    flow_data->set_command(SOCKS_CMD_BIND);
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_RESPONSE);
    
    data[0] = 0x00;  // Version
    data[1] = 0x5A;  // GRANTED
    data[2] = 0x00;  // Port high
    data[3] = 0x50;  // Port low (80)
    data[4] = 192;   // IP
    data[5] = 168;
    data[6] = 1;
    data[7] = 1;
    
    bool result = inspector->parse_socks4_response(data, 8, flow_data);
    
    CHECK_TRUE(result);
    CHECK_EQUAL(SOCKS_STATE_V4_BIND_SECOND_RESPONSE, flow_data->get_state());
}

TEST(ParseSocks4ResponseTests, connection_rejected_sets_error_state)
{
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target_address("192.168.1.100");
    flow_data->set_target_port(80);
    
    data[0] = 0x00;  // Version
    data[1] = 0x5B;  // REJECTED (not 0x5A)
    data[2] = 0x00;
    data[3] = 0x00;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;
    
    bool result = inspector->parse_socks4_response(data, 8, flow_data);
    
    CHECK_FALSE(result);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

TEST(ParseSocks4ResponseTests, rejected_with_different_status_codes)
{
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target_address("10.0.0.1");
    flow_data->set_target_port(22);
    
    data[0] = 0x00;
    data[1] = 0x5C;  // Request rejected - identd not reachable
    
    bool result = inspector->parse_socks4_response(data, 8, flow_data);
    
    CHECK_FALSE(result);
    CHECK_EQUAL(SOCKS_STATE_ERROR, flow_data->get_state());
}

//-------------------------------------------------------------------------
// parse_socks4_request Tests - Full Coverage
//-------------------------------------------------------------------------

TEST_GROUP(ParseSocks4RequestTests)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksInspectorTestHelper* inspector = nullptr;
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;
    uint8_t data[512];  // Increased size to accommodate userid_too_long test (needs 265 bytes)

    void setup() override
    {
        SocksFlowData::init();
        SocksModule module;
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        inspector = new SocksInspectorTestHelper(&module);
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
        memset(data, 0, sizeof(data));
    }

    void teardown() override
    {
        delete flow_data;
        delete inspector;
        clear_stored_flow_data();
    }
};

TEST(ParseSocks4RequestTests, null_data_returns_false)
{
    bool result = inspector->parse_socks4_request(nullptr, 10, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4RequestTests, insufficient_length_returns_false)
{
    data[0] = 0x04;
    bool result = inspector->parse_socks4_request(data, 8, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4RequestTests, invalid_version_returns_false)
{
    data[0] = 0x05;  // Should be 0x04
    data[1] = 0x01;
    bool result = inspector->parse_socks4_request(data, 10, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4RequestTests, invalid_command_returns_false)
{
    data[0] = 0x04;
    data[1] = 0xFF;  // Invalid command
    bool result = inspector->parse_socks4_request(data, 10, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4RequestTests, missing_userid_null_terminator_returns_false)
{
    data[0] = 0x04;
    data[1] = 0x01;  // CONNECT
    data[2] = 0x00;  // Port
    data[3] = 0x50;
    data[4] = 192;   // IP
    data[5] = 168;
    data[6] = 1;
    data[7] = 1;
    data[8] = 'u';   // Userid starts but no null terminator within length
    
    bool result = inspector->parse_socks4_request(data, 9, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4RequestTests, userid_too_long_returns_false)
{
    data[0] = 0x04;
    data[1] = 0x01;
    data[2] = 0x00;
    data[3] = 0x50;
    data[4] = 192;
    data[5] = 168;
    data[6] = 1;
    data[7] = 1;
    // Fill with 256 bytes (too long)
    memset(&data[8], 'a', 256);
    data[264] = 0;  // Null terminator
    
    bool result = inspector->parse_socks4_request(data, 265, flow_data);
    CHECK_FALSE(result);
}

TEST(ParseSocks4RequestTests, minimal_valid_request_with_empty_userid)
{
    data[0] = 0x04;
    data[1] = 0x01;
    data[2] = 0x00;
    data[3] = 0x50;
    data[4] = 192;
    data[5] = 168;
    data[6] = 1;
    data[7] = 1;
    data[8] = 0;  // Null terminator for empty userid
    
    bool result = inspector->parse_socks4_request(data, 9, flow_data);
    CHECK_TRUE(result);  // This is a valid SOCKS4 request with empty userid
    CHECK_EQUAL(SOCKS4_VERSION, flow_data->get_socks_version());
    CHECK_EQUAL(SOCKS_CMD_CONNECT, flow_data->get_command());
}

TEST(ParseSocks4RequestTests, socks4_ipv4_request_success)
{
    data[0] = 0x04;  // Version
    data[1] = 0x01;  // CONNECT
    data[2] = 0x00;  // Port high
    data[3] = 0x50;  // Port low (80)
    data[4] = 192;   // IP: 192.168.1.100
    data[5] = 168;
    data[6] = 1;
    data[7] = 100;
    data[8] = 'u';   // Userid
    data[9] = 's';
    data[10] = 'e';
    data[11] = 'r';
    data[12] = 0;    // Null terminator
    
    bool result = inspector->parse_socks4_request(data, 13, flow_data);
    
    CHECK_TRUE(result);
    CHECK_EQUAL(SOCKS4_VERSION, flow_data->get_socks_version());
    CHECK_EQUAL(SOCKS_CMD_CONNECT, flow_data->get_command());
    CHECK_EQUAL(80, flow_data->get_target_port());
    CHECK_EQUAL(SOCKS_ATYP_IPV4, flow_data->get_address_type());
    CHECK_FALSE(flow_data->is_socks4a());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
