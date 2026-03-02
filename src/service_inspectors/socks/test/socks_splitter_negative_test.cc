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

// socks_splitter_negative_test.cc author Raza Shafiq <rshafiq@cisco.com>
// Negative test cases for SOCKS splitter to improve code coverage

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "../socks_flow_data.h"

// Access private methods for testing
#define private public
#include "../socks_splitter.h"
#undef private

#include "stream/stream_splitter.h"

namespace snort
{
    class Flow;
    class Packet;
}

// Forward declare SocksStats
struct SocksStats
{
    uint64_t concurrent_sessions = 0;
    uint64_t max_concurrent_sessions = 0;
};

using namespace snort;

// Mock implementations - copied from socks_splitter_test.cc
namespace snort
{
    class Packet
    {
    public:
        Flow* flow = nullptr;
        
        Packet(bool) { flow = nullptr; }
        ~Packet() = default;
    };
    
    class Flow
    {
    public:
        FlowData* flow_data = nullptr;
        unsigned flow_data_id = 0;
        
        FlowData* get_flow_data(unsigned id) const {
            if (flow_data and id == flow_data_id)
                return flow_data;
            return nullptr;
        }
        
        int set_flow_data(FlowData* fd) {
            flow_data = fd;
            if (fd)
                flow_data_id = SocksFlowData::get_inspector_id();
            return 0;
        }
    };
    
    class Trace {};
    
    class TraceApi
    {
    public:
        static unsigned get_constraints_generation();
        static bool filter(const Packet&);
    };
    
    FlowData::FlowData(uint32_t) {}
    FlowData::~FlowData() {}

    FlowData* FlowDataStore::get(uint32_t) const { return nullptr; }
    
    uint32_t FlowData::flow_data_id = 1;
    unsigned FlowData::create_flow_data_id()
    { return ++flow_data_id; }

    void trace_vprintf(const char*, uint8_t, const char*, const Packet*, const char*, va_list) {}
    
    const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned, unsigned,
        const uint8_t*, unsigned, uint32_t, unsigned&)
    {
        return {nullptr, 0};
    }
    
    unsigned StreamSplitter::max(Flow*) { return 0; }
    
    unsigned TraceApi::get_constraints_generation() { return 0; }
    bool TraceApi::filter(const Packet&) { return false; }
    
    char* snort_strdup(const char* s)
    {
        if (!s)
            return nullptr;
        size_t len = strlen(s) + 1;
        char* dup = new char[len];
        memcpy(dup, s, len);
        return dup;
    }
}

// Mock SOCKS stats
THREAD_LOCAL SocksStats socks_stats;

//=============================================================================
// Test Group: SOCKS Splitter Error Cases
//=============================================================================
TEST_GROUP(SocksSplitterErrorCases)
{
    SocksSplitter* splitter = nullptr;
    
    void setup()
    {
        SocksFlowData::init();
        splitter = new SocksSplitter(true); // client-to-server
    }
    
    void teardown()
    {
        delete splitter;
    }
};

// Note: scan() tests with Packet are covered by socks_splitter_test.cc
// This file focuses on testing the private parsing methods directly

// Test auth negotiation with invalid version
TEST(SocksSplitterErrorCases, test_auth_neg_invalid_version)
{
    uint8_t data[] = {0x04, 0x01, 0x00}; // Wrong version for auth negotiation
    uint32_t result = splitter->parse_auth_negotiation(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test auth negotiation with zero methods
TEST(SocksSplitterErrorCases, test_auth_neg_zero_methods)
{
    uint8_t data[] = {0x05, 0x00}; // Zero methods
    uint32_t result = splitter->parse_auth_negotiation(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test auth negotiation incomplete
TEST(SocksSplitterErrorCases, test_auth_neg_incomplete)
{
    uint8_t data[] = {0x05, 0x03, 0x00}; // Says 3 methods but only 1 byte
    uint32_t result = splitter->parse_auth_negotiation(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test auth response too short
TEST(SocksSplitterErrorCases, test_auth_resp_too_short)
{
    uint8_t data[] = {0x05}; // Only 1 byte
    uint32_t result = splitter->parse_auth_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test auth response with unsupported method (GSSAPI)
TEST(SocksSplitterErrorCases, test_auth_resp_unsupported_method)
{
    uint8_t data[] = {0x05, 0x01}; // GSSAPI (unsupported)
    uint32_t result = splitter->parse_auth_response(data, sizeof(data));
    CHECK_EQUAL(2, result); // Consumes the 2 bytes
}

// Test auth response invalid version
TEST(SocksSplitterErrorCases, test_auth_resp_invalid_version)
{
    uint8_t data[] = {0x03, 0x00}; // Invalid version
    uint32_t result = splitter->parse_auth_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test username/password auth invalid version
TEST(SocksSplitterErrorCases, test_userpass_auth_invalid_version)
{
    uint8_t data[] = {0x02, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'};
    uint32_t result = splitter->parse_username_password_auth(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test username/password auth too short
TEST(SocksSplitterErrorCases, test_userpass_auth_too_short)
{
    uint8_t data[] = {0x01, 0x04}; // Missing username
    uint32_t result = splitter->parse_username_password_auth(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test username/password auth incomplete username
TEST(SocksSplitterErrorCases, test_userpass_auth_incomplete_username)
{
    uint8_t data[] = {0x01, 0x10, 'u', 's'}; // Says 16 bytes but only 2
    uint32_t result = splitter->parse_username_password_auth(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test username/password auth incomplete password
TEST(SocksSplitterErrorCases, test_userpass_auth_incomplete_password)
{
    uint8_t data[] = {0x01, 0x04, 'u', 's', 'e', 'r', 0x10, 'p'}; // Says 16 bytes password but only 1
    uint32_t result = splitter->parse_username_password_auth(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test username/password auth response invalid version
TEST(SocksSplitterErrorCases, test_userpass_auth_resp_invalid_version)
{
    uint8_t data[] = {0x02, 0x00}; // Wrong version
    uint32_t result = splitter->parse_username_password_auth_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test username/password auth response too short
TEST(SocksSplitterErrorCases, test_userpass_auth_resp_too_short)
{
    uint8_t data[] = {0x01}; // Only 1 byte
    uint32_t result = splitter->parse_username_password_auth_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test connect request invalid version
TEST(SocksSplitterErrorCases, test_connect_req_invalid_version)
{
    uint8_t data[] = {0x04, 0x01, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};
    uint32_t result = splitter->parse_connect_request(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test connect request too short
TEST(SocksSplitterErrorCases, test_connect_req_too_short)
{
    uint8_t data[] = {0x05, 0x01, 0x00}; // Only 3 bytes
    uint32_t result = splitter->parse_connect_request(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test connect response invalid version
TEST(SocksSplitterErrorCases, test_connect_resp_invalid_version)
{
    uint8_t data[] = {0x04, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};
    uint32_t result = splitter->parse_connect_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test connect response too short
TEST(SocksSplitterErrorCases, test_connect_resp_too_short)
{
    uint8_t data[] = {0x05, 0x00, 0x00}; // Only 3 bytes
    uint32_t result = splitter->parse_connect_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test address parsing with invalid address type
TEST(SocksSplitterErrorCases, test_address_invalid_type)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0xFF}; // Invalid address type 0xFF
    uint32_t result = splitter->parse_address_port_length(data, sizeof(data), 3);
    CHECK_EQUAL(0, result);
}

// Test address parsing with domain length = 0
TEST(SocksSplitterErrorCases, test_address_domain_zero_length)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50}; // Domain length = 0
    uint32_t result = splitter->parse_address_port_length(data, sizeof(data), 3);
    CHECK_EQUAL(0, result);
}

// Test address parsing with domain length > 253
TEST(SocksSplitterErrorCases, test_address_domain_too_long)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x03, 254}; // Domain length = 254 (> 253 max)
    uint32_t result = splitter->parse_address_port_length(data, sizeof(data), 3);
    CHECK_EQUAL(0, result);
}

// Test address parsing incomplete domain
TEST(SocksSplitterErrorCases, test_address_domain_incomplete)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x03, 0x0A, 'e', 'x'}; // Says 10 bytes but only 2
    uint32_t result = splitter->parse_address_port_length(data, sizeof(data), 3);
    CHECK_EQUAL(0, result);
}

// Test address parsing offset out of bounds
TEST(SocksSplitterErrorCases, test_address_offset_out_of_bounds)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x01};
    uint32_t result = splitter->parse_address_port_length(data, sizeof(data), 10); // Offset > len
    CHECK_EQUAL(0, result);
}

// Test SOCKS4 request invalid version
TEST(SocksSplitterErrorCases, test_socks4_req_invalid_version)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01, 0x00};
    uint32_t result = splitter->parse_socks4_request(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test SOCKS4 request too short
TEST(SocksSplitterErrorCases, test_socks4_req_too_short)
{
    uint8_t data[] = {0x04, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01}; // Only 8 bytes
    uint32_t result = splitter->parse_socks4_request(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test SOCKS4 request no null terminator
TEST(SocksSplitterErrorCases, test_socks4_req_no_null_terminator)
{
    uint8_t data[] = {0x04, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01, 'u', 's', 'e', 'r'}; // No null
    uint32_t result = splitter->parse_socks4_request(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test SOCKS4 request userid too long
TEST(SocksSplitterErrorCases, test_socks4_req_userid_too_long)
{
    uint8_t data[300];
    data[0] = 0x04; // Version
    data[1] = 0x01; // Command
    data[2] = 0x00; data[3] = 0x50; // Port
    data[4] = 0x0A; data[5] = 0x00; data[6] = 0x00; data[7] = 0x01; // IP
    // Fill with 256+ bytes (too long)
    for (int i = 8; i < 270; i++)
        data[i] = 'A';
    
    uint32_t result = splitter->parse_socks4_request(data, 270);
    CHECK_EQUAL(0, result);
}

// Test SOCKS4a request incomplete domain
TEST(SocksSplitterErrorCases, test_socks4a_req_incomplete_domain)
{
    uint8_t data[] = {0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 'e', 'x', 'a', 'm'}; // No null
    uint32_t result = splitter->parse_socks4_request(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test SOCKS4a request domain too long
TEST(SocksSplitterErrorCases, test_socks4a_req_domain_too_long)
{
    uint8_t data[300];
    data[0] = 0x04; // Version
    data[1] = 0x01; // Command
    data[2] = 0x00; data[3] = 0x50; // Port
    data[4] = 0x00; data[5] = 0x00; data[6] = 0x00; data[7] = 0x01; // SOCKS4a indicator
    data[8] = 0x00; // Userid null terminator
    // Fill with 254+ bytes domain (too long)
    for (int i = 9; i < 270; i++)
        data[i] = 'a';
    
    uint32_t result = splitter->parse_socks4_request(data, 270);
    CHECK_EQUAL(0, result);
}

// Test SOCKS4 response too short
TEST(SocksSplitterErrorCases, test_socks4_resp_too_short)
{
    uint8_t data[] = {0x00, 0x5A, 0x00, 0x50, 0x0A, 0x00, 0x00}; // Only 7 bytes
    uint32_t result = splitter->parse_socks4_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test SOCKS4 response invalid version
TEST(SocksSplitterErrorCases, test_socks4_resp_invalid_version)
{
    uint8_t data[] = {0x04, 0x5A, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01}; // Version should be 0x00
    uint32_t result = splitter->parse_socks4_response(data, sizeof(data));
    CHECK_EQUAL(0, result);
}

// Test valid cases to ensure they still work
TEST(SocksSplitterErrorCases, test_valid_auth_negotiation)
{
    uint8_t data[] = {0x05, 0x02, 0x00, 0x02}; // Version 5, 2 methods
    uint32_t result = splitter->parse_auth_negotiation(data, sizeof(data));
    CHECK_EQUAL(4, result);
}

TEST(SocksSplitterErrorCases, test_valid_auth_response_none)
{
    uint8_t data[] = {0x05, 0x00}; // No auth
    uint32_t result = splitter->parse_auth_response(data, sizeof(data));
    CHECK_EQUAL(2, result);
}

TEST(SocksSplitterErrorCases, test_valid_auth_response_userpass)
{
    uint8_t data[] = {0x05, 0x02}; // Username/password
    uint32_t result = splitter->parse_auth_response(data, sizeof(data));
    CHECK_EQUAL(2, result);
}

TEST(SocksSplitterErrorCases, test_valid_userpass_auth)
{
    uint8_t data[] = {0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'};
    uint32_t result = splitter->parse_username_password_auth(data, sizeof(data));
    CHECK_EQUAL(11, result);
}

TEST(SocksSplitterErrorCases, test_valid_userpass_auth_response)
{
    uint8_t data[] = {0x01, 0x00}; // Success
    uint32_t result = splitter->parse_username_password_auth_response(data, sizeof(data));
    CHECK_EQUAL(2, result);
}

TEST(SocksSplitterErrorCases, test_valid_connect_request_ipv4)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};
    uint32_t result = splitter->parse_connect_request(data, sizeof(data));
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_valid_connect_response_ipv4)
{
    uint8_t data[] = {0x05, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};
    uint32_t result = splitter->parse_connect_response(data, sizeof(data));
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_valid_socks4_request)
{
    uint8_t data[] = {0x04, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01, 0x00};
    uint32_t result = splitter->parse_socks4_request(data, sizeof(data));
    CHECK_EQUAL(9, result);
}

TEST(SocksSplitterErrorCases, test_valid_socks4_response)
{
    uint8_t data[] = {0x00, 0x5A, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01};
    uint32_t result = splitter->parse_socks4_response(data, sizeof(data));
    CHECK_EQUAL(8, result);
}

TEST(SocksSplitterErrorCases, test_bind_reverse_auth_response_state)
{
    uint8_t data[] = {0x05, 0x01, 0x00};  // Auth negotiation with 1 method
    uint32_t result = splitter->parse_client_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    CHECK_EQUAL(3, result);
}

TEST(SocksSplitterErrorCases, test_bind_reverse_auth_negotiation_state)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};  // Connect request
    uint32_t result = splitter->parse_client_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_bind_reverse_connect_request_state)
{
    uint8_t data[] = {0x05, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};  // Connect response
    uint32_t result = splitter->parse_client_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_bind_reverse_connect_response_state)
{
    uint8_t data[] = {0x05, 0x01, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};  // Connect request
    uint32_t result = splitter->parse_client_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_CONNECT_RESPONSE);
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_default_state_returns_zero)
{
    uint8_t data[] = {0x05, 0x01};
    uint32_t result = splitter->parse_client_packet(data, sizeof(data), static_cast<SocksState>(999));
    CHECK_EQUAL(0, result);
}

TEST(SocksSplitterErrorCases, test_server_connect_request_state)
{
    uint8_t data[] = {0x05, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};  // Connect response
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_V5_CONNECT_REQUEST);
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_server_bind_reverse_auth_negotiation_state)
{
    uint8_t data[] = {0x05, 0x00};  // Auth response
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
    CHECK_EQUAL(2, result);
}

TEST(SocksSplitterErrorCases, test_server_bind_reverse_auth_response_state)
{
    uint8_t data[] = {0x05, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};  // Connect response
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_server_bind_reverse_connect_request_state)
{
    uint8_t data[] = {0x05, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x50};  // Connect response
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
    CHECK_EQUAL(10, result);
}

TEST(SocksSplitterErrorCases, test_server_bind_reverse_connect_response_state)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_V5_BIND_REVERSE_CONNECT_RESPONSE);
    CHECK_EQUAL(5, result);  // Returns len
}

TEST(SocksSplitterErrorCases, test_server_established_state)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_ESTABLISHED);
    CHECK_EQUAL(5, result);  // Returns len
}

TEST(SocksSplitterErrorCases, test_server_error_state)
{
    uint8_t data[] = {0x01, 0x02, 0x03};
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), SOCKS_STATE_ERROR);
    CHECK_EQUAL(3, result);  // Returns len
}

TEST(SocksSplitterErrorCases, test_server_default_state_returns_zero)
{
    uint8_t data[] = {0x05, 0x01};
    uint32_t result = splitter->parse_server_packet(data, sizeof(data), static_cast<SocksState>(999));
    CHECK_EQUAL(0, result);
}

// Main test runner
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
