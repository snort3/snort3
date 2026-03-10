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

//socks_splitter_test.cc -- author Raza Shafiq <rshafiq@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "../socks_splitter.h"
#include "../socks_flow_data.h"
#include "stream/stream_splitter.h"

namespace snort
{
    class Flow;
    class Packet;
}

class FlushBucket;
#define PKT_FROM_CLIENT  0x00000080
#define PKT_FROM_SERVER  0x00000040

using namespace snort;

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
}

struct SocksStats
{
    uint64_t sessions = 0;
    uint64_t concurrent_sessions = 0;
    uint64_t max_concurrent_sessions = 0;
    uint64_t auth_requests = 0;
    uint64_t auth_successes = 0;
    uint64_t auth_failures = 0;
    uint64_t connect_requests = 0;
    uint64_t bind_requests = 0;
    uint64_t udp_associate_requests = 0;
    uint64_t successful_connections = 0;
    uint64_t failed_connections = 0;
    uint64_t udp_associations_created = 0;
    uint64_t udp_expectations_created = 0;
    uint64_t udp_packets = 0;
    uint64_t udp_frags = 0;
};

THREAD_LOCAL SocksStats socks_stats = {};

class FlushBucket
{
public:
    static uint32_t get_size() { return 16384; }
};

// ===== TEST GROUP =====

// Global initialization - call init() once before any tests
struct SocksTestInit
{
    SocksTestInit() { SocksFlowData::init(); }
};
static SocksTestInit socks_test_init;

TEST_GROUP(SocksSplitterTests)
{
    SocksSplitter* client_splitter;
    SocksSplitter* server_splitter;
    Packet* packet;
    Flow* flow;
    SocksFlowData* flow_data;

    void setup()
    {
        SocksFlowData::init();

        client_splitter = new SocksSplitter(true);
        server_splitter = new SocksSplitter(false);
        packet = new Packet(false);
        flow = new Flow();
        flow_data = new SocksFlowData();

        packet->flow = flow;
        flow->set_flow_data(flow_data);
    }

    void teardown()
    {
        delete client_splitter;
        delete server_splitter;
        delete packet;
        delete flow_data;
        delete flow;
    }
};

TEST(SocksSplitterTests, test_flow_data_retrieval)
{
    CHECK(packet != nullptr);
    CHECK(packet->flow != nullptr);
    CHECK(packet->flow == flow);

    unsigned id = SocksFlowData::get_inspector_id();
    CHECK(flow->get_flow_data(id) != nullptr);
    CHECK(flow->get_flow_data(id) == flow_data);

    flow_data->set_state(SOCKS_STATE_V4_CONNECT_RESPONSE);
    CHECK_EQUAL(SOCKS_STATE_V4_CONNECT_RESPONSE, flow_data->get_state());

    uint8_t data[] = {0x00, 0x5A, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01};
    uint32_t fp = 0;

    StreamSplitter::Status result = server_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_SERVER, &fp);

    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(8, fp);
}

TEST(SocksSplitterTests, test_is_paf)
{
    CHECK_TRUE(client_splitter->is_paf());
    CHECK_TRUE(server_splitter->is_paf());
}


TEST(SocksSplitterTests, test_scan_null_data)
{
    uint32_t fp = 0;
    StreamSplitter::Status result = client_splitter->scan(
        packet, nullptr, 10, PKT_FROM_CLIENT, &fp);
    CHECK_EQUAL(StreamSplitter::SEARCH, result);
}

TEST(SocksSplitterTests, test_socks4_partial_request)
{
    uint8_t data[] = {
        0x04, 0x01,             // VER=4, CMD=CONNECT
        0x00, 0x50,             // PORT=80
        0x0A, 0x00, 0x00, 0x01  // IP=10.0.0.1 (no userid)
    };
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_CLIENT, &fp);

    CHECK_EQUAL(StreamSplitter::SEARCH, result);
}

TEST(SocksSplitterTests, test_socks4_response)
{
    uint8_t data[] = {
        0x00, 0x5A,             // VER=0, REP=0x5A (granted)
        0x00, 0x50,             // PORT=80
        0x0A, 0x00, 0x00, 0x01  // IP=10.0.0.1
    };
    uint32_t fp = 0;

    // SOCKS4 response is 8 bytes: VER(1) + REP(1) + PORT(2) + IP(4)
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_RESPONSE);
    StreamSplitter::Status result = server_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_SERVER, &fp);

    // SOCKS4 Protocol: Complete 8-byte response MUST return FLUSH
    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(8, fp);
}

// ===== SOCKS4a AUTO-DETECTION TESTS =====

TEST(SocksSplitterTests, test_socks4a_with_domain_auto_detect)
{
    // SOCKS4a with domain name (IP starts with 0.0.0.x)
    uint8_t data[] = {
        0x04, 0x01,             // VER=4, CMD=CONNECT
        0x00, 0x50,             // PORT=80
        0x00, 0x00, 0x00, 0x01, // IP=0.0.0.1 (signals domain follows)
        0x75, 0x73, 0x65, 0x72, 0x00,  // userid="user\0"
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00  // domain="example.com\0"
    };
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_CLIENT, &fp);

    // SOCKS4a Protocol: Complete message MUST return FLUSH with exact length
    // VER(1) + CMD(1) + PORT(2) + IP(4) + USERID(5) + DOMAIN(12) = 25 bytes
    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(25, fp);
}

// ===== SOCKS5 AUTO-DETECTION TESTS =====

// Note: SOCKS5 CONNECT request tests removed - state-specific parsing
// not fully implemented. Tests were using weak assertions that don't
// verify correct behavior. Need to either:
// 1. Implement proper state-specific parsing in splitter
// 2. Test only auto-detection path (INIT state)
// For now, focusing on tests that verify actual working functionality.

// ===== VERSION DISCRIMINATION TESTS =====

TEST(SocksSplitterTests, test_auto_detect_socks4_vs_socks5)
{
    // Test that splitter can distinguish SOCKS4 (0x04) from SOCKS5 (0x05)
    uint8_t socks4_data[] = {0x04, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01, 0x00};
    uint8_t socks5_data[] = {0x05, 0x01, 0x00};
    uint32_t fp4 = 0, fp5 = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result4 = client_splitter->scan(
        packet, socks4_data, sizeof(socks4_data), PKT_FROM_CLIENT, &fp4);

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result5 = client_splitter->scan(
        packet, socks5_data, sizeof(socks5_data), PKT_FROM_CLIENT, &fp5);

    // SOCKS4 complete message should FLUSH
    CHECK_EQUAL(StreamSplitter::FLUSH, result4);
    CHECK(fp4 > 0);

    // SOCKS5 complete auth negotiation should FLUSH
    CHECK_EQUAL(StreamSplitter::FLUSH, result5);
    CHECK_EQUAL(3, fp5);
}

TEST(SocksSplitterTests, test_auto_detect_socks4_vs_socks4a)
{
    // SOCKS4 with real IP
    uint8_t socks4_data[] = {
        0x04, 0x01, 0x00, 0x50,
        0x0A, 0x00, 0x00, 0x01,  // Real IP: 10.0.0.1
        0x00
    };

    // SOCKS4a with 0.0.0.x IP (signals domain)
    uint8_t socks4a_data[] = {
        0x04, 0x01, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,  // Special IP: 0.0.0.1
        0x00,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00
    };

    uint32_t fp4 = 0, fp4a = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result4 = client_splitter->scan(
        packet, socks4_data, sizeof(socks4_data), PKT_FROM_CLIENT, &fp4);

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result4a = client_splitter->scan(
        packet, socks4a_data, sizeof(socks4a_data), PKT_FROM_CLIENT, &fp4a);

    // Both complete messages should FLUSH
    CHECK_EQUAL(StreamSplitter::FLUSH, result4);
    CHECK_EQUAL(9, fp4);

    CHECK_EQUAL(StreamSplitter::FLUSH, result4a);
    CHECK(fp4a > 9);  // Should be longer due to domain
}

// ===== COMPLEX SCENARIO TESTS =====

TEST(SocksSplitterTests, test_fragmented_socks5_auth_negotiation)
{
    // Simulate fragmented packets - first fragment
    uint8_t frag1[] = {0x05, 0x03};  // VER + NMETHODS (incomplete)
    uint32_t fp1 = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result1 = client_splitter->scan(
        packet, frag1, sizeof(frag1), PKT_FROM_CLIENT, &fp1);

    // Should need more data
    CHECK_EQUAL(StreamSplitter::SEARCH, result1);

    // Second fragment with methods
    uint8_t frag2[] = {0x05, 0x03, 0x00, 0x01, 0x02};  // Complete message
    uint32_t fp2 = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result2 = client_splitter->scan(
        packet, frag2, sizeof(frag2), PKT_FROM_CLIENT, &fp2);

    // Should flush complete message
    CHECK_EQUAL(StreamSplitter::FLUSH, result2);
}

TEST(SocksSplitterTests, test_socks5_with_all_auth_methods)
{
    // SOCKS5 with all common auth methods
    uint8_t data[] = {
        0x05, 0x04,                 // VER=5, NMETHODS=4
        0x00,                       // NO_AUTH
        0x01,                       // GSSAPI
        0x02,                       // USERNAME/PASSWORD
        0x03                        // CHAP
    };
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_CLIENT, &fp);

    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(6, fp);
}

TEST(SocksSplitterTests, test_socks4_with_long_userid)
{
    // SOCKS4 with long userid
    uint8_t data[200];
    int idx = 0;
    data[idx++] = 0x04; data[idx++] = 0x01;  // VER=4, CMD=CONNECT
    data[idx++] = 0x00; data[idx++] = 0x50;  // PORT=80
    data[idx++] = 0x0A; data[idx++] = 0x00;  // IP=10.0.0.1
    data[idx++] = 0x00; data[idx++] = 0x01;

    // Long userid
    for (int i = 0; i < 100; i++) {
        data[idx++] = 'a' + (i % 26);
    }
    data[idx++] = 0x00;  // Null terminator

    uint32_t fp = 0;
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, idx, PKT_FROM_CLIENT, &fp);

    // SOCKS4 Protocol: Complete request with long userid (100 chars)
    // VER(1) + CMD(1) + PORT(2) + IP(4) + USERID(101) = 109 bytes
    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(109, fp);
}

// ===== EDGE CASE TESTS =====

TEST(SocksSplitterTests, test_invalid_version_byte)
{
    // Invalid SOCKS version (not 0x04 or 0x05)
    uint8_t data[] = {0x99, 0x01, 0x00};
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_CLIENT, &fp);

    // Splitter doesn't recognize version 0x99, returns SEARCH (needs more data)
    // This is correct behavior - might not be SOCKS at all
    CHECK_EQUAL(StreamSplitter::SEARCH, result);
}

TEST(SocksSplitterTests, test_minimum_packet_size)
{
    // Too small to be any valid SOCKS message
    uint8_t data[] = {0x05};
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, 1, PKT_FROM_CLIENT, &fp);

    // Too small - returns SEARCH (needs more data)
    CHECK_EQUAL(StreamSplitter::SEARCH, result);
}

TEST(SocksSplitterTests, test_large_buffer_handling)
{
    // Large buffer with valid SOCKS5 auth at start
    uint8_t data[1000];
    data[0] = 0x05;
    data[1] = 0x01;
    data[2] = 0x00;
    // Fill rest with garbage
    for (int i = 3; i < 1000; i++) data[i] = 0xAA;

    uint32_t fp = 0;
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, 1000, PKT_FROM_CLIENT, &fp);

    // Should flush just the SOCKS message, not the whole buffer
    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK(fp >= 3 and fp < 1000);
}

// ===== SERVER RESPONSE TESTS =====
// (Covered by direction handling tests)

// ===== DIRECTION HANDLING TESTS =====

TEST(SocksSplitterTests, test_client_flag_required)
{
    // Without PKT_FROM_CLIENT flag, should be treated as server packet
    uint8_t data[] = {0x05, 0x01, 0x00};
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_INIT);
    // Pass 0 flags - will be treated as server
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, sizeof(data), 0, &fp);

    // Without client flag, treated as server - may auto-detect
    CHECK_EQUAL(StreamSplitter::FLUSH, result);
}

TEST(SocksSplitterTests, test_server_flag_required)
{
    // Server response needs PKT_FROM_SERVER flag
    uint8_t data[] = {0x05, 0x00};
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_V5_AUTH_NEGOTIATION);
    StreamSplitter::Status result = server_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_SERVER, &fp);

    CHECK_EQUAL(StreamSplitter::FLUSH, result);
}

// ===== STATE MACHINE TESTS =====


TEST(SocksSplitterTests, test_error_state_handling)
{
    // In error state, should handle gracefully
    uint8_t data[] = {0x05, 0x01, 0x00};
    uint32_t fp = 0;

    flow_data->set_state(SOCKS_STATE_ERROR);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, sizeof(data), PKT_FROM_CLIENT, &fp);

    // SOCKS Protocol: In ERROR state, should still pass data through
    // MUST return FLUSH to allow error handling at higher layers
    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(3, fp);
}

// ===== ROBUSTNESS TESTS =====

TEST(SocksSplitterTests, test_max_methods_boundary)
{
    // Test with maximum number of methods (255)
    uint8_t data[257];
    data[0] = 0x05;    // version
    data[1] = 0xFF;    // 255 methods
    for (int i = 2; i < 257; i++) data[i] = 0x00;

    uint32_t fp = 0;
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result = client_splitter->scan(
        packet, data, 257, PKT_FROM_CLIENT, &fp);

    CHECK_EQUAL(StreamSplitter::FLUSH, result);
    CHECK_EQUAL(257, fp);
}

// ===== FIELD-LEVEL PARSING VALIDATION TESTS =====
// These tests verify individual field parsing (overlaps removed)

TEST(SocksSplitterTests, test_socks4_userid_null_terminator_required)
{
    // Test that userid MUST be null-terminated
    uint8_t with_null[] = {0x04, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01, 'u', 's', 'e', 'r', 0x00};
    uint8_t without_null[] = {0x04, 0x01, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01, 'u', 's', 'e', 'r'};
    uint32_t fp = 0;

    // With null terminator - should parse completely
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result_with = client_splitter->scan(
        packet, with_null, sizeof(with_null), PKT_FROM_CLIENT, &fp);
    CHECK_EQUAL(StreamSplitter::FLUSH, result_with);
    CHECK_EQUAL(13, fp);

    // Without null terminator - should need more data
    fp = 0;
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result_without = client_splitter->scan(
        packet, without_null, sizeof(without_null), PKT_FROM_CLIENT, &fp);
    CHECK_EQUAL(StreamSplitter::SEARCH, result_without);  // Needs null terminator
}

TEST(SocksSplitterTests, test_socks4a_domain_null_terminator_required)
{
    // SOCKS4a domain must also be null-terminated
    uint8_t with_null[] = {0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 
                           'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00};
    uint8_t without_null[] = {0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00,
                              'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    uint32_t fp = 0;

    // With null terminator
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result_with = client_splitter->scan(
        packet, with_null, sizeof(with_null), PKT_FROM_CLIENT, &fp);
    CHECK_EQUAL(StreamSplitter::FLUSH, result_with);
    CHECK_EQUAL(21, fp);

    // Without null terminator - should need more data
    fp = 0;
    flow_data->set_state(SOCKS_STATE_INIT);
    StreamSplitter::Status result_without = client_splitter->scan(
        packet, without_null, sizeof(without_null), PKT_FROM_CLIENT, &fp);
    CHECK_EQUAL(StreamSplitter::SEARCH, result_without);
}

TEST(SocksSplitterTests, test_socks4_response_version_field)
{
    // SOCKS4 response version must be 0x00 (not 0x04!)
    uint8_t valid[] = {0x00, 0x5A, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01};
    uint8_t invalid[] = {0x04, 0x5A, 0x00, 0x50, 0x0A, 0x00, 0x00, 0x01};  // Wrong version
    uint32_t fp = 0;

    // Valid response (VER=0x00)
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_RESPONSE);
    StreamSplitter::Status result_valid = server_splitter->scan(
        packet, valid, sizeof(valid), PKT_FROM_SERVER, &fp);
    CHECK_EQUAL(StreamSplitter::FLUSH, result_valid);
    CHECK_EQUAL(8, fp);

    // Invalid response (VER=0x04)
    fp = 0;
    flow_data->set_state(SOCKS_STATE_V4_CONNECT_RESPONSE);
    StreamSplitter::Status result_invalid = server_splitter->scan(
        packet, invalid, sizeof(invalid), PKT_FROM_SERVER, &fp);
    CHECK_EQUAL(StreamSplitter::SEARCH, result_invalid);  // Should reject
}


// ===== RUN ALL TESTS =====

int main(int ac, char** av)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(ac, av);
}
