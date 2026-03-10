//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_flow_data_test.cc author Raza Shafiq <rshafiq@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/socks/socks_flow_data.h"
#include "service_inspectors/socks/socks_module.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#undef malloc
#undef free
#undef calloc
#undef realloc

using namespace snort;

// Stubs for linking
namespace snort
{
FlowData::FlowData(unsigned u) : id(u)
{ }
FlowData::~FlowData() = default;

unsigned FlowData::flow_data_id = 0;
unsigned FlowData::create_flow_data_id()
{ return ++flow_data_id; }

void* snort_alloc(size_t sz)
{ return malloc(sz); }

char* snort_strdup(const char* s)
{
    size_t len = strlen(s) + 1;
    char* dup = new char[len];
    memcpy(dup, s, len);
    return dup;
}
}

THREAD_LOCAL SocksStats socks_stats = {};

//-------------------------------------------------------------------------
// SocksAddress Tests
//-------------------------------------------------------------------------

TEST_GROUP(socks_address_test)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksAddress* addr = nullptr;

    void setup() override
    {
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        addr = new SocksAddress();
    }

    void teardown() override
    {
        delete addr;
    }
};

TEST(socks_address_test, constructor_defaults)
{
    CHECK_EQUAL(SOCKS_ATYP_IPV4, addr->type);
    CHECK_EQUAL(0, addr->port);
    CHECK_TRUE(addr->address.empty());
    CHECK_TRUE(addr->cached_ip == nullptr);
    CHECK_FALSE(addr->is_set());
}

TEST(socks_address_test, set_domain_address)
{
    addr->set("example.com", SOCKS_ATYP_DOMAIN, 80);

    CHECK_EQUAL(SOCKS_ATYP_DOMAIN, addr->type);
    CHECK_EQUAL(80, addr->port);
    CHECK_EQUAL(std::string("example.com"), addr->address);
    CHECK_TRUE(addr->cached_ip == nullptr);
    CHECK_TRUE(addr->is_set());

    // Domain names don't convert to IP
    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr == nullptr);
}

TEST(socks_address_test, set_ipv4_string)
{
    addr->set("192.168.1.100", SOCKS_ATYP_IPV4, 443);

    CHECK_EQUAL(SOCKS_ATYP_IPV4, addr->type);
    CHECK_EQUAL(443, addr->port);
    CHECK_EQUAL(std::string("192.168.1.100"), addr->address);
    CHECK_TRUE(addr->cached_ip == nullptr);
    CHECK_TRUE(addr->is_set());

    // Lazy IP conversion
    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr != nullptr);
    CHECK_TRUE(addr->cached_ip != nullptr);
    CHECK_TRUE(ip_ptr->is_ip4());
}

TEST(socks_address_test, set_ipv6_string)
{
    addr->set("2001:db8::1", SOCKS_ATYP_IPV6, 8080);

    CHECK_EQUAL(SOCKS_ATYP_IPV6, addr->type);
    CHECK_EQUAL(8080, addr->port);
    CHECK_EQUAL(std::string("2001:db8::1"), addr->address);
    CHECK_TRUE(addr->cached_ip == nullptr);

    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr != nullptr);
    CHECK_TRUE(addr->cached_ip != nullptr);
    CHECK_TRUE(ip_ptr->is_ip6());
}

TEST(socks_address_test, set_from_binary_ipv4)
{
    SfIp test_ip;
    test_ip.set("10.0.0.1");

    addr->set(test_ip, 1080);

    CHECK_EQUAL(SOCKS_ATYP_IPV4, addr->type);
    CHECK_EQUAL(1080, addr->port);
    CHECK_EQUAL(std::string("10.0.0.1"), addr->address);
    CHECK_TRUE(addr->cached_ip != nullptr);

    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr != nullptr);
    CHECK_TRUE(ip_ptr->is_ip4());
}

TEST(socks_address_test, set_from_binary_ipv6)
{
    SfIp test_ip;
    test_ip.set("fe80::1");
    
    addr->set(test_ip, 9050);
    
    CHECK_EQUAL(SOCKS_ATYP_IPV6, addr->type);
    CHECK_EQUAL(9050, addr->port);
    CHECK_TRUE(addr->address.find("fe80") != std::string::npos);
    CHECK_TRUE(addr->cached_ip != nullptr);
    
    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr != nullptr);
    CHECK_TRUE(ip_ptr->is_ip6());
}

TEST(socks_address_test, clear_address)
{
    addr->set("192.168.1.1", SOCKS_ATYP_IPV4, 80);
    addr->get_ip(); // Cache the IP
    CHECK_TRUE(addr->cached_ip != nullptr);
    
    addr->clear();
    
    CHECK_TRUE(addr->address.empty());
    CHECK_EQUAL(0, addr->port);
    CHECK_EQUAL(SOCKS_ATYP_IPV4, addr->type);
    CHECK_TRUE(addr->cached_ip == nullptr);
    CHECK_FALSE(addr->is_set());
}

TEST(socks_address_test, ip_caching_mechanism)
{
    addr->set("172.16.0.1", SOCKS_ATYP_IPV4, 22);

    // First call should cache
    CHECK_TRUE(addr->cached_ip == nullptr);
    auto ip_ptr1 = addr->get_ip();
    CHECK_TRUE(ip_ptr1 != nullptr);
    CHECK_TRUE(addr->cached_ip != nullptr);

    // Second call should return cached value
    auto ip_ptr2 = addr->get_ip();
    CHECK_TRUE(ip_ptr2 != nullptr);
    // Both should have the same cached value
}

TEST(socks_address_test, invalid_ip_string)
{
    addr->set("not.an.ip.address", SOCKS_ATYP_IPV4, 80);
    
    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr == nullptr);
    CHECK_TRUE(addr->cached_ip == nullptr);
}

TEST(socks_address_test, port_boundaries)
{
    addr->set("10.0.0.1", SOCKS_ATYP_IPV4, 0);
    CHECK_EQUAL(0, addr->port);
    
    addr->set("10.0.0.1", SOCKS_ATYP_IPV4, 65535);
    CHECK_EQUAL(65535, addr->port);
}

TEST(socks_address_test, loopback_addresses)
{
    // IPv4 loopback
    addr->set("127.0.0.1", SOCKS_ATYP_IPV4, 1080);
    auto ip_ptr4 = addr->get_ip();
    CHECK_TRUE(ip_ptr4 != nullptr);
    CHECK_TRUE(ip_ptr4->is_ip4());
    
    // IPv6 loopback
    addr->clear();
    addr->set("::1", SOCKS_ATYP_IPV6, 1080);
    auto ip_ptr6 = addr->get_ip();
    CHECK_TRUE(ip_ptr6 != nullptr);
    CHECK_TRUE(ip_ptr6->is_ip6());
}

TEST(socks_address_test, ipv4_mapped_ipv6)
{
    addr->set("::ffff:192.168.1.1", SOCKS_ATYP_IPV6, 80);
    
    auto ip_ptr = addr->get_ip();
    CHECK_TRUE(ip_ptr != nullptr);
}

//-------------------------------------------------------------------------
// SocksFlowData Tests
//-------------------------------------------------------------------------

TEST_GROUP(socks_flow_data_test)
{
    // cppcheck-suppress constVariablePointer ; false positive - reassigned in setup()
    SocksFlowData* flow_data = nullptr;

    void setup() override
    {
        SocksFlowData::init();
        // cppcheck-suppress unreadVariable ; false positive - used in tests
        flow_data = new SocksFlowData();
    }

    void teardown() override
    {
        delete flow_data;
    }
};

TEST(socks_flow_data_test, constructor_initialization)
{
    CHECK_EQUAL(SOCKS_STATE_INIT, flow_data->get_state());
    CHECK_EQUAL(SOCKS_DIR_CLIENT_TO_SERVER, flow_data->get_direction());
    CHECK_EQUAL(0, flow_data->get_socks_version());
    CHECK_FALSE(flow_data->is_socks4a());
    CHECK_EQUAL(SOCKS5_AUTH_NONE, flow_data->get_auth_method());
    CHECK_EQUAL(SOCKS_CMD_CONNECT, flow_data->get_command());
    CHECK_EQUAL(0, flow_data->get_request_count());
    CHECK_EQUAL(0, flow_data->get_response_count());
    CHECK_EQUAL(SOCKS5_REP_SUCCESS, flow_data->get_last_error());
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
}

TEST(socks_flow_data_test, direction_toggle)
{
    CHECK_EQUAL(SOCKS_DIR_CLIENT_TO_SERVER, flow_data->get_direction());
    
    flow_data->set_direction(SOCKS_DIR_SERVER_TO_CLIENT);
    CHECK_EQUAL(SOCKS_DIR_SERVER_TO_CLIENT, flow_data->get_direction());
    
    flow_data->set_direction(SOCKS_DIR_CLIENT_TO_SERVER);
    CHECK_EQUAL(SOCKS_DIR_CLIENT_TO_SERVER, flow_data->get_direction());
}

TEST(socks_flow_data_test, socks4a_flag)
{
    CHECK_FALSE(flow_data->is_socks4a());
    
    flow_data->set_socks4a(true);
    CHECK_TRUE(flow_data->is_socks4a());
    
    flow_data->set_socks4a(false);
    CHECK_FALSE(flow_data->is_socks4a());
}

TEST(socks_flow_data_test, target_operations)
{
    flow_data->set_target("example.com", SOCKS_ATYP_DOMAIN, 80);
    
    CHECK_EQUAL(std::string("example.com"), flow_data->get_target_address());
    CHECK_EQUAL(SOCKS_ATYP_DOMAIN, flow_data->get_address_type());
    CHECK_EQUAL(80, flow_data->get_target_port());
}

TEST(socks_flow_data_test, target_ip_operations)
{
    SfIp test_ip;
    test_ip.set("203.0.113.50");
    
    flow_data->set_target_ip(test_ip);
    
    auto retrieved_ip = flow_data->get_target_ip();
    CHECK_TRUE(retrieved_ip != nullptr);
    CHECK_TRUE(retrieved_ip->is_ip4());
}

TEST(socks_flow_data_test, bind_operations)
{
    flow_data->set_bind("192.168.1.1", SOCKS_ATYP_IPV4, 9050);
    
    CHECK_EQUAL(std::string("192.168.1.1"), flow_data->get_bind_address());
    CHECK_EQUAL(SOCKS_ATYP_IPV4, flow_data->get_bind_address_type());
    CHECK_EQUAL(9050, flow_data->get_bind_port());
}

TEST(socks_flow_data_test, bind_ip_operations)
{
    SfIp test_ip;
    test_ip.set("172.16.0.1");
    
    flow_data->set_bind_ip(test_ip);
    
    auto retrieved_ip = flow_data->get_bind_ip();
    CHECK_TRUE(retrieved_ip != nullptr);
    CHECK_TRUE(retrieved_ip->is_ip4());
}

TEST(socks_flow_data_test, counter_overflow_behavior)
{
    // Test counter behavior near max values
    for (unsigned i = 0; i < 100; i++)
        flow_data->increment_request_count();
    
    CHECK_EQUAL(100, flow_data->get_request_count());
}

TEST(socks_flow_data_test, handoff_flags)
{
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
    
    flow_data->set_handoff_pending(true);
    CHECK_TRUE(flow_data->is_handoff_pending());
    
    flow_data->set_handoff_completed(true);
    CHECK_TRUE(flow_data->is_handoff_completed());
    
    flow_data->set_handoff_pending(false);
    flow_data->set_handoff_completed(false);
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
}

TEST(socks_flow_data_test, userid_operations)
{
    CHECK_TRUE(flow_data->get_userid().empty());
    
    flow_data->set_userid("testuser");
    CHECK_EQUAL(std::string("testuser"), flow_data->get_userid());
    
    flow_data->set_userid("admin123");
    CHECK_EQUAL(std::string("admin123"), flow_data->get_userid());
    
    flow_data->set_userid("");
    CHECK_TRUE(flow_data->get_userid().empty());
}

TEST(socks_flow_data_test, inspector_id_consistency)
{
    unsigned id1 = SocksFlowData::get_inspector_id();
    unsigned id2 = SocksFlowData::get_inspector_id();
    
    CHECK_EQUAL(id1, id2);
    CHECK(id1 > 0);
}

//-------------------------------------------------------------------------
// Integration Tests - Complex Scenarios
//-------------------------------------------------------------------------

TEST(socks_flow_data_test, socks5_connect_complete_workflow)
{
    // Simulate complete SOCKS5 CONNECT workflow
    flow_data->set_socks_version(SOCKS5_VERSION);
    flow_data->set_state(SOCKS_STATE_V5_AUTH_NEGOTIATION);
    flow_data->set_auth_method(SOCKS5_AUTH_NONE);
    flow_data->increment_request_count();
    
    flow_data->set_state(SOCKS_STATE_V5_CONNECT_REQUEST);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target("example.com", SOCKS_ATYP_DOMAIN, 80);
    flow_data->increment_request_count();
    
    flow_data->set_state(SOCKS_STATE_V5_CONNECT_RESPONSE);
    flow_data->set_direction(SOCKS_DIR_SERVER_TO_CLIENT);
    flow_data->increment_response_count();
    
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_handoff_pending(true);
    
    // Verify final state
    CHECK_EQUAL(SOCKS5_VERSION, flow_data->get_socks_version());
    CHECK_EQUAL(SOCKS_STATE_ESTABLISHED, flow_data->get_state());
    CHECK_EQUAL(SOCKS_CMD_CONNECT, flow_data->get_command());
    CHECK_EQUAL(std::string("example.com"), flow_data->get_target_address());
    CHECK_EQUAL(80, flow_data->get_target_port());
    CHECK_EQUAL(2, flow_data->get_request_count());
    CHECK_EQUAL(1, flow_data->get_response_count());
    CHECK_TRUE(flow_data->is_handoff_pending());
}

TEST(socks_flow_data_test, socks5_udp_associate_workflow)
{
    flow_data->set_socks_version(SOCKS5_VERSION);
    flow_data->set_command(SOCKS_CMD_UDP_ASSOCIATE);
    flow_data->set_target("0.0.0.0", SOCKS_ATYP_IPV4, 0);
    flow_data->set_bind("10.0.0.1", SOCKS_ATYP_IPV4, 5060);
    
    CHECK_EQUAL(SOCKS_CMD_UDP_ASSOCIATE, flow_data->get_command());
}

TEST(socks_flow_data_test, socks4a_domain_workflow)
{
    flow_data->set_socks_version(SOCKS4_VERSION);
    flow_data->set_socks4a(true);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target("example.org", SOCKS_ATYP_DOMAIN, 443);
    flow_data->set_userid("anonymous");
    
    CHECK_TRUE(flow_data->is_socks4a());
    CHECK_EQUAL(std::string("example.org"), flow_data->get_target_address());
    CHECK_EQUAL(443, flow_data->get_target_port());
}

TEST(socks_flow_data_test, username_password_auth_workflow)
{
    flow_data->set_socks_version(SOCKS5_VERSION);
    flow_data->set_state(SOCKS_STATE_V5_AUTH_NEGOTIATION);
    flow_data->set_auth_method(SOCKS5_AUTH_USERNAME_PASSWORD);
    flow_data->increment_request_count();
    
    flow_data->set_state(SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH);
    flow_data->set_userid("secureuser");
    flow_data->increment_request_count();
    
    flow_data->set_state(SOCKS_STATE_V5_CONNECT_REQUEST);
    flow_data->increment_request_count();
    
    CHECK_EQUAL(SOCKS5_AUTH_USERNAME_PASSWORD, flow_data->get_auth_method());
    CHECK_EQUAL(std::string("secureuser"), flow_data->get_userid());
    CHECK_EQUAL(3, flow_data->get_request_count());
}

TEST(socks_flow_data_test, ipv6_target_workflow)
{
    SfIp ipv6_target;
    ipv6_target.set("2001:db8:85a3::8a2e:370:7334");
    
    flow_data->set_socks_version(SOCKS5_VERSION);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target_ip(ipv6_target);
    flow_data->set_target_port(443);
    
    auto retrieved_ip = flow_data->get_target_ip();
    CHECK_TRUE(retrieved_ip != nullptr);
    CHECK_TRUE(retrieved_ip->is_ip6());
    CHECK_EQUAL(SOCKS_ATYP_IPV6, flow_data->get_address_type());
}

TEST(socks_flow_data_test, handoff_lifecycle)
{
    // Test complete handoff lifecycle
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
    
    // Connection established, ready for handoff
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_handoff_pending(true);
    CHECK_TRUE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
    
    // Handoff completed
    flow_data->set_handoff_completed(true);
    CHECK_TRUE(flow_data->is_handoff_completed());
}

TEST(socks_flow_data_test, empty_target_address)
{
    // Test behavior with empty target
    CHECK_TRUE(flow_data->get_target_address().empty());
    CHECK_EQUAL(0, flow_data->get_target_port());
    
    auto ip_ptr = flow_data->get_target_ip();
    CHECK_TRUE(ip_ptr == nullptr);
}

TEST(socks_flow_data_test, empty_bind_address)
{
    // Test behavior with empty bind
    CHECK_TRUE(flow_data->get_bind_address().empty());
    CHECK_EQUAL(0, flow_data->get_bind_port());
    
    auto ip_ptr = flow_data->get_bind_ip();
    CHECK_TRUE(ip_ptr == nullptr);
}

TEST(socks_flow_data_test, all_address_types)
{
    const SocksAddressType types[] = {
        SOCKS_ATYP_IPV4,
        SOCKS_ATYP_DOMAIN,
        SOCKS_ATYP_IPV6
    };
    
    for (auto type : types)
    {
        flow_data->set_address_type(type);
        CHECK_EQUAL(type, flow_data->get_address_type());
    }
}

TEST(socks_flow_data_test, stress_test_counters)
{
    // Stress test with large counter values
    for (unsigned i = 0; i < 10000; i++)
    {
        flow_data->increment_request_count();
        if (i % 2 == 0)
            flow_data->increment_response_count();
    }
    
    CHECK_EQUAL(10000, flow_data->get_request_count());
    CHECK_EQUAL(5000, flow_data->get_response_count());
}

TEST(socks_flow_data_test, private_ip_ranges)
{
    // Test with various private IP ranges
    const char* private_ips[] = {
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1"
    };
    
    for (const char* const ip_str : private_ips)
    {
        SfIp test_ip;
        test_ip.set(ip_str);
        flow_data->set_target_ip(test_ip);
        
        auto retrieved_ip = flow_data->get_target_ip();
        CHECK_TRUE(retrieved_ip != nullptr);
        CHECK_TRUE(retrieved_ip->is_ip4());
    }
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
