//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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

// socks_handoff_test.cc author Raza Shafiq <rshafiq@cisco.com>

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
FlowData::FlowData(unsigned u) : id(u) {}
FlowData::~FlowData() = default;

unsigned FlowData::flow_data_id = 0;
unsigned FlowData::create_flow_data_id()
{ return ++flow_data_id; }

} // namespace snort

THREAD_LOCAL SocksStats socks_stats = {};

//-------------------------------------------------------------------------
// Handoff Tests
//-------------------------------------------------------------------------

TEST_GROUP(socks_handoff_test)
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

TEST(socks_handoff_test, initial_handoff_state)
{
    // Verify initial state
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
}

TEST(socks_handoff_test, handoff_lifecycle_connect)
{
    // Simulate CONNECT command handoff lifecycle
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    
    // Initial state
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
    
    // Set pending after connection established
    flow_data->set_handoff_pending(true);
    CHECK_TRUE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
    
    // Complete handoff
    flow_data->set_handoff_pending(false);
    flow_data->set_handoff_completed(true);
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_TRUE(flow_data->is_handoff_completed());
}

TEST(socks_handoff_test, no_handoff_for_bind)
{
    // BIND command should not trigger handoff
    flow_data->set_command(SOCKS_CMD_BIND);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
}

TEST(socks_handoff_test, no_handoff_for_udp_associate)
{
    // UDP_ASSOCIATE command should not trigger handoff
    flow_data->set_command(SOCKS_CMD_UDP_ASSOCIATE);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
}

TEST(socks_handoff_test, handoff_with_target_info)
{
    // Test handoff with target address information
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target("example.com", SOCKS_ATYP_DOMAIN, 443);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_handoff_pending(true);
    
    CHECK_TRUE(flow_data->is_handoff_pending());
    CHECK_EQUAL(std::string("example.com"), flow_data->get_target_address());
    CHECK_EQUAL(443, flow_data->get_target_port());
}

TEST(socks_handoff_test, socks4_connect_handoff)
{
    // Test SOCKS4 CONNECT handoff
    flow_data->set_socks_version(SOCKS4_VERSION);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target("10.0.0.1", SOCKS_ATYP_IPV4, 22);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_handoff_pending(true);
    
    CHECK_EQUAL(SOCKS4_VERSION, flow_data->get_socks_version());
    CHECK_TRUE(flow_data->is_handoff_pending());
}

TEST(socks_handoff_test, socks4a_connect_handoff)
{
    // Test SOCKS4a CONNECT handoff with domain
    flow_data->set_socks_version(SOCKS4_VERSION);
    flow_data->set_socks4a(true);
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target("ssh.example.com", SOCKS_ATYP_DOMAIN, 22);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_handoff_pending(true);
    
    CHECK_TRUE(flow_data->is_socks4a());
    CHECK_TRUE(flow_data->is_handoff_pending());
    CHECK_EQUAL(std::string("ssh.example.com"), flow_data->get_target_address());
}

TEST(socks_handoff_test, handoff_with_auth)
{
    // Test handoff after authentication
    flow_data->set_socks_version(SOCKS5_VERSION);
    flow_data->set_auth_method(SOCKS5_AUTH_USERNAME_PASSWORD);
    flow_data->set_userid("testuser");
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_target("secure.example.com", SOCKS_ATYP_DOMAIN, 443);
    flow_data->set_state(SOCKS_STATE_ESTABLISHED);
    flow_data->set_handoff_pending(true);
    
    CHECK_EQUAL(SOCKS5_AUTH_USERNAME_PASSWORD, flow_data->get_auth_method());
    CHECK_TRUE(flow_data->is_handoff_pending());
}

TEST(socks_handoff_test, handoff_with_error_state)
{
    // Test that handoff doesn't occur in error state
    flow_data->set_command(SOCKS_CMD_CONNECT);
    flow_data->set_state(SOCKS_STATE_ERROR);
    flow_data->set_last_error(SOCKS5_REP_CONNECTION_REFUSED);
    
    CHECK_FALSE(flow_data->is_handoff_pending());
    CHECK_FALSE(flow_data->is_handoff_completed());
}


int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
