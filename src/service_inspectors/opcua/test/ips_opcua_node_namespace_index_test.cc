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

// ips_opcua_node_namespace_index_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_opcua_mock.h"
#include "../ips_opcua_node_namespace_index.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(IpsOpcuaNodeNamespaceIndexTest)
{
    void setup() override
    {
        ofd = new OpcuaFlowData();
        OpcuaFlowData::inspector_id = 1;
    }

    void teardown() override
    {
        if(ofd != nullptr)
        {
            delete ofd;
            ofd = nullptr;
        }
        mock().clear();
    }
};

// Test ips_opcua_node_namespace_index: Validates detection of specific namespace indexes
// within MSG packets. Tests uint8_t namespace index matching for both client and server
// directions, ensuring proper validation of message type before namespace comparison.
// Namespace 0 is reserved for OPC UA standard nodes, while higher indexes are for custom namespaces.
TEST(IpsOpcuaNodeNamespaceIndexTest, namespace_index_detection_comprehensive_test)
{
    OpcuaNodeNamespaceIndexOption opcua_namespace(OPCUA_DEFAULT_NAMESPACE_INDEX);
    Cursor c; Packet p(true);

    // Test case 1: Packet with no flow context should not match
    // Namespace index detection requires valid flow data structure
    p.flow = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_namespace.eval(c, &p));

    // Test case 2: Packet with incomplete PDU should not match
    // Namespace index is part of node addressing in complete messages
    snort::Flow f; p.flow = &f;
    p.packet_flags = 0;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_namespace.eval(c, &p));

    // Test case 3: Packet without clear direction should not match
    // Direction determines which session data to examine
    p.packet_flags = PKT_PDU_FULL;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_namespace.eval(c, &p));

    // Test case 4: Client packet with non-MSG type should not match
    // Namespace indexes only exist in MSG type OPC UA packets, not control messages
    p.packet_flags |= PKT_FROM_CLIENT;
    ofd->client_ssn_data.msg_type = OPCUA_MSG_OPN;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_namespace.eval(c, &p));

    // Test case 5: MSG packet with non-matching namespace index should not match
    // Testing with namespace index 1 when expecting default (0)
    ofd->client_ssn_data.msg_type = OPCUA_MSG_MSG;
    ofd->client_ssn_data.node_namespace_index = 1;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_namespace.eval(c, &p));

    // Test case 6: MSG packet with matching default namespace index should match
    // Valid MSG PDU with default namespace (0) should trigger detection
    ofd->client_ssn_data.node_namespace_index = OPCUA_DEFAULT_NAMESPACE_INDEX;
    CHECK_EQUAL(IpsOption::MATCH, opcua_namespace.eval(c, &p));

    // Test case 7: Server packet with matching conditions should match
    // Verify namespace detection works for server-side packets
    p.packet_flags &= ~PKT_FROM_CLIENT;
    p.packet_flags |= PKT_FROM_SERVER;
    ofd->server_ssn_data.msg_type = OPCUA_MSG_MSG;
    ofd->server_ssn_data.node_namespace_index = OPCUA_DEFAULT_NAMESPACE_INDEX;
    CHECK_EQUAL(IpsOption::MATCH, opcua_namespace.eval(c, &p));

    // Test case 8: No flow data should result in no match
    // Simulates cleanup or invalid flow state
    delete ofd;
    ofd = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_namespace.eval(c, &p));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}