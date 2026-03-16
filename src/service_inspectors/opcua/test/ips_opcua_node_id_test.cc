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

// ips_opcua_node_id_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_opcua_mock.h"
#include "../ips_opcua_node_id.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(IpsOpcuaNodeIdTest)
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

// Test ips_opcua_node_id: Validates detection of specific OPC UA node IDs within MSG packets.
// Tests numeric node ID matching for both client and server directions, ensuring the packet
// contains a MSG type before attempting node ID comparison. Only processes MSG PDUs since
// node IDs are specific to OPC UA service calls, not protocol control messages.
TEST(IpsOpcuaNodeIdTest, node_id_detection_comprehensive_test)
{
    OpcuaNodeIdOption opcua_node_id(OPCUA_MSG_SERVICE_GET_ENDPOINTS_REQUEST);
    Cursor c; Packet p(true);

    // Test case 1: Packet with no flow context should not match
    // Node ID detection requires valid flow data with session information
    p.flow = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_node_id.eval(c, &p));

    // Test case 2: Packet with incomplete PDU should not match
    // Node ID extraction requires complete message structure
    snort::Flow f; p.flow = &f;
    p.packet_flags = 0;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_node_id.eval(c, &p));

    // Test case 3: Packet without clear direction should not match
    // Directional context needed to access correct session data
    p.packet_flags = PKT_PDU_FULL;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_node_id.eval(c, &p));

    // Test case 4: Client packet with non-MSG type should not match
    // Node ID detection only works on MSG PDUs, not control messages (HEL, ACK, etc.)
    p.packet_flags |= PKT_FROM_CLIENT;
    ofd->client_ssn_data.msg_type = OPCUA_MSG_HEL;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_node_id.eval(c, &p));

    // Test case 5: MSG packet with non-matching node ID should not match
    // Testing with different node ID value than expected
    ofd->client_ssn_data.msg_type = OPCUA_MSG_MSG;
    ofd->client_ssn_data.node_id = OPCUA_MSG_SERVICE_REGISTER_SERVER_REQUEST;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_node_id.eval(c, &p));

    // Test case 6: MSG packet with matching node ID should match
    // Valid MSG PDU with correct node ID should trigger detection
    ofd->client_ssn_data.node_id = OPCUA_MSG_SERVICE_GET_ENDPOINTS_REQUEST;
    CHECK_EQUAL(IpsOption::MATCH, opcua_node_id.eval(c, &p));

    // Test case 7: Server packet with matching conditions should match
    // Verify same logic applies to server-side packets
    p.packet_flags &= ~PKT_FROM_CLIENT;
    p.packet_flags |= PKT_FROM_SERVER;
    ofd->server_ssn_data.msg_type = OPCUA_MSG_MSG;
    ofd->server_ssn_data.node_id = OPCUA_MSG_SERVICE_GET_ENDPOINTS_REQUEST;
    CHECK_EQUAL(IpsOption::MATCH, opcua_node_id.eval(c, &p));

    // Test case 8: No flow data should result in no match
    // Simulates cleanup or invalid flow state
    delete ofd;
    ofd = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_node_id.eval(c, &p));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
