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

// ips_opcua_msg_service_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_opcua_mock.h"
#include "../ips_opcua_msg_service.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(IpsOpcuaTest)
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

// Test ips_opcua_msg_service: Validates detection of specific OPC UA message service types
// within MSG PDUs. Tests both client and server directions, ensuring proper validation
// of message type, namespace index, and node ID matching.
TEST(IpsOpcuaTest, msg_service_detection_test)
{
    OpcuaMsgServiceOption opcua_ips(OPCUA_MSG_SERVICE_TEST_UNION);
    Cursor c; Packet p(true); 

    // Test case 1: Packet with no flow context should not match
    // This ensures the rule doesn't trigger on malformed traffic
    p.flow = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 2: Packet with incomplete PDU should not match
    // OPC UA service detection requires complete protocol data units
    snort::Flow f; p.flow = &f;
    p.packet_flags = 0;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 3: Packet without clear direction (client/server) should not match
    // OPC UA inspection requires directional context for proper analysis
    p.packet_flags = PKT_PDU_FULL;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 4: Client packet with incorrect message type should not match
    // msg_service detection only works on MSG type PDUs, not HEL/ACK/etc.
    p.packet_flags |= PKT_FROM_CLIENT;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 5: MSG packet with non-default namespace index should not match
    // Service detection is limited to default namespace (index 0) for standard services
    ofd->client_ssn_data.msg_type = OPCUA_MSG_MSG;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 6: Valid message type and namespace but wrong node ID should not match
    // The specific service node ID must match the configured detection value
    ofd->client_ssn_data.node_namespace_index = OPCUA_DEFAULT_NAMESPACE_INDEX;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 7: Valid client packet with all correct attributes should match
    // Complete MSG PDU with default namespace and matching service node ID
    ofd->client_ssn_data.node_id = OPCUA_MSG_SERVICE_TEST_UNION;
    CHECK_EQUAL(IpsOption::MATCH, opcua_ips.eval(c, &p));

    // Test case 8: Server packet validation follows same logic as client
    // Switch to server direction and verify same validation sequence
    p.packet_flags &= ~PKT_FROM_CLIENT;
    p.packet_flags |= PKT_FROM_SERVER;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 9: Server packet needs MSG type for service detection
    ofd->server_ssn_data.msg_type = OPCUA_MSG_MSG;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 10: Server packet needs default namespace index
    ofd->server_ssn_data.node_namespace_index = OPCUA_DEFAULT_NAMESPACE_INDEX;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));

    // Test case 11: Valid server packet with matching service node ID should match
    ofd->server_ssn_data.node_id = OPCUA_MSG_SERVICE_TEST_UNION;
    CHECK_EQUAL(IpsOption::MATCH, opcua_ips.eval(c, &p));

    // Test case 12: No flow data should result in no match
    // Simulates cleanup or invalid flow state
    delete ofd;
    ofd = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_ips.eval(c, &p));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}