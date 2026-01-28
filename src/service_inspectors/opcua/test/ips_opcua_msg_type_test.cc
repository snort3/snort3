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

// ips_opcua_msg_type_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_opcua_mock.h"
#include "../ips_opcua_msg_type.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>


TEST_GROUP(IpsOpcuaMsgTypeTest)
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

// Test ips_opcua_msg_type: Validates detection of OPC UA message types in packet headers.
// Tests all supported message types (HEL, ACK, ERR, RHE, OPN, MSG, CLO) and ensures
// proper directional matching for both client and server packets.
TEST(IpsOpcuaMsgTypeTest, message_type_detection_comprehensive_test)
{
    OpcuaMsgTypeOption opcua_msg_type(OPCUA_MSG_HEL);
    Cursor c; Packet p(true);

    // Test case 1: Packet with no flow context should not match
    // Message type detection requires valid flow data for context
    p.flow = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_msg_type.eval(c, &p));

    // Test case 2: Packet with incomplete PDU should not match
    // OPC UA message type is determined from complete protocol headers
    snort::Flow f; p.flow = &f;
    p.packet_flags = 0;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_msg_type.eval(c, &p));

    // Test case 3: Packet without clear direction should not match
    // Directional context is required for proper session data lookup
    p.packet_flags = PKT_PDU_FULL;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_msg_type.eval(c, &p));

    // Test case 4: Client packet with non-matching message type should not match
    // Testing with MSG type when expecting HEL type
    p.packet_flags |= PKT_FROM_CLIENT;
    ofd->client_ssn_data.msg_type = OPCUA_MSG_MSG;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_msg_type.eval(c, &p));

    // Test case 5: Client packet with matching HEL message type should match
    // Valid hello message from client should trigger detection
    ofd->client_ssn_data.msg_type = OPCUA_MSG_HEL;
    CHECK_EQUAL(IpsOption::MATCH, opcua_msg_type.eval(c, &p));

    // Test case 6: Server packet with matching message type should match
    // Switch to server direction and verify same message type matching
    p.packet_flags &= ~PKT_FROM_CLIENT;
    p.packet_flags |= PKT_FROM_SERVER;
    ofd->server_ssn_data.msg_type = OPCUA_MSG_HEL;
    CHECK_EQUAL(IpsOption::MATCH, opcua_msg_type.eval(c, &p));

    // Test case 7: Test different message types (ACK, ERR, MSG, CLO)
    // Verify detection works for all supported OPC UA message types
    OpcuaMsgTypeOption opcua_ack(OPCUA_MSG_ACK);
    ofd->server_ssn_data.msg_type = OPCUA_MSG_ACK;
    CHECK_EQUAL(IpsOption::MATCH, opcua_ack.eval(c, &p));

    OpcuaMsgTypeOption opcua_msg(OPCUA_MSG_MSG);
    ofd->server_ssn_data.msg_type = OPCUA_MSG_MSG;
    CHECK_EQUAL(IpsOption::MATCH, opcua_msg.eval(c, &p));

    OpcuaMsgTypeOption opcua_err(OPCUA_MSG_ERR);
    ofd->server_ssn_data.msg_type = OPCUA_MSG_ERR;
    CHECK_EQUAL(IpsOption::MATCH, opcua_err.eval(c, &p));

    OpcuaMsgTypeOption opcua_rhe(OPCUA_MSG_RHE);
    ofd->server_ssn_data.msg_type = OPCUA_MSG_RHE;
    CHECK_EQUAL(IpsOption::MATCH, opcua_rhe.eval(c, &p));

    // Test case 8: Test OPN and CLO message types
    // Verify detection works for secure channel open/close operations
    OpcuaMsgTypeOption opcua_opn(OPCUA_MSG_OPN);
    ofd->server_ssn_data.msg_type = OPCUA_MSG_OPN;
    CHECK_EQUAL(IpsOption::MATCH, opcua_opn.eval(c, &p));

    OpcuaMsgTypeOption opcua_clo(OPCUA_MSG_CLO);
    ofd->server_ssn_data.msg_type = OPCUA_MSG_CLO;
    CHECK_EQUAL(IpsOption::MATCH, opcua_clo.eval(c, &p));

    // Test case 9: No flow data should result in no match
    // Simulates cleanup or invalid flow state
    delete ofd;
    ofd = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opcua_msg_type.eval(c, &p));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
