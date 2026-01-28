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

// opcua_curse_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// define to access opcua_curse as it's private function
#define private public

#include "../opcua_curse.h"
#include "../curse_book.h"

#include <cstring>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(OpcuaCurse)
{
    uint8_t test_data[1024];
    CurseTracker tracker;

    void setup() override
    {
        reset();
    }

    void teardown() override
    {
        mock().clear();
    }

    void reset()
    {
        memset(test_data, 0, sizeof(test_data));
        tracker.opcua.state = OPCUA_STATE__MSG_TYPE_1;
        tracker.opcua.last_state = OPCUA_STATE__MSG_TYPE_1;
        tracker.opcua.raw_msg_type[0] = '_';
        tracker.opcua.raw_msg_type[1] = '_';
        tracker.opcua.raw_msg_type[2] = '_';
        tracker.opcua.msg_type = OPCUA_MSG__UNDEFINED;
    }

    void create_opcua_message(const char* msg, uint8_t* data, uint32_t msg_size)
    {
        // Message type (first 3 bytes) + is_final flag (4th byte)
        data[0] = msg[0]; data[1] = msg[1]; data[2] = msg[2];
        data[3] = msg[3]; // is_final flag ('F', 'C', or 'A')
        
        // Message size in little-endian format (bytes 4-7)
        data[4] = msg_size & 0xFF;
        data[5] = (msg_size >> 8) & 0xFF;
        data[6] = (msg_size >> 16) & 0xFF;
        data[7] = (msg_size >> 24) & 0xFF;
    }
};

// Test OPC UA Hello (HEL) message detection
// Verifies that valid HEL messages with proper size (32 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_hel)
{
    create_opcua_message("HELF", test_data, 32);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 32, &tracker));

    reset();
    create_opcua_message("HELF", test_data, 28);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 28, &tracker));
}

// Test OPC UA Acknowledge (ACK) message detection
// Verifies that valid ACK messages with proper size (28 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_ack)
{
    create_opcua_message("ACKF", test_data, 28);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 28, &tracker));

    reset();
    create_opcua_message("ACKF", test_data, 27);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 27, &tracker));
}

// Test OPC UA Error (ERR) message detection
// Verifies that valid ERR messages with proper size (16 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_err)
{
    create_opcua_message("ERRF", test_data, 16);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 16, &tracker));

    reset();
    create_opcua_message("ERRF", test_data, 15);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 15, &tracker));
}

// Test OPC UA Reverse Hello (RHE) message detection
// Verifies that valid RHE messages with proper size (16 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_rhe)
{
    create_opcua_message("RHEF", test_data, 16);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 16, &tracker));

    reset();
    create_opcua_message("RHEF", test_data, 15);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 15, &tracker));
}

// Test OPC UA Open Secure Channel (OPN) message detection
// Verifies that valid OPN messages with proper size (36 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_opn)
{
    create_opcua_message("OPNF", test_data, 36);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 36, &tracker));

    reset();
    create_opcua_message("OPNF", test_data, 35);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 35, &tracker));
}

// Test OPC UA Message (MSG) detection
// Verifies that valid MSG messages with proper size (32 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_msg)
{
    create_opcua_message("MSGF", test_data, 28);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 28, &tracker));

    reset();
    create_opcua_message("MSGF", test_data, 27);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 27, &tracker));
}

// Test OPC UA Close Secure Channel (CLO) message detection
// Verifies that valid CLO messages with proper size (32 bytes minimum) are detected
// and that messages below the minimum size threshold are rejected
TEST(OpcuaCurse, opcua_clo)
{
    create_opcua_message("CLOF", test_data, 28);
    CHECK_TRUE(CurseBook::opcua_curse(test_data, 28, &tracker));

    reset();
    create_opcua_message("CLOF", test_data, 27);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 27, &tracker));
}

// Test OPC UA invalid message type rejection
// Verifies that messages with invalid message type identifiers are properly rejected
// Tests corruption in each of the three message type identifier positions
TEST(OpcuaCurse, opcua_invalid_message_type)
{
    // Invalid first character
    create_opcua_message("XELF", test_data, 36);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 36, &tracker));

    // Invalid second character
    reset();
    create_opcua_message("HXLF", test_data, 36);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 36, &tracker));

    // Invalid third character
    reset();
    create_opcua_message("HEXY", test_data, 36);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 36, &tracker));

    // Invalid is final field
    reset();
    create_opcua_message("HELO", test_data, 36);
    CHECK_FALSE(CurseBook::opcua_curse(test_data, 36, &tracker));
}



int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
