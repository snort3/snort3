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

// opcua_splitter_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "opcua_mock.h"
#include "../opcua_splitter.h"
#include "../opcua_module.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

THREAD_LOCAL OpcuaStats opcua_stats;

TEST_GROUP(OpcuaSplitterTest)
{
    OpcuaSplitter* splitter;        // The splitter under test
    uint8_t test_data[1024];      // Buffer for constructing test messages
    snort::Packet server_packet;   // Mock packet from server
    snort::Packet client_packet;   // Mock packet from client
    uint32_t fp;                  // Flush point returned by splitter

    void setup() override
    {
        reset();
        splitter = new OpcuaSplitter(true);
        
        server_packet.packet_flags = PKT_FROM_SERVER;
        client_packet.packet_flags = PKT_FROM_CLIENT;
    }

    void teardown() override
    {
        delete splitter;
        event_sid = 0;
        mock().clear();
    }

    // Helper function to create OPC UA message headers
    // Constructs minimal valid OPC UA message with proper header structure
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

    void reset()
    {
        fp = 0;
        event_sid = 0; 
        memset(test_data, 0, sizeof(test_data));
    }
};

TEST(OpcuaSplitterTest, scan_valid_messages)
{
    uint32_t msg_size = 32;

    // Test case 1: Valid HEL (Hello) message from client
    // Client initiates connection with Hello message, should flush immediately
    create_opcua_message("HELF", test_data, msg_size);
    snort::StreamSplitter::Status result = splitter->scan(&client_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);

    // Test case 2: Valid ACK (Acknowledge) message from server
    // Server responds to Hello with Acknowledge, should flush immediately
    reset();
    create_opcua_message("ACKF", test_data, msg_size);
    result = splitter->scan(&server_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);

    // Test case 3: Valid OPN (Open) message from client
    // Client opens secure channel, should flush immediately
    reset();
    create_opcua_message("OPNF", test_data, msg_size);
    result = splitter->scan(&client_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);

    // Test case 4: Valid CLO (Close) message from server
    // Server closes secure channel or session, should flush immediately
    reset();
    create_opcua_message("CLOF", test_data, msg_size);
    result = splitter->scan(&server_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);

    // Test case 5: Valid MSG (Message) from client
    // Client sends service request message, should flush immediately
    reset();
    create_opcua_message("MSGF", test_data, msg_size);
    result = splitter->scan(&client_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);

    // Test case 6: Valid MSG (Message) from server
    // Server sends service response message, should flush immediately
    reset();
    create_opcua_message("MSGF", test_data, msg_size);
    result = splitter->scan(&server_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);

    // Test case 7: Valid RHE (Reverse Hello) message from server
    // Server initiates reverse connection, should flush immediately
    reset();
    create_opcua_message("RHEF", test_data, msg_size);
    result = splitter->scan(&server_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(msg_size, fp);
}

TEST(OpcuaSplitterTest, scan_invalid_messages)
{
    uint32_t msg_size = 32;

    // Test case 1: Invalid message type from client ("AOT!")
    // Non-standard OPC UA message type should abort processing and trigger bad message type event
    create_opcua_message("AOT!", test_data, msg_size);
    snort::StreamSplitter::Status result = splitter->scan(&client_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(OPCUA_BAD_MSG_TYPE, event_sid);

    // Test case 2: Invalid message type from server ("PIG")
    // Non-standard OPC UA message type should abort processing and trigger bad message type event
    reset();
    create_opcua_message("PIG", test_data, msg_size);
    result = splitter->scan(&server_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(OPCUA_BAD_MSG_TYPE, event_sid);

    // Test case 3: Packet without client or server flags set
    // Splitter cannot determine message direction, should abort processing
    // This tests handling of packets with undefined/invalid packet flags
    reset();
    snort::Packet packet(true);
    create_opcua_message("SUS", test_data, msg_size);
    result = splitter->scan(&packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);

    // Test case 5: Invalid is final field ("O")
    // Non-standard OPC UA is final fields are considered abnormal but do not affect parsing in most cases
    // Should flush but trigger a bad IsFinal event for security monitoring in the decoder
    reset();
    create_opcua_message("HELO", test_data, msg_size);
    result = splitter->scan(&server_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
}

TEST(OpcuaSplitterTest, scan_size_issues)
{
    // Test case 1: Message with abnormally large size (16384 bytes)
    // OPC UA messages over 16383 bytes are considered abnormal and may indicate attacks
    // Should flush but trigger abnormal message size event for security monitoring
    uint32_t msg_size = 16384;
    create_opcua_message("HELF", test_data, msg_size);
    snort::StreamSplitter::Status result = splitter->scan(&client_packet, test_data, msg_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(OPCUA_ABNORMAL_MSG_SIZE, event_sid);

    // Test case 2: Message with size inconsistency (unflushed bytes exceed claimed size)
    // Message claims size of 2 bytes but more data is provided across multiple scans
    // First scan processes 3 bytes (more than claimed size), second scan should abort
    reset();
    msg_size = 2;
    create_opcua_message("HELF", test_data, msg_size);
    result = splitter->scan(&client_packet, test_data, 3u, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::SEARCH, result);
    result = splitter->scan(&client_packet, &test_data[3], 8u, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);

    // Test case 3: Valid message split across multiple TCP packets
    // Message header arrives in first packet (8 bytes), remaining data in second packet
    // Should successfully reassemble and trigger split message event for monitoring
    reset();
    msg_size = 32;
    uint32_t split_size = 8u;
    create_opcua_message("HELF", test_data, msg_size);
    result = splitter->scan(&client_packet, test_data, split_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::SEARCH, result);
    result = splitter->scan(&client_packet, &test_data[split_size], msg_size - split_size, 0, &fp);
    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(OPCUA_SPLIT_MSG, event_sid);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
