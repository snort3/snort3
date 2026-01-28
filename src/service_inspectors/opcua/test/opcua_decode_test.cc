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

// opcua_decode_test.cc author Daniil Kolomiiets <dkolomii@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "opcua_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

THREAD_LOCAL OpcuaStats opcua_stats;

inline uint32_t get_actual_value(uint32_t opcua_string_size)
{
    return opcua_string_size == OPCUA_NULL_STRING_SIZE ? 0 : opcua_string_size;
}

TEST_GROUP(OpcuaDecodeTest)
{
    snort::Packet packet;
    OpcuaFlowData* opcua_fd;
    uint8_t test_data[1024];

    void setup() override
    {
        memset(&opcua_stats, 0, sizeof(opcua_stats));
        packet.data = test_data;
        packet.dsize = 0;
        opcua_fd = new OpcuaFlowData();
    }

    void teardown() override
    {
        delete opcua_fd;
        event_sid = 0;
        mock().clear();
    }

    void reset()
    {
        event_sid = 0;
        opcua_fd->reset();
        memset(test_data, 0, sizeof(test_data));
    }

    void create_opcua_message(const char* msg, uint8_t* data, uint32_t msg_size, bool client_packet = true)
    {
        packet.packet_flags = client_packet ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
        data[0] = msg[0]; data[1] = msg[1]; data[2] = msg[2];
        data[3] = msg[3]; // is_final
        data[4] = msg_size & 0xFF;
        data[5] = (msg_size >> 8) & 0xFF;
        data[6] = (msg_size >> 16) & 0xFF;
        data[7] = (msg_size >> 24) & 0xFF;

        packet.dsize = msg_size;
    }

    void create_hello_message(uint32_t msg_size = 32,
                            uint32_t protocol_version = 0x00000000,
                            uint32_t url_len = OPCUA_NULL_STRING_SIZE,
                            const char final_field = 'F')
    {
        char msg[5] = {'H', 'E', 'L', final_field, '\0'};
        create_opcua_message(msg, test_data, msg_size);
        *reinterpret_cast<uint32_t*>(&test_data[8]) = protocol_version;
        *reinterpret_cast<uint32_t*>(&test_data[28]) = url_len;
    }

    void create_ack_message(uint32_t msg_size = 28,
                            uint32_t protocol_version = 0x00000000,
                            const char final_field = 'F')
    {
        char msg[5] = {'A', 'C', 'K', final_field, '\0'};
        create_opcua_message(msg, test_data, msg_size, false);
        *reinterpret_cast<uint32_t*>(&test_data[8]) = protocol_version;
    }

    void create_err_message(uint32_t msg_size = 16u,
                            uint32_t reason_size = OPCUA_NULL_STRING_SIZE,
                            const char final_field = 'F')
    {
        char msg[5] = {'E', 'R', 'R', final_field, '\0'};

        create_opcua_message(msg, test_data, msg_size, false);
        *reinterpret_cast<uint32_t*>(&test_data[12]) = reason_size;
    }

    void create_rhe_message(uint32_t msg_size = 18,
                            uint32_t server_uri_size = 1,
                            uint32_t endpoint_url_size = 1,
                            const char final_field = 'F')
    {

        const char msg[5] = {'R', 'H', 'E', final_field, '\0'};
        create_opcua_message(msg, test_data, msg_size, false);

        *reinterpret_cast<uint32_t*>(&test_data[8]) = server_uri_size;
        uint32_t endpoint_url_offset = 12 + get_actual_value(server_uri_size);
        if(endpoint_url_offset < 1024)
            *reinterpret_cast<uint32_t*>(&test_data[endpoint_url_offset]) = endpoint_url_size;
    }

    void create_opn_message(uint32_t msg_size = 32,
                            uint32_t sec_policy_size = OPCUA_NULL_STRING_SIZE,
                            uint32_t sender_cert_size = OPCUA_NULL_STRING_SIZE,
                            uint32_t receiver_cert_thumbprint_size = OPCUA_NULL_STRING_SIZE,
                            const char final_field = 'F')
    {
        const char msg[5] = {'O', 'P', 'N', final_field, '\0'};
        create_opcua_message(msg, test_data, msg_size);
        *reinterpret_cast<uint32_t*>(&test_data[12]) = sec_policy_size;
        uint32_t offset = 16 + get_actual_value(sec_policy_size);
        if(offset < 1024)
            *reinterpret_cast<uint32_t*>(&test_data[offset]) = sender_cert_size;
        offset += 4 + get_actual_value(sender_cert_size);
        if(offset < 1024)
            *reinterpret_cast<uint32_t*>(&test_data[offset]) = receiver_cert_thumbprint_size;
    }

    void create_msg_message(uint32_t msg_size = 26,
                            uint8_t encoding_mask = OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC,
                            uint8_t namespace_index = OPCUA_DEFAULT_NAMESPACE_INDEX,
                            const char final_field = 'F')
    {
        const char msg[5] = {'M', 'S', 'G', final_field, '\0'};
        create_opcua_message(msg, test_data, msg_size);
        test_data[24] = encoding_mask;
        test_data[25] = namespace_index;
    }

    void create_clo_message(uint32_t msg_size = 24, const char final_field = 'F')
    {
        const char msg[5] = {'C', 'L', 'O', final_field, '\0'};
        create_opcua_message(msg, test_data, msg_size, false);
    }
};

TEST(OpcuaDecodeTest, fail_decode)
{
    // Test case 1: Message with insufficient size (4 bytes < OPCUA_HEADER_MIN_SIZE)
    // Should fail to decode due to incomplete OPC UA header
    create_opcua_message("HELF", test_data, 4);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));

    // Test case 2: Packet without client or server flags set
    // Should fail to decode as direction cannot be determined
    snort::Packet invalid_packet(true);
    invalid_packet.dsize = 32;
    invalid_packet.packet_flags = 0;
    CHECK_FALSE(opcua_decode(&invalid_packet, opcua_fd));

    // Test case 3: Invalid message type from client
    // Should fail to decode and trigger bad message type event
    reset();
    create_opcua_message("INVALID_MESSAGE_FROM_CLIENT", test_data, 32);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_TYPE, event_sid);

    // Test case 4: Invalid message type from server
    // Should fail to decode and trigger bad message type event
    reset();
    create_opcua_message("INVALID_MESSAGE_FROM_SERVER", test_data, 32, false);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_TYPE, event_sid);
}

TEST(OpcuaDecodeTest, invalid_size)
{
    // Test case 1: HEL message with size below minimum (28 bytes < OPCUA_HEL_MIN_SIZE)
    // Should fail to decode due to insufficient size for HEL message structure
    create_opcua_message("HELF", test_data, 28);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);

    // Test case 2: ACK message with size below minimum (24 bytes < OPCUA_ACK_MIN_SIZE)
    // Should fail to decode due to insufficient size for ACK message structure
    reset();
    create_opcua_message("ACKF", test_data, 24, false);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);

    // Test case 3: ERR message with size below minimum (12 bytes < OPCUA_ERR_MIN_SIZE)
    // Should fail to decode due to insufficient size for ERR message structure
    reset();
    create_opcua_message("ERRF", test_data, 12, false);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);

    // Test case 4: RHE message with size below minimum (14 bytes < OPCUA_RHE_MIN_SIZE)
    // Should fail to decode due to insufficient size for RHE message structure
    reset();
    create_opcua_message("RHEF", test_data, 14, false);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);

    // Test case 5: OPN message with size below minimum (28 bytes < OPCUA_OPN_MIN_SIZE)
    // Should fail to decode due to insufficient size for OPN message structure
    reset();
    create_opcua_message("OPNF", test_data, 28);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);

    // Test case 6: CLO message with size below minimum (20 bytes < OPCUA_MSG_CLO_MIN_SIZE)
    // Should fail to decode due to insufficient size for CLO message structure
    reset();
    create_opcua_message("CLOF", test_data, 20, false);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);

    // Test case 7: MSG message with size below minimum (22 bytes < OPCUA_MSG_MIN_SIZE)
    // Should fail to decode due to insufficient size for MSG message structure
    reset();
    create_opcua_message("MSGF", test_data, 22);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_MSG_SIZE, event_sid);
}

TEST(OpcuaDecodeTest, decode_hel_message)
{
    constexpr uint32_t url_size = 10;
    constexpr uint32_t msg_with_url = 32 + url_size;

    // Test case 1: HEL message with non-zero protocol version
    // Should decode successfully but trigger abnormal protocol version event
    create_hello_message(msg_with_url, 1, url_size);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_PROTO_VERSION, event_sid);

    // Test case 2: HEL message with standard protocol version (0)
    // Should decode successfully with no events triggered
    reset();
    create_hello_message(msg_with_url, 0, url_size);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 3: HEL message with string length exceeding available data
    // Message size is 32 bytes but string claims to be url_size (10) bytes
    // Should fail decoding due to insufficient data for the claimed string length
    reset();
    create_hello_message(32, 0, url_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 4: HEL message with extremely large string size (5000 bytes)
    // String size exceeds reasonable limits, should trigger invalid string size event
    reset();
    uint32_t overflow_string_size = 5000;
    create_hello_message(32, 0, overflow_string_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_INVALID_STRING_SIZE, event_sid);

    // Test case 5: HEL message with null string (OPCUA_NULL_STRING_SIZE = 0xFFFFFFFF)
    // Should decode successfully but trigger abnormal string event for null endpoint URL
    reset();
    create_hello_message();
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 6: HEL message with invalid is_final flag ('C' instead of 'F')
    // Should fail decoding due to invalid message format flag
    reset();
    create_hello_message(msg_with_url, 0, url_size, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_ISFINAL, event_sid);
}

TEST(OpcuaDecodeTest, decode_ack_message)
{
    // Test case 1: Valid ACK message with standard protocol version (0)
    // Should decode successfully with no events triggered
    create_ack_message();
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 2: ACK message with non-zero protocol version
    // Should decode successfully but trigger abnormal protocol version event
    reset();
    create_ack_message(28, 1);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_PROTO_VERSION, event_sid);

    // Test case 3: ACK message with invalid is_final flag ('C' instead of 'F')
    // Should fail decoding due to invalid message format flag
    reset();
    create_ack_message(28, 0, 'C');
    CHECK_TRUE(opcua_decode(&packet,opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_ISFINAL, event_sid);
}

TEST(OpcuaDecodeTest, decode_err_message)
{
    constexpr uint32_t error_size = 11;
    constexpr uint32_t msg_size_with_error = 16u + error_size;

    // Test case 1: Valid ERR message with error reason string
    // Should decode successfully with no events triggered
    create_err_message(msg_size_with_error, error_size);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 2: ERR message with null error reason (default parameters)
    // Should decode successfully with no events triggered
    reset();
    create_err_message();
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 3: ERR message with mismatched message size and string size
    // Message size (16) doesn't account for error string size (11)
    // Should fail due to insufficient data for the claimed string length
    reset();
    create_err_message(16, error_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 4: ERR message with extremely large error string size (5000 bytes)
    // String size exceeds reasonable limits, should trigger invalid string size event
    reset();
    create_err_message(16, 5000);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_INVALID_STRING_SIZE, event_sid);

    // Test case 5: ERR message with invalid is_final flag ('C' instead of 'F')
    // Should fail decoding due to invalid message format flag
    reset();
    create_err_message(msg_size_with_error, error_size, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_ISFINAL, event_sid);
}

TEST(OpcuaDecodeTest, decode_rhe_message)
{
    constexpr uint32_t server_uri_size = 16;
    constexpr uint32_t endpoint_url_size = 18;
    constexpr uint32_t msg_size = 16 + server_uri_size + endpoint_url_size;

    // Test case 1: Valid RHE message with proper server URI and endpoint URL sizes
    // Should decode successfully with no events triggered
    create_rhe_message(msg_size, server_uri_size, endpoint_url_size);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 2: RHE message with insufficient size for server URI
    // Message size (18) is too small to contain server URI of claimed size (16)
    // Should fail due to insufficient data for server URI
    reset();
    create_rhe_message(18, server_uri_size, endpoint_url_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 3: RHE message with insufficient size for endpoint URL
    // Message size only accounts for header + server URI, missing endpoint URL
    // Should fail due to insufficient data for endpoint URL
    reset();
    create_rhe_message(16 + server_uri_size, server_uri_size, endpoint_url_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 4: RHE message too small to read endpoint URL size field
    // Message size doesn't include space for endpoint URL size field (4 bytes)
    // Should fail due to truncated message structure
    reset();
    create_rhe_message(14 + server_uri_size, server_uri_size, endpoint_url_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 5: RHE message with null server URI (OPCUA_NULL_STRING_SIZE)
    // Should decode successfully but trigger abnormal string event for null server URI
    reset();
    create_rhe_message(16 + endpoint_url_size, OPCUA_NULL_STRING_SIZE, endpoint_url_size);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 6: RHE message with null endpoint URL (OPCUA_NULL_STRING_SIZE)
    // Should decode successfully but trigger abnormal string event for null endpoint URL
    reset();
    create_rhe_message(16 + server_uri_size, server_uri_size, OPCUA_NULL_STRING_SIZE);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 7: RHE message with extremely large server URI size (5000 bytes)
    // Server URI size exceeds reasonable limits, should trigger invalid string size event
    reset();
    create_rhe_message(msg_size, 5000, endpoint_url_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_INVALID_STRING_SIZE, event_sid);

    // Test case 8: RHE message with extremely large endpoint URL size (5000 bytes)
    // Endpoint URL size exceeds reasonable limits, should trigger invalid string size event
    reset();
    create_rhe_message(msg_size, server_uri_size, 5000);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_INVALID_STRING_SIZE, event_sid);

    // Test case 9: RHE message with invalid is_final flag ('C' instead of 'F')
    // Should fail decoding due to invalid message format flag
    reset();
    create_rhe_message(msg_size, server_uri_size, endpoint_url_size, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_ISFINAL, event_sid);
}

TEST(OpcuaDecodeTest, decode_opn_message)
{
    constexpr uint32_t sec_policy_size = 20;
    constexpr uint32_t sender_cert_size = 256;
    constexpr uint32_t receiver_cert_thumbprint_size = 20;
    constexpr uint32_t msg_size = 32 + sec_policy_size + sender_cert_size + receiver_cert_thumbprint_size + 1;

    // Test case 1: Valid OPN message with complete security information
    // Contains proper security policy URI, sender certificate, and receiver thumbprint
    // Should decode successfully with no events triggered
    create_opn_message(msg_size, sec_policy_size, sender_cert_size, receiver_cert_thumbprint_size);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 2: Valid OPN message with null security fields (default parameters)
    // Uses OPCUA_NULL_STRING_SIZE for all certificate fields, common for unsecured connections
    // Should decode successfully with no events triggered
    reset();
    create_opn_message();
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 3: OPN message with insufficient size for security policy string
    // Message size (32) is too small to contain security policy of claimed size (20)
    // Should fail due to insufficient data for security policy URI
    reset();
    create_opn_message(32, sec_policy_size, sender_cert_size, receiver_cert_thumbprint_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 4: OPN message with extremely large sender certificate size
    // Message claims sender certificate size exceeds reasonable limits
    // Should fail and trigger invalid string size event
    reset();
    create_opn_message(32 + sec_policy_size + 1, sec_policy_size, sender_cert_size, receiver_cert_thumbprint_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_INVALID_STRING_SIZE, event_sid);

    // Test case 5: OPN message with extremely large receiver certificate thumbprint size
    // Message claims receiver thumbprint size exceeds reasonable limits
    // Should fail and trigger abnormal string event
    reset();
    create_opn_message(32 + sec_policy_size + sender_cert_size + 1, sec_policy_size, 
        sender_cert_size, receiver_cert_thumbprint_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);

    // Test case 6: OPN message with invalid receiver thumbprint size
    // Should fail decoding due to invalid string size
    reset();
    create_opn_message(msg_size, sec_policy_size, sender_cert_size, 10u);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_INVALID_STRING_SIZE, event_sid);

    // Test case 7: OPN message with invalid is_final flag ('C' instead of 'F')
    // Should fail decoding due to invalid message format flag
    reset();
    create_opn_message(msg_size, sec_policy_size, sender_cert_size, receiver_cert_thumbprint_size, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_ISFINAL, event_sid);

    // Test case 8: OPN message too small to read sender certificate size field
    // Message size (38) doesn't include space for sender cert size field after security policy
    // Should fail due to truncated message structure
    reset();
    create_opn_message(38, sec_policy_size, sender_cert_size, receiver_cert_thumbprint_size);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_ABNORMAL_STRING, event_sid);
}

TEST(OpcuaDecodeTest, decode_clo_message)
{
    // Test case 1: Valid CLO message with standard format
    // CLO messages are typically sent by server to close secure channels/sessions
    // Should decode successfully with no events triggered
    create_clo_message();
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 2: CLO message with invalid is_final flag ('C' instead of 'F')
    // Should fail decoding due to invalid message format flag
    reset();
    create_clo_message(24, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_ISFINAL, event_sid);
}

TEST(OpcuaDecodeTest, decode_msg_message)
{
    // Test case 1: Valid complete MSG message with default namespace and encoding
    // Standard OPC UA service message with proper TypeID encoding
    // Should decode successfully with no events triggered
    reset();
    create_msg_message(28);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 2: Valid MSG message with non-zero namespace index
    // Uses namespace index 1 instead of default 0, which may indicate custom types
    // Should decode successfully but trigger abnormal namespace event
    reset();
    create_msg_message(28, OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC, 1);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_NONZERO_NAMESPACE_INDEX_MSG, event_sid);

    // Test case 3: MSG message with insufficient size for TypeID processing
    // Message size (26) is too small to contain complete TypeID information
    // Should fail due to truncated TypeID encoding data
    reset();
    create_msg_message(26);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_BAD_TYPEID_ENCODING, event_sid);

    // Test case 4: MSG message with extremely large size exceeding buffer limits
    // Message claims size (10000) that would exceed chunked message buffer capacity
    // Should fail and trigger large chunked message event
    reset();
    create_msg_message(10000);
    CHECK_FALSE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(OPCUA_LARGE_CHUNKED_MSG, event_sid);

    // Test case 5: Valid MSG chunked message sequence (intermediate + final)
    // First chunk with 'C' flag (continue), followed by final chunk with 'F' flag
    // Should decode both chunks successfully, triggering intermediate event on first chunk
    reset();
    create_msg_message(28, OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC, OPCUA_DEFAULT_NAMESPACE_INDEX, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    memset(test_data, 0, sizeof(test_data));
    event_sid = 0;
    create_msg_message(28);
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    CHECK_EQUAL(0, event_sid);

    // Test case 6: MSG chunked message sequence with abort
    // First chunk with 'C' flag (continue), followed by abort chunk with 'A' flag
    // Should handle both chunks
    reset();
    create_msg_message(28, OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC, OPCUA_DEFAULT_NAMESPACE_INDEX, 'C');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
    memset(test_data, 0, sizeof(test_data));
    event_sid = 0;
    create_msg_message(28, OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC, OPCUA_DEFAULT_NAMESPACE_INDEX, 'A');
    CHECK_TRUE(opcua_decode(&packet, opcua_fd));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
