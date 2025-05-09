//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// active_packet_trace_test.cc author Steve Chew <stechew@cisco.com>

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../active.cc"
#include "active_packet_trace_stubs.h"
#include "packet_io/active.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

const int BUFFER_SIZE = 2048;
char log_buffer[BUFFER_SIZE] = {};
bool direct_inject_failed = false;
bool daq_inject_failed = false;
bool encode_failed = false;
bool encode_unreach_failed = false;
uint8_t encode_buf[BUFFER_SIZE];
uint16_t max_payload = 0;

void CHECK_STR(const char* str)
{
    int failed = strcmp(log_buffer, str);
    if (failed)
    {
        printf("String comparison failed...\n"
               "Expected: %s"
               "Actual  : %s", str, log_buffer);
    }
    log_buffer[0] = '\0';   // Must set to zero-length string before reuse

    CHECK(not failed);
}

bool snort::PacketTracer::is_active() { return true; }
uint16_t PacketManager::encode_get_max_payload(const Packet*) { return max_payload; }

// Override log to write to a buffer instead so we can check the result.
void PacketTracer::log(const char* format, ...)
{
    size_t len = strlen(log_buffer);

    va_list args;
    va_start(args, format);
    vsnprintf(&log_buffer[len], BUFFER_SIZE, format, args);
    va_end(args);
}

int SFDAQInstance::ioctl(DAQ_IoctlCmd, void*, size_t)
{
    if (direct_inject_failed)
        return -1;

    return DAQ_SUCCESS;
}

int SFDAQ::inject(DAQ_Msg_h, int, const uint8_t*, uint32_t)
{
    if (daq_inject_failed)
        return -1;

    return DAQ_SUCCESS;
}

const uint8_t* PacketManager::encode_response(TcpResponse, EncodeFlags, const Packet*, uint32_t&,
    const uint8_t* const, uint32_t)
{
    if (encode_failed)
        return nullptr;

    return encode_buf;
}

const uint8_t* PacketManager::encode_reject(UnreachResponse, EncodeFlags, const Packet*, uint32_t&)
{
    if (encode_unreach_failed)
        return nullptr;

    return encode_buf;
}

TEST_GROUP(active_packet_trace)
{
    void setup() {
        direct_inject_failed = false;
        daq_inject_failed = false;
        encode_failed = false;
        encode_unreach_failed = false;
        max_payload = 0;
    }

    void teardown() {
    }
};

TEST(active_packet_trace, check_send_reset)
{
    EncodeFlags ef = ENC_FLAG_FWD;
    Packet pkt;
    Flow flow;
    Active active;
    pkt.flow = &flow;
    pkt.active = &active;
    s_attempts = 1;

    // Direct inject cases.
    pkt.packet_flags = PKT_USE_DIRECT_INJECT;
    direct_inject_failed = true;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: failed direct injection of RST packet in forward direction\n");

    ef = 0;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: failed direct injection of RST packet in reverse direction\n");

    direct_inject_failed = false;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: successful direct injection of RST packet in reverse direction\n");

    ef = ENC_FLAG_FWD;
    direct_inject_failed = false;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: successful direct injection of RST packet in forward direction\n");


    // DAQ inject cases
    pkt.packet_flags &= ~PKT_USE_DIRECT_INJECT;

    daq_inject_failed = true;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: failed injection of RST packet in forward direction\n");

    ef = 0;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: failed injection of RST packet in reverse direction\n");

    daq_inject_failed = false;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: successful injection of RST packet in reverse direction\n");

    ef = ENC_FLAG_FWD;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset: successful injection of RST packet in forward direction\n");


    // Encoding failure cases
    encode_failed = true;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset failed to encode: failed injection of RST packet in forward direction\n");

    ef = 0;
    pkt.active->send_reset(&pkt, ef);
    CHECK_STR("send_reset failed to encode: failed injection of RST packet in reverse direction\n");
}

TEST(active_packet_trace, check_send_unreach)
{
    Packet pkt;
    Flow flow;
    Active active;
    pkt.flow = &flow;
    pkt.active = &active;
    s_attempts = 1;

    pkt.active->send_unreach(&pkt, snort::UnreachResponse::FWD);
    CHECK_STR("send_unreach: successful injection of packet unreachable in reverse direction\n");

    daq_inject_failed = true;
    pkt.active->send_unreach(&pkt, snort::UnreachResponse::FWD);
    CHECK_STR("send_unreach: failed injection of packet unreachable in reverse direction\n");

    encode_unreach_failed = true;
    pkt.active->send_unreach(&pkt, snort::UnreachResponse::FWD);
    CHECK_STR("send_unreach failed to encode: failed injection of packet unreachable in reverse direction\n");
}

TEST(active_packet_trace, check_send_data)
{
    EncodeFlags ef = ENC_FLAG_FWD;
    Packet pkt;
    Flow flow;
    Active active;
    pkt.flow = &flow;
    pkt.active = &active;
    s_attempts = 1;

    // Direct inject cases with no RSTs.
    pkt.packet_flags = PKT_USE_DIRECT_INJECT;
    direct_inject_failed = true;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: failed direct injection of payload packet (length 2048) in forward direction\n");

    ef = 0;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: failed direct injection of payload packet (length 2048) in reverse direction\n");

    direct_inject_failed = false;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: successful direct injection of payload packet (length 2048) in reverse direction\n");

    ef = ENC_FLAG_FWD;
    direct_inject_failed = false;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: successful direct injection of payload packet (length 2048) in forward direction\n");


    // Direct inject cases with client and server RSTs
    ef = ENC_FLAG_FWD | ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;

    direct_inject_failed = true;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: failed direct injection of RST packet in reverse direction\n");

    ef = ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: failed direct injection of RST packet in forward direction\n");

    direct_inject_failed = false;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: successful direct injection of RST packet in forward direction\n"
              "send_data: successful direct injection of payload packet (length 2048) in reverse direction\n"
              "send_data: successful direct injection of RST packet in reverse direction\n"
             );

    ef = ENC_FLAG_FWD | ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;
    direct_inject_failed = false;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: successful direct injection of RST packet in reverse direction\n"
              "send_data: successful direct injection of payload packet (length 2048) in forward direction\n"
              "send_data: successful direct injection of RST packet in forward direction\n"
             );


    // DAQ inject cases with no RSTs.
    pkt.packet_flags &= ~PKT_USE_DIRECT_INJECT;
    ef = ENC_FLAG_FWD;

    // Testing FIN sends (max_payload = 0)
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: successful injection of FIN packet in forward direction\n");

    ef = 0;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: successful injection of FIN packet in reverse direction\n");

    // Testing FIN sends (max_payload = 1000)
    max_payload = 1000;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: successful injection of payload packet (length 2048) in reverse direction\n"
              "send_data: successful injection of FIN packet in reverse direction\n"
             );

    ef = ENC_FLAG_FWD;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data: successful injection of payload packet (length 2048) in forward direction\n"
              "send_data: successful injection of FIN packet in forward direction\n"
             );

    // Testing FIN encoding failure.
    encode_failed = true;
    max_payload = 0;

    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data failed to encode: failed injection of FIN packet in forward direction\n");

    ef = 0;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data failed to encode: failed injection of FIN packet in reverse direction\n");


    // Testing server RST encoding failure.
    ef = ENC_FLAG_RST_SRVR;
    encode_failed = true;

    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator failed to encode: failed injection of RST packet in forward direction\n"
              "send_data failed to encode: failed injection of FIN packet in reverse direction\n"
             );

    ef = 0;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data failed to encode: failed injection of FIN packet in reverse direction\n");

    // Testing DAQ inject with client and server RSTs.
    ef = ENC_FLAG_FWD | ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;
    encode_failed = false;
    max_payload = 1000;

    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: successful injection of RST packet in reverse direction\n"
              "send_data: successful injection of payload packet (length 2048) in forward direction\n"
              "send_data: successful injection of FIN packet in forward direction\n"
              "send_data: successful injection of RST packet in forward direction\n"
             );

    ef = ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: successful injection of RST packet in forward direction\n"
              "send_data: successful injection of payload packet (length 2048) in reverse direction\n"
              "send_data: successful injection of FIN packet in reverse direction\n"
              "send_data: successful injection of RST packet in reverse direction\n"
             );

    daq_inject_failed = true;
    ef = ENC_FLAG_FWD | ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: failed injection of RST packet in reverse direction\n"
              "send_data: failed injection of payload packet (length 2048) in forward direction\n"
              "send_data: failed injection of FIN packet in forward direction\n"
              "send_data: failed injection of RST packet in forward direction\n"
             );

    daq_inject_failed = true;
    ef = ENC_FLAG_RST_CLNT | ENC_FLAG_RST_SRVR;
    pkt.active->send_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("send_data to originator: failed injection of RST packet in forward direction\n"
              "send_data: failed injection of payload packet (length 2048) in reverse direction\n"
              "send_data: failed injection of FIN packet in reverse direction\n"
              "send_data: failed injection of RST packet in reverse direction\n"
             );

}

TEST(active_packet_trace, check_inject_data)
{
    EncodeFlags ef = ENC_FLAG_FWD;
    Packet pkt;
    Flow flow;
    Active active;
    pkt.flow = &flow;
    pkt.active = &active;
    s_attempts = 1;

    pkt.active->inject_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("inject_data: successful injection of payload packet (length 2048) in forward direction\n");

    daq_inject_failed = true;
    pkt.active->inject_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("inject_data: failed injection of payload packet (length 2048) in forward direction\n");

    encode_failed = true;
    pkt.active->inject_data(&pkt, ef, encode_buf, BUFFER_SIZE);
    CHECK_STR("inject_data failed to encode: failed injection of payload packet (length 2048) in forward direction\n");
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
