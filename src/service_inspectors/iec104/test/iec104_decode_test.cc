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
// iec104_parse_apdu_test.cc author Yehor Furman <yefurman@cisco.com>

#include "../iec104_decode.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

THREAD_LOCAL const snort::Trace* iec104_trace = nullptr;

namespace snort
{
    uint8_t TraceApi::get_constraints_generation() { return 0; }
    void TraceApi::filter(const Packet&) { }
    void trace_vprintf(const char*, uint8_t, const char*, const Packet*, const char*, va_list) { }

    Packet::Packet(bool) { memset(this, 0, sizeof(*this)); }
    Packet::~Packet() = default;

    FlowData::FlowData(unsigned u) : id(u) { }
    FlowData::~FlowData() = default;
}

unsigned Iec104FlowData::inspector_id = 0;
Iec104FlowData::Iec104FlowData() : snort::FlowData(inspector_id) { }
Iec104FlowData::~Iec104FlowData() = default;

void parseIec104ApciU(const Iec104ApciU*) { }
void parseIec104ApciS(const Iec104ApciS*) { }
void parseIec104ApciI(const Iec104ApciI*, const uint16_t&) { }

TEST_GROUP(iec104_decode_type_i_min_len)
{
    // cppcheck-suppress constVariablePointer
    snort::Packet* packet = nullptr;
    // cppcheck-suppress constVariablePointer
    Iec104FlowData* flow_data = nullptr;

    void setup() override
    {
        // cppcheck-suppress unreadVariable
        packet = new snort::Packet(false);
        // cppcheck-suppress unreadVariable
        flow_data = new Iec104FlowData();
    }

    void teardown() override
    {
        delete packet;
        delete flow_data;
    }
};

TEST(iec104_decode_type_i_min_len, type_i_6_bytes_rejected)
{
    const uint8_t type_i_6_bytes[] = {0x68, 0x04, 0x00, 0x00, 0x00, 0x00};
    snort::Packet* const local_packet = packet;
    Iec104FlowData* const local_flow_data = flow_data;
    local_packet->data = type_i_6_bytes;
    local_packet->dsize = sizeof(type_i_6_bytes);
    bool result = Iec104Decode(local_packet, local_flow_data);
    CHECK_FALSE(result);
}

TEST(iec104_decode_type_i_min_len, type_i_11_bytes_rejected)
{
    const uint8_t type_i_11_bytes[] = {0x68, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x01, 0x00};
    snort::Packet* const local_packet = packet;
    Iec104FlowData* const local_flow_data = flow_data;
    local_packet->data = type_i_11_bytes;
    local_packet->dsize = sizeof(type_i_11_bytes);
    bool result = Iec104Decode(local_packet, local_flow_data);
    CHECK_FALSE(result);
}

TEST(iec104_decode_type_i_min_len, type_i_12_bytes_accepted)
{
    const uint8_t type_i_12_bytes[] = {0x68, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x01, 0x00, 0x00};
    snort::Packet* const local_packet = packet;
    Iec104FlowData* const local_flow_data = flow_data;
    local_packet->data = type_i_12_bytes;
    local_packet->dsize = sizeof(type_i_12_bytes);
    bool result = Iec104Decode(local_packet, local_flow_data);
    CHECK_TRUE(result);
    CHECK_EQUAL(IEC104_APCI_TYPE_I, local_flow_data->ssn_data.iec104_apci_type);
}

TEST(iec104_decode_type_i_min_len, type_s_6_bytes_accepted)
{
    const uint8_t type_s_6_bytes[] = {0x68, 0x04, 0x01, 0x00, 0x00, 0x00};
    snort::Packet* const local_packet = packet;
    Iec104FlowData* const local_flow_data = flow_data;
    local_packet->data = type_s_6_bytes;
    local_packet->dsize = sizeof(type_s_6_bytes);
    bool result = Iec104Decode(local_packet, local_flow_data);
    CHECK_TRUE(result);
    CHECK_EQUAL(IEC104_APCI_TYPE_S, local_flow_data->ssn_data.iec104_apci_type);
}

TEST(iec104_decode_type_i_min_len, type_u_6_bytes_accepted)
{
    const uint8_t type_u_6_bytes[] = {0x68, 0x04, 0x03, 0x00, 0x00, 0x00};
    snort::Packet* const local_packet = packet;
    Iec104FlowData* const local_flow_data = flow_data;
    local_packet->data = type_u_6_bytes;
    local_packet->dsize = sizeof(type_u_6_bytes);
    bool result = Iec104Decode(local_packet, local_flow_data);
    CHECK_TRUE(result);
    CHECK_EQUAL(IEC104_APCI_TYPE_U, local_flow_data->ssn_data.iec104_apci_type);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
