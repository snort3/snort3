//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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
//
// s7comm_paf_test.cc author Oleksandr Stepanov <ostepano@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../s7comm_paf.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;
const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned int, unsigned int,
    unsigned char const*, unsigned int, unsigned int, unsigned int &) { return {}; }
unsigned StreamSplitter::max(snort::Flow*) { return 0; }
}


S7commplusSplitter* test_splitter = nullptr;
snort::Packet mock_packet(true);

TEST_GROUP(s7commplus_stream_splitter_tests)
{
    void setup() override
    {
        test_splitter = new S7commplusSplitter(true);
    }
    void teardown() override
    {
        delete test_splitter;
    }
};

TEST(s7commplus_stream_splitter_tests, test_splitter_is_paf)
{
    CHECK_TRUE(test_splitter->is_paf());
}

TEST(s7commplus_stream_splitter_tests, splitter_search_on_not_enough_bytes)
{
    const uint8_t* test_data = (uint8_t*)"\x03";
    uint32_t test_data_len = 1;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::SEARCH);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_incorrect_tpkt_version)
{
    const uint8_t* test_data = (uint8_t*)"\x01";
    uint32_t test_data_len = 1;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_incorrect_reserved_bytes)
{
    const uint8_t* test_data = (uint8_t*)"\x03\xff\xff";
    uint32_t test_data_len = 3;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_incorrect_tpkt_length)
{
    const uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x00\x00";
    uint32_t test_data_len = 5;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_incorrect_cotp_length)
{
    const uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x10\x01";
    uint32_t test_data_len = 5;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_incorrect_cotp_pdu_type)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x10\x02\x00";
    uint32_t test_data_len = 6;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);

    test_data = (uint8_t*)"\x03\x00\x00\x10\x02\x03";
    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);

    test_data = (uint8_t*)"\x03\x00\x00\x10\x02\x09";
    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);

    test_data = (uint8_t*)"\x03\x00\x00\x10\x02\x0A";
    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_cotp_cr_class_2_or_higher)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x10\x02\x0e\x00\x00\x01\x01\x20";
    uint32_t test_data_len = 11;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);

    test_data = (uint8_t*)"\x03\x00\x00\x10\x02\x0e\x00\x00\x01\x01\x40";
    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_flush_on_cotp_cr_class_0_or_1)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x24\x06\xe0\x00\x00\x01\x01\x00";
    uint32_t test_data_len = 11;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);

    test_data = (uint8_t*)"\x03\x00\x00\x24\x06\xe0\x00\x00\x01\x01\x10";
    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_abnormal_class_options)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x24\x06\xe0\x00\x00\x01\x01\x01";
    uint32_t test_data_len = 11;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_flush_on_data_transfer_correct_s7_protocol)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x24\x06\xf0\x80\x72";
    uint32_t test_data_len = 8;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);
}

TEST(s7commplus_stream_splitter_tests, splitter_search_and_flush_correct_s7_protocol)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00";
    uint32_t test_data_len = 2;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::SEARCH);

    test_data = (uint8_t*)"\x00\x24";

    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::SEARCH);


    test_data = (uint8_t*)"\x06\xf0\x80\x72";
    test_data_len = 4;

    result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);
}

TEST(s7commplus_stream_splitter_tests, splitter_flush_on_cotp_fragment)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x24\x06\xf0\x00";
    uint32_t test_data_len = 7;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_data_transfer_incorrect_s7_protocol)
{
    uint8_t* test_data = (uint8_t*)"\x03\x00\x00\x24\x06\xf0\x80\x34";
    uint32_t test_data_len = 8;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST_GROUP(s7commplus_misc)
{

};

TEST(s7commplus_misc, verify_s7commplus_paf_state)
{
    s7commplus_paf_state_t test_state = (s7commplus_paf_state_t)0;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__TPKT_VER, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__TPKT_RESERVED, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__TPKT_LEN_1, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__TPKT_LEN_2, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_LEN, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_PDU_TYPE, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_1, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_2, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_CR_SRC_REF_1, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_CR_SRC_REF_2, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_CR_CLASS_OPTIONS, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__COTP_DT_TPDU_NUM_EOT, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__S7_PROTOCOL_ID, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__MAX, test_state);
    ++test_state;
    CHECK_EQUAL(s7commplus_paf_state_t::S7COMMPLUS_PAF_STATE__MAX, test_state);
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}