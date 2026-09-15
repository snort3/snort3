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

#include "../s7comm.h"
#include "../s7comm_module.h"
#include "../s7comm_paf.h"

#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

#include <vector>

namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;
const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned int, unsigned int,
    unsigned char const*, unsigned int, unsigned int, unsigned int &) { return {}; }
unsigned StreamSplitter::max(snort::Flow*) { return 0; }

Inspector::Inspector() = default;
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

FlowDataStore::~FlowDataStore() = default;
}

S7commplus::S7commplus(uint16_t limit) : small_pdus_limit(limit)
{ }

void S7commplus::show(const snort::SnortConfig*) const { }
void S7commplus::eval(snort::Packet*) { }
snort::StreamSplitter* S7commplus::get_splitter(bool c2s)
{ return new S7commplusSplitter(c2s); }
bool S7commplus::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&)
{ return false; }

THREAD_LOCAL S7commplusStats s7commplus_stats = {};

static constexpr uint16_t default_small_pdus_limit = S7COMMPLUS_DEFAULT_SMALL_PDUS_LIMIT;

S7commplusSplitter* test_splitter = nullptr;
S7commplus* test_inspector = nullptr;

// Flow::Flow(), Flow::~Flow() and FlowStash::reset() are inline in some snort3
// revisions and defined in flow.cc / flow_stash.cc in others, so this test can
// neither rely on them nor stub them without breaking one of the two. The
// splitter reads only Flow::gadget, so back the mock flow with zeroed static
// storage and never run its constructor or destructor.
alignas(snort::Flow) static uint8_t mock_flow_storage[sizeof(snort::Flow)];
static snort::Flow& mock_flow = *reinterpret_cast<snort::Flow*>(mock_flow_storage);

snort::Packet mock_packet(true);

static void set_small_pdus_limit(uint16_t limit)
{
    delete test_inspector;
    test_inspector = new S7commplus(limit);
    mock_flow.gadget = test_inspector;
}

static void append_empty_fragment(std::vector<uint8_t>& buf)
{
    static const uint8_t fragment[] =
        { 0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x00 };
    buf.insert(buf.end(), fragment, fragment + sizeof(fragment));
}

static std::vector<uint8_t> consecutive_small_frames(unsigned count)
{
    std::vector<uint8_t> data;
    for (unsigned i = 0; i < count; ++i)
        append_empty_fragment(data);
    return data;
}

// TPKT + COTP + S7comm-plus header + S7comm-plus data header, exactly
// S7COMMPLUS_MIN_DATA_FRAME_LEN bytes, so the splitter does not count it as a small frame
static void append_plausible_fragment(std::vector<uint8_t>& buf)
{
    static const uint8_t fragment[] =
    {
        0x03, 0x00, 0x00, 0x12,                   // TPKT: version, reserved, length 18
        0x02, 0xf0, 0x80,                         // COTP: length, DT PDU type, TPDU number + EOT
        0x72, 0x01, 0x00, 0x07,                   // S7comm-plus: protocol id, version 1, data len
        0x31, 0x00, 0x00, 0x04, 0xca, 0x00, 0x00  // S7comm-plus data: opcode, reserved, function,
    };
    buf.insert(buf.end(), fragment, fragment + sizeof(fragment));
}

static snort::StreamSplitter::Status scan_frames(S7commplusSplitter& splitter,
    const std::vector<uint8_t>& data, unsigned& flush_count)
{
    flush_count = 0;
    uint32_t offset = 0;

    while (offset < data.size())
    {
        uint32_t fp = 0;
        const auto result = splitter.scan(&mock_packet, data.data() + offset,
            data.size() - offset, 0, &fp);

        if (result == snort::StreamSplitter::ABORT)
            return result;

        if (result == snort::StreamSplitter::FLUSH)
        {
            ++flush_count;
            offset += fp;
            continue;
        }

        return result;
    }

    return snort::StreamSplitter::STOP;
}

TEST_GROUP(s7commplus_stream_splitter_tests)
{
    void setup() override
    {
        s7commplus_stats = {};
        mock_packet.flow = &mock_flow;
        set_small_pdus_limit(default_small_pdus_limit);
        test_splitter = new S7commplusSplitter(true);
    }
    void teardown() override
    {
        delete test_splitter;
        test_splitter = nullptr;
        mock_flow.gadget = nullptr;
        delete test_inspector;
        test_inspector = nullptr;
        mock_packet.flow = &mock_flow;
    }
};

TEST(s7commplus_stream_splitter_tests, test_splitter_is_paf)
{
    CHECK_TRUE(test_splitter->is_paf());
}

TEST(s7commplus_stream_splitter_tests, inspector_get_splitter_returns_paf)
{
    auto* splitter = test_inspector->get_splitter(true);
    CHECK_TRUE(splitter != nullptr);
    CHECK_TRUE(splitter->is_paf());
    delete splitter;
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
    const auto* test_data = reinterpret_cast<const uint8_t*>("\x03\x00\x00\x10\x02\x00");
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
    const auto* test_data = reinterpret_cast<const uint8_t*>(
        "\x03\x00\x00\x10\x02\x0e\x00\x00\x01\x01\x20");
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
    const auto* test_data = reinterpret_cast<const uint8_t*>(
        "\x03\x00\x00\x24\x06\xe0\x00\x00\x01\x01\x00");
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
    const auto* test_data = reinterpret_cast<const uint8_t*>(
        "\x03\x00\x00\x24\x06\xe0\x00\x00\x01\x01\x01");
    uint32_t test_data_len = 11;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_flush_on_data_transfer_correct_s7_protocol)
{
    const auto* test_data = reinterpret_cast<const uint8_t*>(
        "\x03\x00\x00\x24\x06\xf0\x80\x72");
    uint32_t test_data_len = 8;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);
}

TEST(s7commplus_stream_splitter_tests, splitter_search_and_flush_correct_s7_protocol)
{
    const auto* test_data = reinterpret_cast<const uint8_t*>("\x03\x00");
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
    const auto* test_data = reinterpret_cast<const uint8_t*>(
        "\x03\x00\x00\x24\x06\xf0\x00");
    uint32_t test_data_len = 7;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::FLUSH);
    CHECK_EQUAL(flush_point, 36);
}

TEST(s7commplus_stream_splitter_tests, splitter_abort_on_data_transfer_incorrect_s7_protocol)
{
    const auto* test_data = reinterpret_cast<const uint8_t*>(
        "\x03\x00\x00\x24\x06\xf0\x80\x34");
    uint32_t test_data_len = 8;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(result, snort::StreamSplitter::ABORT);
}

TEST(s7commplus_stream_splitter_tests, splitter_flush_on_small_cotp_fragment)
{
    const auto* test_data = reinterpret_cast<const uint8_t*>("\x03\x00\x00\x07\x02\xf0\x00");
    uint32_t test_data_len = 7;
    uint32_t flush_point = 0;

    flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(flush_point, 7);
    CHECK_EQUAL(0, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, splitter_flush_on_plausible_sized_cotp_fragment)
{
    const auto* test_data = reinterpret_cast<const uint8_t*>("\x03\x00\x00\x0b\x02\xf0\x00\x72\x01\x55\x55");
    uint32_t test_data_len = 11;
    uint32_t flush_point = 0;
    auto result = test_splitter->scan(&mock_packet, test_data, test_data_len, 0, &flush_point);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(flush_point, 11);
    CHECK_EQUAL(0, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, single_small_frame_never_drops)
{
    delete test_splitter;
    set_small_pdus_limit(1);
    test_splitter = new S7commplusSplitter(true);

    std::vector<uint8_t> data;
    append_empty_fragment(data);

    uint32_t flush_point = 0;
    const auto result = test_splitter->scan(&mock_packet, data.data(), data.size(), 0, &flush_point);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(data.size(), flush_point);
    CHECK_EQUAL(0, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, abort_when_small_pdus_limit_exceeded)
{
    delete test_splitter;
    set_small_pdus_limit(2);
    test_splitter = new S7commplusSplitter(true);

    std::vector<uint8_t> data;
    append_plausible_fragment(data);
    append_empty_fragment(data);
    append_empty_fragment(data);
    append_empty_fragment(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*test_splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(3, flush_count);
    CHECK_EQUAL(1, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, disabled_limits_allow_many_consecutive_small_frames)
{
    delete test_splitter;
    set_small_pdus_limit(0);
    test_splitter = new S7commplusSplitter(true);

    const auto data = consecutive_small_frames(default_small_pdus_limit + 1);
    unsigned flush_count = 0;
    const auto result = scan_frames(*test_splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(default_small_pdus_limit + 1, flush_count);
    CHECK_EQUAL(0, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, allows_up_to_small_pdus_limit)
{
    delete test_splitter;
    set_small_pdus_limit(2);
    test_splitter = new S7commplusSplitter(true);

    std::vector<uint8_t> data;
    append_empty_fragment(data);
    append_empty_fragment(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*test_splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(2, flush_count);
    CHECK_EQUAL(0, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, missing_gadget_uses_default_small_pdu_limit)
{
    mock_flow.gadget = nullptr;

    const auto allowed = consecutive_small_frames(default_small_pdus_limit);
    unsigned flush_count = 0;
    auto result = scan_frames(*test_splitter, allowed, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(default_small_pdus_limit, flush_count);
    CHECK_EQUAL(0, s7commplus_stats.small_pdu_aborts);

    delete test_splitter;
    test_splitter = new S7commplusSplitter(true);

    const auto exceeded = consecutive_small_frames(default_small_pdus_limit + 1);
    flush_count = 0;
    result = scan_frames(*test_splitter, exceeded, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(default_small_pdus_limit, flush_count);
    CHECK_EQUAL(1, s7commplus_stats.small_pdu_aborts);
}

TEST(s7commplus_stream_splitter_tests, missing_flow_uses_default_small_pdu_limit)
{
    mock_packet.flow = nullptr;

    const auto data = consecutive_small_frames(default_small_pdus_limit + 1);
    unsigned flush_count = 0;
    const auto result = scan_frames(*test_splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(default_small_pdus_limit, flush_count);
    CHECK_EQUAL(1, s7commplus_stats.small_pdu_aborts);
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
