//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// cip_paf_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../cip.h"
#include "../cip_module.h"
#include "../cip_paf.h"
#include "../cip_parsing.h"
#include "flow/flow.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include <vector>

namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;
Inspector::Inspector() : ref_count(nullptr) { }
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
FlowDataStore::~FlowDataStore() = default;
const StreamBuffer StreamSplitter::reassemble(Flow*, uint32_t, uint32_t,
    const uint8_t*, uint32_t, uint32_t, uint32_t&) { return { nullptr, 0 }; }
unsigned StreamSplitter::max(snort::Flow*) { return 0; }
}

Cip::Cip(CipProtoConf* pc) : config(pc)
{ }

Cip::~Cip()
{ }

bool Cip::configure(snort::SnortConfig*)
{ return true; }

void Cip::show(const snort::SnortConfig*) const
{ }

void Cip::eval(snort::Packet*)
{ }

class snort::StreamSplitter* Cip::get_splitter(bool)
{ return nullptr; }

bool enip_command_valid(uint16_t command)
{ return !((0x0006 <= command && command <= 0x0062) || (0x00C8 <= command)); }

THREAD_LOCAL CipStats cip_stats = {};

static snort::Packet mock_packet(true);

// Flow's constructor, destructor and vtable live in flow.cc, which this test
// does not link, and stubbing them here would clash with the revisions that
// declare them inline. The splitter only reads Flow::gadget, so back the mock
// flow with zeroed static storage and never run its constructor or destructor.
alignas(snort::Flow) static uint8_t mock_flow_storage[sizeof(snort::Flow)];
static snort::Flow* const mock_flow = reinterpret_cast<snort::Flow*>(mock_flow_storage);

static void append_nop_frame(std::vector<uint8_t>& buf)
{
    const size_t start = buf.size();
    buf.resize(start + ENIP_HEADER_SIZE, 0);
}

static void append_enip_frame(std::vector<uint8_t>& buf, uint16_t command, uint16_t payload_len)
{
    const size_t start = buf.size();
    buf.resize(start + ENIP_HEADER_SIZE + payload_len, 0);
    buf[start] = command & 0xff;
    buf[start + 1] = (command >> 8) & 0xff;
    buf[start + 2] = payload_len & 0xff;
    buf[start + 3] = (payload_len >> 8) & 0xff;
}

static snort::StreamSplitter::Status scan_frames(CipSplitter& splitter,
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

TEST_GROUP(cip_paf_config_tests)
{
    CipSplitter* splitter;
    CipProtoConf config;
    Cip* inspector;

    void setup() override
    {
        cip_stats = {};
        config = {};
        config.small_pdus_limit = CIP_DEFAULT_SMALL_PDUS_LIMIT;
        inspector = new Cip(&config);
        mock_flow->gadget = inspector;
        mock_packet.flow = mock_flow;
        splitter = new CipSplitter(true);
    }

    void teardown() override
    {
        delete splitter;
        mock_packet.flow = nullptr;
        mock_flow->gadget = nullptr;
        delete inspector;
    }
};

TEST(cip_paf_config_tests, splitter_is_paf)
{
    CHECK_TRUE(splitter->is_paf());
}

TEST(cip_paf_config_tests, search_when_header_incomplete)
{
    const uint8_t data[] = { 0x00, 0x00, 0x00 };
    uint32_t fp = 0;

    const auto result = splitter->scan(&mock_packet, data, sizeof(data), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::SEARCH, result);
}

TEST(cip_paf_config_tests, flush_single_nop_frame)
{
    std::vector<uint8_t> data;
    append_nop_frame(data);

    uint32_t fp = 0;
    const auto result = splitter->scan(&mock_packet, data.data(), data.size(), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(ENIP_HEADER_SIZE, fp);
    CHECK_EQUAL(0, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, flush_single_useful_frame)
{
    std::vector<uint8_t> data;
    append_enip_frame(data, ENIP_COMMAND_SEND_RR_DATA, 6);

    uint32_t fp = 0;
    const auto result = splitter->scan(&mock_packet, data.data(), data.size(), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(ENIP_HEADER_SIZE + 6, fp);
    CHECK_EQUAL(0, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, single_small_frame_never_aborts)
{
    config.small_pdus_limit = 1;

    std::vector<uint8_t> data;
    append_nop_frame(data);

    uint32_t fp = 0;
    const auto result = splitter->scan(&mock_packet, data.data(), data.size(), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(ENIP_HEADER_SIZE, fp);
    CHECK_EQUAL(0, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, disabled_limits_allow_many_packed_small_frames)
{
    config.small_pdus_limit = 0;

    std::vector<uint8_t> data;
    for (int i = 0; i < 35; ++i)
        append_nop_frame(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(35, flush_count);
    CHECK_EQUAL(0, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, abort_when_small_pdus_limit_exceeded)
{
    config.small_pdus_limit = 2;

    std::vector<uint8_t> data;
    append_enip_frame(data, ENIP_COMMAND_SEND_RR_DATA, 6);
    append_nop_frame(data);
    append_nop_frame(data);
    append_nop_frame(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(3, flush_count);
    CHECK_EQUAL(1, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, allows_up_to_small_pdus_limit)
{
    config.small_pdus_limit = 2;

    std::vector<uint8_t> data;
    append_nop_frame(data);
    append_nop_frame(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(2, flush_count);
    CHECK_EQUAL(0, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, missing_gadget_uses_default_small_pdus_limit)
{
    mock_packet.flow = nullptr;
    config.small_pdus_limit = 0;

    std::vector<uint8_t> data;
    for (int i = 0; i < CIP_DEFAULT_SMALL_PDUS_LIMIT + 1; ++i)
        append_nop_frame(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(CIP_DEFAULT_SMALL_PDUS_LIMIT, flush_count);
    CHECK_EQUAL(1, cip_stats.small_pdu_aborts);
}

TEST(cip_paf_config_tests, useful_frame_resets_small_pdu_run)
{
    config.small_pdus_limit = 2;

    std::vector<uint8_t> data;
    append_nop_frame(data);
    append_nop_frame(data);
    append_enip_frame(data, ENIP_COMMAND_SEND_RR_DATA, 6);
    append_nop_frame(data);
    append_nop_frame(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(5, flush_count);
    CHECK_EQUAL(0, cip_stats.small_pdu_aborts);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
