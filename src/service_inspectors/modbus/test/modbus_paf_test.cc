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
// modbus_paf_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../modbus.h"
#include "../modbus_module.h"
#include "../modbus_paf.h"
#include "detection/detection_engine.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include <vector>

namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;
const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&) { return { nullptr, 0 }; }
unsigned StreamSplitter::max(snort::Flow*) { return 0; }
int DetectionEngine::queue_event(unsigned, unsigned) { return 0; }

Inspector::Inspector() = default;
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

FlowDataStore::~FlowDataStore() = default;
}

Modbus::Modbus(uint16_t limit) : small_pdus_limit(limit)
{ }

void Modbus::show(const snort::SnortConfig*) const { }
void Modbus::eval(snort::Packet*) { }
bool Modbus::get_buf(snort::InspectionBuffer::Type, snort::Packet*, snort::InspectionBuffer&)
{ return false; }
bool Modbus::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&)
{ return false; }
snort::StreamSplitter* Modbus::get_splitter(bool) { return nullptr; }

// Flow::Flow(), Flow::~Flow() and FlowStash::reset() are inline in some snort3
// revisions and defined in flow.cc / flow_stash.cc in others, so this test can
// neither rely on them nor stub them without breaking one of the two. The
// splitter reads only Flow::gadget, so back the mock flow with zeroed static
// storage and never run its constructor or destructor.
alignas(snort::Flow) static uint8_t mock_flow_storage[sizeof(snort::Flow)];
static snort::Flow& mock_flow = *reinterpret_cast<snort::Flow*>(mock_flow_storage);

THREAD_LOCAL ModbusStats modbus_stats = {};

static constexpr uint16_t default_small_pdus_limit = MODBUS_DEFAULT_SMALL_PDUS_LIMIT;
static constexpr uint32_t MODBUS_EMPTY_PDU_SIZE = 8;
static constexpr uint32_t MODBUS_READ_COILS_PDU_SIZE = 12;

static snort::Packet mock_packet(true);
static Modbus* test_inspector = nullptr;

static void set_small_pdus_limit(uint16_t limit)
{
    delete test_inspector;
    test_inspector = new Modbus(limit);
    mock_flow.gadget = test_inspector;
}

static void append_empty_frame(std::vector<uint8_t>& buf)
{
    static const uint8_t frame[] =
        { 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01 };
    buf.insert(buf.end(), frame, frame + sizeof(frame));
}

static void append_read_coils_frame(std::vector<uint8_t>& buf)
{
    static const uint8_t frame[] =
        { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
    buf.insert(buf.end(), frame, frame + sizeof(frame));
}

static std::vector<uint8_t> consecutive_small_frames(unsigned count)
{
    std::vector<uint8_t> data;
    for (unsigned i = 0; i < count; ++i)
        append_empty_frame(data);
    return data;
}

static snort::StreamSplitter::Status scan_frames(ModbusSplitter& splitter,
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

TEST_GROUP(modbus_paf_config_tests)
{
    ModbusSplitter* splitter;

    void setup() override
    {
        modbus_stats = {};
        mock_packet.flow = &mock_flow;
        set_small_pdus_limit(default_small_pdus_limit);
        splitter = new ModbusSplitter(true);
    }

    void teardown() override
    {
        delete splitter;
        splitter = nullptr;
        mock_flow.gadget = nullptr;
        delete test_inspector;
        test_inspector = nullptr;
        mock_packet.flow = &mock_flow;
    }
};

TEST(modbus_paf_config_tests, splitter_is_paf)
{
    CHECK_TRUE(splitter->is_paf());
}

TEST(modbus_paf_config_tests, search_when_header_incomplete)
{
    const uint8_t data[] = { 0x00, 0x01, 0x00 };
    uint32_t fp = 0;

    const auto result = splitter->scan(&mock_packet, data, sizeof(data), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::SEARCH, result);
}

TEST(modbus_paf_config_tests, flush_single_empty_frame)
{
    std::vector<uint8_t> data;
    append_empty_frame(data);

    uint32_t fp = 0;
    const auto result = splitter->scan(&mock_packet, data.data(), data.size(), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(MODBUS_EMPTY_PDU_SIZE, fp);
    CHECK_EQUAL(0, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, flush_single_read_coils_frame)
{
    std::vector<uint8_t> data;
    append_read_coils_frame(data);

    uint32_t fp = 0;
    const auto result = splitter->scan(&mock_packet, data.data(), data.size(), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(MODBUS_READ_COILS_PDU_SIZE, fp);
    CHECK_EQUAL(0, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, single_small_frame_never_aborts)
{
    delete splitter;
    set_small_pdus_limit(1);
    splitter = new ModbusSplitter(true);

    std::vector<uint8_t> data;
    append_empty_frame(data);

    uint32_t fp = 0;
    const auto result = splitter->scan(&mock_packet, data.data(), data.size(), 0, &fp);

    CHECK_EQUAL(snort::StreamSplitter::FLUSH, result);
    CHECK_EQUAL(MODBUS_EMPTY_PDU_SIZE, fp);
    CHECK_EQUAL(0, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, disabled_limits_allow_many_packed_small_frames)
{
    delete splitter;
    set_small_pdus_limit(0);
    splitter = new ModbusSplitter(true);

    const auto data = consecutive_small_frames(65);
    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(65, flush_count);
    CHECK_EQUAL(0, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, abort_when_small_pdus_limit_exceeded)
{
    delete splitter;
    set_small_pdus_limit(2);
    splitter = new ModbusSplitter(true);

    std::vector<uint8_t> data;
    append_read_coils_frame(data);
    append_empty_frame(data);
    append_empty_frame(data);
    append_empty_frame(data);

    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(3, flush_count);
    CHECK_EQUAL(1, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, allows_up_to_small_pdus_limit)
{
    delete splitter;
    set_small_pdus_limit(2);
    splitter = new ModbusSplitter(true);

    const auto data = consecutive_small_frames(2);
    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(2, flush_count);
    CHECK_EQUAL(0, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, missing_gadget_uses_default_small_pdu_limit)
{
    mock_flow.gadget = nullptr;

    const auto allowed = consecutive_small_frames(default_small_pdus_limit);
    unsigned flush_count = 0;
    auto result = scan_frames(*splitter, allowed, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::STOP, result);
    CHECK_EQUAL(default_small_pdus_limit, flush_count);
    CHECK_EQUAL(0, modbus_stats.small_pdu_aborts);

    delete splitter;
    splitter = new ModbusSplitter(true);

    const auto exceeded = consecutive_small_frames(default_small_pdus_limit + 1);
    flush_count = 0;
    result = scan_frames(*splitter, exceeded, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(default_small_pdus_limit, flush_count);
    CHECK_EQUAL(1, modbus_stats.small_pdu_aborts);
}

TEST(modbus_paf_config_tests, missing_flow_uses_default_small_pdu_limit)
{
    mock_packet.flow = nullptr;

    const auto data = consecutive_small_frames(default_small_pdus_limit + 1);
    unsigned flush_count = 0;
    const auto result = scan_frames(*splitter, data, flush_count);

    CHECK_EQUAL(snort::StreamSplitter::ABORT, result);
    CHECK_EQUAL(default_small_pdus_limit, flush_count);
    CHECK_EQUAL(1, modbus_stats.small_pdu_aborts);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
