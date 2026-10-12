//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_context_data_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>
#include <cstring>

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "flow/stream_flow.h"
#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_context_data.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace HttpEnums;

long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

namespace
{
    IpsContext* test_context = nullptr;
    IpsContextData* test_context_data = nullptr;
}

namespace snort
{
FlowDataStore::~FlowDataStore() = default;
Packet::Packet(bool) { }
Packet::~Packet() = default;

unsigned IpsContextData::get_ips_id()
{
    return 1;
}
}

IpsContext::IpsContext(unsigned) { }
IpsContext::~IpsContext() = default;
IpsContext* DetectionEngine::get_next_context() { return test_context; }
void DetectionEngine::wait_for_context() { }
IpsContextData* DetectionEngine::get_data(unsigned, IpsContext*) { return test_context_data; }
IpsContextData* DetectionEngine::get_data(unsigned) { return test_context_data; }
void DetectionEngine::set_data(unsigned, IpsContextData* data) { test_context_data = data; }
// cppcheck-suppress functionStatic
void IpsContext::set_context_data(unsigned, IpsContextData* context_data)
{ test_context_data = context_data; }

// cppcheck-suppress functionStatic
const Field& HttpMsgSection::get_classic_buffer(unsigned, uint64_t, uint64_t)
{
    return Field::FIELD_NULL;
}

class TestStreamIntf : public snort::StreamFlowIntf
{
public:
    explicit TestStreamIntf(HttpMsgSection* section) : hi_section(section) { }

    void get_stream_id(const snort::Flow*, int64_t& stream_id) override
    { stream_id = 1; }

    void* get_hi_msg_section(const snort::Flow*) override
    { return hi_section; }

    AppId get_appid_from_stream(const snort::Flow*) override
    { return APP_ID_NONE; }

private:
    HttpMsgSection* const hi_section;
};

static void clear_test_context_data()
{
    delete test_context_data;
    test_context_data = nullptr;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

TEST_GROUP(http_context_data_test)
{
    void setup() override
    {
        test_context = new IpsContext;
    }

    void teardown() override
    {
        if ( test_context_data )
        {
            test_context_data->clear();
            delete test_context_data;
            test_context_data = nullptr;
        }

        delete test_context;
        test_context = nullptr;
    }
};

TEST(http_context_data_test, claimed_buffer_survives_context_clear)
{
    uint8_t* buffer = new uint8_t[4];

    HttpContextData::save_pending_section_buffer(buffer);
    CHECK(test_context_data != nullptr);

    HttpContextData::claim_pending_section_buffer(test_context, buffer);

    // clear() must not delete a successfully claimed buffer.
    test_context_data->clear();
    delete[] buffer;
}

TEST(http_context_data_test, unclaimed_buffer_is_released_on_context_clear)
{
    HttpContextData::save_pending_section_buffer(new uint8_t[4]);
    CHECK(test_context_data != nullptr);

    // CppUTest's leak detection verifies that the buffer is released.
    test_context_data->clear();
}

TEST_GROUP(http_context_data_capture_test)
{
    void setup() override
    {
        HttpContextData::ips_id = 1;
    }

    void teardown() override
    {
        clear_test_context_data();
        HttpContextData::ips_id = 0;
    }
};

TEST(http_context_data_capture_test, capture_splitter_first_write_wins_mode)
{
    const HttpSplitterSnapshot& first = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_300, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 300;
            snap.request_line_length = 299;
            snap.reason_code_detail_300 = BAD_VERSION;
        });

    const HttpSplitterSnapshot& second = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_300, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 1;
            snap.request_line_length = 2;
            snap.reason_code_detail_300 = NONE;
        });

    POINTERS_EQUAL(&first, &second);
    CHECK_EQUAL(300, second.request_size);
    CHECK_EQUAL(299, second.request_line_length);
    CHECK_EQUAL(BAD_VERSION, second.reason_code_detail_300);
}

TEST(http_context_data_capture_test, capture_splitter_refresh_mode)
{
    const HttpSplitterSnapshot& first = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_298, HttpContextData::CaptureMode::Refresh,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 50;
        });
    CHECK_EQUAL(50, first.request_size);

    const HttpSplitterSnapshot& second = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_298, HttpContextData::CaptureMode::Refresh,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 5000;
        });

    POINTERS_EQUAL(&first, &second);
    CHECK_EQUAL(5000, second.request_size);
}

TEST(http_context_data_capture_test, slots_are_isolated_across_sids)
{
    const HttpSplitterSnapshot& snap_300 = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_300, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 25;
            snap.reason_code_detail_300 = BAD_VERSION;
        });

    const HttpSplitterSnapshot& snap_298 = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_298, HttpContextData::CaptureMode::Refresh,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 330;
        });

    CHECK(&snap_300 != &snap_298);
    CHECK_EQUAL(25, snap_300.request_size);
    CHECK_EQUAL(BAD_VERSION, snap_300.reason_code_detail_300);
    CHECK_EQUAL(330, snap_298.request_size);
}

TEST(http_context_data_capture_test, clear_drops_splitter_snapshots)
{
    HttpContextData::capture_splitter(
        SplitterSlot::SLOT_300, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 300;
        });
    HttpContextData::capture_splitter(
        SplitterSlot::SLOT_298, HttpContextData::CaptureMode::Refresh,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 298;
        });

    auto* data = static_cast<HttpContextData*>(snort::DetectionEngine::get_data(HttpContextData::ips_id));
    data->clear();

    const HttpSplitterSnapshot& fresh = HttpContextData::capture_splitter(
        SplitterSlot::SLOT_300, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 299;
        });

    CHECK_EQUAL(299, fresh.request_size);
}

TEST(http_context_data_capture_test, get_view_uses_stream_intf_section_without_context_snapshot)
{
    HttpContextData::capture_splitter(
        SplitterSlot::SLOT_298, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 298;
        });

    char section_storage;
    auto* section = reinterpret_cast<HttpMsgSection*>(&section_storage);
    TestStreamIntf stream_intf(section);
    alignas(snort::Flow) uint8_t flow_storage[sizeof(snort::Flow)] = {};
    auto* flow = reinterpret_cast<snort::Flow*>(flow_storage);
    flow->stream_intf = &stream_intf;
    snort::Packet packet(false);
    packet.flow = flow;

    const HttpContextDataView view = HttpContextData::get_view(&packet);

    POINTERS_EQUAL(section, view.current_section);
    for (const auto* snap : view.splitter_snapshots)
        POINTERS_EQUAL(nullptr, snap);
}

TEST(http_context_data_capture_test, get_view_uses_context_snapshot_for_stream_intf_without_section)
{
    HttpContextData::capture_splitter(
        SplitterSlot::SLOT_298, HttpContextData::CaptureMode::FirstWriteWins,
        [](HttpSplitterSnapshot& snap)
        {
            snap.request_size = 298;
        });

    TestStreamIntf stream_intf(nullptr);
    alignas(snort::Flow) uint8_t flow_storage[sizeof(snort::Flow)] = {};
    auto* flow = reinterpret_cast<snort::Flow*>(flow_storage);
    flow->stream_intf = &stream_intf;
    snort::Packet packet(false);
    packet.flow = flow;

    const HttpContextDataView view = HttpContextData::get_view(&packet);

    POINTERS_EQUAL(nullptr, view.current_section);
    const auto* snap_298 = view.splitter_snapshots[static_cast<unsigned>(SplitterSlot::SLOT_298)];
    CHECK(snap_298 != nullptr);
    CHECK_EQUAL(298, snap_298->request_size);
    POINTERS_EQUAL(nullptr, view.splitter_snapshots[static_cast<unsigned>(SplitterSlot::SLOT_300)]);
    POINTERS_EQUAL(nullptr, view.splitter_snapshots[static_cast<unsigned>(SplitterSlot::SLOT_299)]);
}
