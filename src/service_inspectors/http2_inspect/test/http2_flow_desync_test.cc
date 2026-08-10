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
// http2_flow_desync_test.cc author Oleksandr Fedorych <ofedoryc@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_test_input.h"
#include "service_inspectors/http_inspect/http_test_manager.h"
#include "service_inspectors/http_inspect/test/http_unit_test_helpers.h"
#include "service_inspectors/http2_inspect/http2_push_promise_frame.h"

#include "http2_unit_test_helpers.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

namespace snort
{
void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }

int DetectionEngine::queue_event(unsigned, unsigned) { return 0; }

Flow::~Flow() { }

FlowData::FlowData(unsigned) : id(0) { }
FlowData::~FlowData() { }

FlowData* FlowDataStore::get(unsigned) const { return nullptr; }
void FlowDataStore::set(FlowData*) { }
FlowDataStore::~FlowDataStore() { }

Inspector::Inspector() : ref_count(nullptr) { }
void Inspector::add_ref() { }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
bool Inspector::likes(Packet*) { return 0; }
void Inspector::rem_ref() { }
Inspector::~Inspector() { }

Packet::Packet(bool) { }
Packet::~Packet() { }

unsigned StreamSplitter::max(Flow*) { return 0; }
const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned,
    unsigned, const uint8_t*, unsigned, uint32_t, unsigned&) { return { nullptr, 0 }; }

THREAD_LOCAL bool TimeProfilerStats::enabled = false;
}

Field::Field(int32_t, const uint8_t*, bool)
    : strt(nullptr), len(0), own_the_buffer(false) { }
const Field Field::FIELD_NULL { HttpCommon::STAT_NO_SOURCE };
void Field::print(FILE*, const char*) const { }

HttpFlowData::HttpFlowData(snort::Flow*, HttpParaList const* params)
    : FlowData(0), params(params)
{
#ifdef REG_TEST
    seq_num = 0;
#endif
}
void HttpFlowData::finish_hx_body(HttpCommon::SourceId,
    HttpCommon::HXBodyState, bool) { }
HttpFlowData::~HttpFlowData()
{
    for ( size_t i = 0; i < 2; ++i )
    {
        delete events[i];
        delete infractions[i];
    }
}

HttpInspect::HttpInspect(HttpParaList const* params)
    : params(params), xtra_trueip_id(0), xtra_uri_id(0)
    , xtra_host_id(0), xtra_jsnorm_id(0)
{ }
const uint8_t* HttpInspect::adjust_log_packet(snort::Packet*, uint16_t&) { return nullptr; }
void HttpInspect::clear(snort::Packet*) { }
bool HttpInspect::configure(snort::SnortConfig*) { return true; }
void HttpInspect::eval(snort::Packet*) { }
void HttpInspect::eval(snort::Packet*, HttpCommon::SourceId, const uint8_t*, uint16_t) { }
void HttpInspect::finish_hx_body(snort::Flow*, HttpCommon::SourceId,
    HttpCommon::HXBodyState, bool) const { }
void HttpInspect::show(const snort::SnortConfig*) const { }
bool HttpInspect::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&) { return true; }
bool HttpInspect::get_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
bool HttpInspect::get_fp_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
HttpCommon::SectionType HttpInspect::get_type_expected(snort::Flow*,
    HttpCommon::SourceId) const { return HttpCommon::SEC_DISCARD; }
void HttpInspect::set_hx_body_state(snort::Flow*, HttpCommon::SourceId,
    HttpCommon::HXBodyState) const { }
HttpInspect::~HttpInspect() { }

HttpParaList::JsNormParam::~JsNormParam() { }
HttpParaList::~HttpParaList() { }

bool HttpStreamSplitter::finish(snort::Flow*) { return false; }
void HttpStreamSplitter::prep_partial_flush(const snort::Flow*, uint32_t, uint32_t, uint32_t,
    HttpEnums::PartialFlushType) { }
const snort::StreamBuffer HttpStreamSplitter::reassemble(snort::Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&) { return { nullptr, 0 }; }
snort::StreamSplitter::Status HttpStreamSplitter::scan(snort::Packet*, const uint8_t*, uint32_t,
    uint32_t, uint32_t*) { return StreamSplitter::FLUSH; }
snort::StreamSplitter::Status HttpStreamSplitter::scan(snort::Flow*, const uint8_t*, uint32_t,
    uint32_t*, snort::Packet*) { return snort::StreamSplitter::FLUSH; }
snort::StreamSplitter::Status HttpStreamSplitter::status_value(snort::StreamSplitter::Status, bool)
{ return snort::StreamSplitter::FLUSH; }

bool HttpTestInput::finish() { return false; }
void HttpTestInput::flush(uint32_t) { }
void HttpTestInput::reassemble(uint8_t**, unsigned&, unsigned&, unsigned&,
    uint32_t&, HttpCommon::SourceId, bool&) { }
void HttpTestInput::scan(uint8_t*&, uint32_t&, HttpCommon::SourceId, uint64_t) { }

bool HttpTestManager::show_scan = false;
unsigned HttpTestManager::test_input = IN_NONE;
HttpTestInput* HttpTestManager::test_input_source = nullptr;
FILE* HttpTestManager::test_out = nullptr;
unsigned HttpTestManager::test_output = IN_NONE;

Http2Frame* Http2Frame::new_frame(const uint8_t*, const uint32_t, const uint8_t*, const uint32_t,
    Http2FlowData*, HttpCommon::SourceId, const Http2ParaList*, Http2Stream*) { return nullptr; }

THREAD_LOCAL snort::ProfileStats Http2Module::http2_profile;
THREAD_LOCAL PegCount Http2Module::peg_counts[Http2Enums::PEG_COUNT__MAX] = { };

HpackDynamicTable::~HpackDynamicTable() { }

uint32_t Http2PushPromiseFrame::get_promised_stream_id(Http2EventGen* const,
    Http2Infractions* const, const uint8_t*, uint32_t) { return 0; }

snort::StreamSplitter::Status Http2StreamSplitter::scan(snort::Packet*, const uint8_t*, uint32_t,
    uint32_t, uint32_t*) { return snort::StreamSplitter::FLUSH; }
const snort::StreamBuffer Http2StreamSplitter::reassemble(snort::Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&) { return { nullptr, 0 }; }
bool Http2StreamSplitter::finish(snort::Flow*) { return false; }

class Http2FlowDesyncFixture : public Utest
{
public:
    static constexpr auto source_id = HttpCommon::SRC_SERVER;

    bool* abort_flow = nullptr;
    snort::Flow* const flow = new snort::Flow;
    std::queue<uint32_t>* frame_lengths = nullptr;
    Http2FlowData* session_data = nullptr;

    void setup() override
    {
        flow->assistant_gadget = new HttpInspect(nullptr);
        session_data = new Http2FlowData(flow);

        abort_flow = Http2UnitTestSetup::get_abort_flow(session_data, source_id);
        frame_lengths = Http2UnitTestSetup::get_frame_lengths(session_data, source_id);

        CHECK_FALSE(*abort_flow);
        CHECK(std::empty(*frame_lengths));
    }

    void teardown() override
    {
        CHECK(*abort_flow);

        delete session_data;
        delete flow->assistant_gadget;
        delete flow;
    }
};

TEST_GROUP_BASE(http2_data_cutter_desync, Http2FlowDesyncFixture)
{
    // cppcheck-suppress variableScope ; fixture state is consumed by test bodies
    // cppcheck-suppress constVariablePointer ; fixture state is consumed by test bodies
    Http2DataCutter* cutter = nullptr;

    void setup() override
    {
        Http2FlowDesyncFixture::setup();

        // cppcheck-suppress unreadVariable ; fixture state is consumed by test bodies
        cutter = Http2UnitTestSetup::get_data_cutter(session_data, source_id);
    }
};

TEST(http2_data_cutter_desync, scan_skip_over_frame_multiple_lengths)
{
    uint32_t flush_offset = 0;
    uint32_t data_offset = 0;

    frame_lengths->push(10);
    frame_lengths->push(10);

    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    CHECK_EQUAL(snort::StreamSplitter::ABORT,
        cutter->scan(frame, std::size(frame), &flush_offset, data_offset, 0, nullptr));
}

TEST(http2_data_cutter_desync, scan_missing_frame_length_with_stream)
{
    static constexpr uint32_t stream_id = 1;

    auto& stream = Http2UnitTestSetup::get_streams(session_data)->emplace_back(stream_id, session_data);

    stream.set_hi_flow_data(new HttpFlowData(flow, nullptr));
    stream.set_state(source_id, Http2Enums::STREAM_EXPECT_BODY);

    *Http2UnitTestSetup::get_current_stream_id(session_data, source_id) = stream_id;

    uint32_t flush_offset = 0;
    uint32_t data_offset = 0;

    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    CHECK_EQUAL(snort::StreamSplitter::ABORT,
        cutter->scan(frame, std::size(frame), &flush_offset, data_offset, 0, nullptr));
}

TEST(http2_data_cutter_desync, scan_search)
{
    static constexpr uint32_t stream_id = 1;

    auto& stream = Http2UnitTestSetup::get_streams(session_data)->emplace_back(stream_id, session_data);

    stream.set_hi_flow_data(new HttpFlowData(flow, nullptr));
    stream.set_state(source_id, Http2Enums::STREAM_EXPECT_BODY);

    *Http2UnitTestSetup::get_current_stream_id(session_data, source_id) = stream_id;

    uint32_t flush_offset = 0;
    uint32_t data_offset = 0;

    Http2UnitTestSetup::get_frame_bytes_seen(*cutter) = 1;

    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    CHECK_EQUAL(snort::StreamSplitter::ABORT,
        cutter->scan(frame, std::size(frame), &flush_offset, data_offset, 0, nullptr));
}

TEST(http2_data_cutter_desync, missing_frame_length_with_remaining_data_in_reassemble)
{
    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    cutter->reassemble(frame, std::size(frame));
}

TEST_GROUP_BASE(http2_stream_splitter_desync, Http2FlowDesyncFixture)
{
    // cppcheck-suppress unreadVariable ; fixture state is consumed by test bodies
    Http2StreamSplitter splitter { source_id == HttpCommon::SRC_CLIENT };
};

TEST(http2_stream_splitter_desync, invalid_total_in_implement_reassemble)
{
    static constexpr unsigned total = 777;
    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    Http2UnitTestSetup::implement_reassemble(&splitter, session_data, total, 0,
        frame, std::size(frame), 0, source_id);
}

TEST(http2_stream_splitter_desync, missing_frame_lengths_in_implement_reassemble)
{
    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    *Http2UnitTestSetup::get_bytes_scanned(session_data, source_id) = std::size(frame);

    Http2UnitTestSetup::implement_reassemble(&splitter, session_data, std::size(frame), 0,
        frame, std::size(frame), 0, source_id);
}

TEST(http2_stream_splitter_desync, missing_frame_lengths_in_implement_scan)
{
    *Http2UnitTestSetup::get_scan_state(session_data, source_id) = Http2Enums::SCAN_PADDING_LENGTH;
    *Http2UnitTestSetup::get_scan_reamining_frame_octets(session_data, source_id) = 1;

    uint32_t flush_offset = 0;
    snort::Packet packet;

    static constexpr uint8_t frame[Http2Enums::FRAME_HEADER_LENGTH] = { };

    CHECK_EQUAL(snort::StreamSplitter::ABORT,
        Http2UnitTestSetup::implement_scan(&splitter, session_data, frame, std::size(frame),
            &flush_offset, source_id, &packet));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
