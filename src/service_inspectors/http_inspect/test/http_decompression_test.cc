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
// http_decompression_test.cc author Oleksandr Fedorych <ofedoryc@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "pub_sub/http_transaction_end_event.h"
#include "pub_sub/http_form_data_event.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_compress_stream.h"
#include "service_inspectors/http_inspect/http_cutter.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_event.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_module.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_transaction.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"

#include "http_unit_test_helpers.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

static const uint8_t deflate_compressed[] = {
    0x78, 0x9c, 0x63, 0x60, 0xc0, 0x07, 0x00, 0x00, 0x1e, 0x00, 0x01
};
static constexpr uint32_t deflate_compressed_size = sizeof(deflate_compressed);

static const uint8_t gzip_compressed[] = {
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0x63, 0x60, 0xc0, 0x07, 0x00, 0xb5, 0x3e, 0x04, 0x00, 0x1e,
    0x00, 0x00, 0x00
};
static constexpr uint32_t gzip_compressed_size = sizeof(gzip_compressed);

static constexpr uint32_t scan_buf_size = 2000;

namespace snort
{
unsigned FlowData::flow_data_id = 0;
FlowData::FlowData(unsigned) :   id(0) { }
FlowData::~FlowData() = default;
FlowDataStore::~FlowDataStore() = default;
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
fd_status_t File_Decomp_StopFree(fd_session_t*) { return File_Decomp_OK; }
uint32_t str_to_hash(const uint8_t*, size_t) { return 0; }
FlowData* FlowDataStore::get(unsigned) const { return nullptr; }
void FlowDataStore::set(FlowData*) { }
Flow::~Flow() = default;
unsigned DataBus::get_id(PubKey const&) { return 0; }
void DataBus::publish(unsigned int, unsigned int, DataEvent&, Flow*) { }
HttpTransactionEndEvent::HttpTransactionEndEvent(const HttpTransaction* const trans)
    :   transaction(trans) { }
Inspector::Inspector() :   ref_count(nullptr) { }
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
const StreamBuffer StreamSplitter::reassemble(snort::Flow*, unsigned int, unsigned int,
    unsigned char const*, unsigned int, unsigned int, unsigned int&)
{
    StreamBuffer buf { nullptr, 0 };
    return buf;
}

unsigned StreamSplitter::max(snort::Flow*) { return 0; }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }
void trace_vprintf(const char*, TraceLevel, const char*, const snort::Packet*, const char*,
    va_list) { }
}

THREAD_LOCAL const snort::Trace* http_trace = nullptr;

HttpParaList::UriParam::UriParam() :   uri_char{} { }
HttpParaList::JsNormParam::~JsNormParam() { }
HttpParaList::~HttpParaList() { }

void HttpFormDataEvent::format_as_uri() const { }

unsigned Http2FlowData::inspector_id = 0;
uint32_t Http2FlowData::get_processing_stream_id() const { return 0; }
HttpInspect::HttpInspect(const HttpParaList* para)
    :   params(para), xtra_trueip_id(0), xtra_uri_id(0), xtra_host_id(0), xtra_jsnorm_id(0) { }
HttpInspect::~HttpInspect() = default;
bool HttpInspect::configure(SnortConfig*) { return true; }
void HttpInspect::show(const SnortConfig*) const { }
bool HttpInspect::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&) { return true; }
HttpCommon::SectionType HttpInspect::get_type_expected(snort::Flow*, HttpCommon::SourceId) const
{ return SEC_DISCARD; }
void HttpInspect::finish_hx_body(snort::Flow*, HttpCommon::SourceId, HttpCommon::HXBodyState,
    bool) const { }
void HttpInspect::set_hx_body_state(snort::Flow*, HttpCommon::SourceId,
    HttpCommon::HXBodyState) const { }
bool HttpInspect::get_fp_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
void HttpInspect::eval(snort::Packet*) { }
void HttpInspect::eval(snort::Packet*, HttpCommon::SourceId, const uint8_t*, uint16_t) { }
void HttpInspect::clear(snort::Packet*) { }
bool HttpInspect::get_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
const uint8_t* HttpInspect::adjust_log_packet(snort::Packet*, uint16_t&) { return nullptr; }
StreamSplitter::Status HttpStreamSplitter::scan(snort::Packet*, const uint8_t*, uint32_t,
    uint32_t, uint32_t*) { return StreamSplitter::FLUSH; }
StreamSplitter::Status HttpStreamSplitter::scan(snort::Flow*, const uint8_t*, uint32_t,
    uint32_t*, snort::Packet*) { return StreamSplitter::FLUSH; }
const snort::StreamBuffer HttpStreamSplitter::reassemble(snort::Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&)
{
    StreamBuffer buf { nullptr, 0 };
    return buf;
}

bool HttpStreamSplitter::finish(snort::Flow*) { return false; }
void HttpStreamSplitter::prep_partial_flush(snort::Flow*, uint32_t, uint32_t, uint32_t) { }
void HttpMsgSection::clear_tmp_buffers() { }

HttpTransaction::~HttpTransaction() = default;
void HttpTransaction::delete_transaction(HttpTransaction*, HttpFlowData*) { }
HttpInfractions* HttpTransaction::get_infractions(HttpCommon::SourceId) { return nullptr; }

THREAD_LOCAL PegCount HttpModule::peg_counts[PEG_COUNT_MAX] = { };
const Field Field::FIELD_NULL { STAT_NO_SOURCE };

struct HttpDecompressionFixture : public Utest
{
    Flow* const flow = new Flow;
    HttpParaList params;
    // cppcheck-suppress constVariablePointer
    HttpFlowData* session_data = nullptr;

    void setup() override
    {
        flow->gadget = new HttpInspect(&params);
        // cppcheck-suppress unreadVariable
        session_data = new HttpFlowData(flow, &params);
    }

    void teardown() override
    {
        delete session_data;
        session_data = nullptr;
        delete flow->gadget;
        flow->gadget = nullptr;
        delete flow;
    }
};

TEST_GROUP_BASE(cl_cutter_decompression_test, HttpDecompressionFixture)
{
};

TEST(cl_cutter_decompression_test, long_body_deflate_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = deflate_compressed_size;
    const uint32_t remaining = scan_buf_size;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyClCutter cutter(static_cast<int64_t>(remaining), false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    const auto result = cutter.cut(scan_buf, scan_buf_size, infractions, &events,
        flow_target, true, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(0, cutter.get_octets_seen());
    CHECK_EQUAL(7, cutter.get_num_flush());
    // cppcheck-suppress syntaxError
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());
}

TEST(cl_cutter_decompression_test, long_body_gzip_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_GZIP);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_size = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_size);

    const uint32_t flow_target = gzip_compressed_size;
    const uint32_t remaining = scan_buf_size;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, gzip_compressed, gzip_compressed_size);

    HttpBodyClCutter cutter(static_cast<int64_t>(remaining), false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    const auto result = cutter.cut(scan_buf, scan_buf_size, infractions, &events,
        flow_target, true, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(0, cutter.get_octets_seen());
    CHECK_EQUAL(15, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());
}

TEST(cl_cutter_decompression_test, octets_seen_long_section_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = 10;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyClCutter cutter(10, false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, 7, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(6, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());

    // remaining after the two cuts above is 2 bytes, so when we send the next 3 bytes, only 2 are
    // flushed.
    result = cutter.cut(scan_buf + 8, 3, infractions, &events, flow_target, false, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(2, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());
}

TEST(cl_cutter_decompression_test, octets_seen_no_stretch_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_GZIP);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_size = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_size);

    const uint32_t flow_target = gzip_compressed_size;
    const uint32_t remaining = scan_buf_size;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, gzip_compressed, gzip_compressed_size);

    HttpBodyClCutter cutter(static_cast<int64_t>(remaining), false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, scan_buf_size - 1, infractions, &events,
        flow_target, true, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(14, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());

    result = cutter.cut(scan_buf, scan_buf_size, infractions, &events, 2000, false, HX_BODY_NOT_COMPLETE);
    // If the cutter computed remaining correctly in the previous cut() call, it will return 1984
    // bytes to be flushed.
    // Otherwise, it will return 1985 bytes because we haven't accounted for octets_seen in the
    // previous cut() call where remaining was computed.
    CHECK_EQUAL(SCAN_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(1984, cutter.get_num_flush());
    CHECK_COMPARE(2000, >, cutter.get_num_flush());
}

TEST(cl_cutter_decompression_test, octets_seen_mid_segment_stretch_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = 240;

    uint8_t scan_buf[scan_buf_size] = { };
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyClCutter cutter(1800, false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, 1700, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(6, cutter.get_num_flush());
    CHECK_COMPARE(flow_target - cutter.get_octets_seen(), >, cutter.get_num_flush());

    result = cutter.cut(scan_buf, scan_buf_size, infractions, &events, 2000, false, HX_BODY_NOT_COMPLETE);
    // If the cutter computed remaining correctly in the previous cut() call, it will return 1792
    // bytes to be flushed.
    // Otherwise, it will return 1793 bytes because we haven't accounted for octets_seen in the
    // previous cut() call where remaining was computed.
    CHECK_EQUAL(SCAN_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(1792, cutter.get_num_flush());
    CHECK_COMPARE(2000, >, cutter.get_num_flush());
}

TEST(cl_cutter_decompression_test, octets_seen_last_segment_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = 240;

    uint8_t scan_buf[scan_buf_size] = { };
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyClCutter cutter(10, false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, 9, infractions, &events, flow_target, false, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(6, cutter.get_num_flush());
    CHECK_COMPARE((flow_target - cutter.get_octets_seen()), >, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 10, 10, infractions, &events, flow_target, false, HX_BODY_NOT_COMPLETE);
    // Here we verify that remaining is computed correctly when stretching is not allowed.
    // If remaining is computed correctly, we will receive SCAN_FOUND. Otherwise, SCAN_NOT_FOUND.
    CHECK_EQUAL(SCAN_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(2, cutter.get_num_flush());
    CHECK_COMPARE((flow_target - cutter.get_octets_seen()), >, cutter.get_num_flush());
}

TEST_GROUP_BASE(old_cutter_decompression_test, HttpDecompressionFixture)
{
};

TEST(old_cutter_decompression_test, no_stretch_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = 8;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyOldCutter cutter(false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, 7, infractions, &events, flow_target, false, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(6, cutter.get_num_flush());
}

TEST(old_cutter_decompression_test, large_body_deflate_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_size = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS]();
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_size);

    // flow_target = compressed size; send a larger buffer so length >= flow_target
    const uint32_t flow_target = deflate_compressed_size;

    uint8_t scan_buf[scan_buf_size] = { };
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyOldCutter cutter(false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    const auto result = cutter.cut(scan_buf, scan_buf_size, infractions, &events,
        flow_target, false, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(0, cutter.get_octets_seen());
    CHECK_EQUAL(7, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());
}

TEST(old_cutter_decompression_test, large_body_gzip_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_GZIP);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_size = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS]();
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_size);

    const uint32_t flow_target = gzip_compressed_size;

    uint8_t scan_buf[scan_buf_size] = { };
    memcpy(scan_buf, gzip_compressed, gzip_compressed_size);

    HttpBodyOldCutter cutter(false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    const auto result = cutter.cut(scan_buf, scan_buf_size, infractions, &events,
        flow_target, false, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(0, cutter.get_octets_seen());
    CHECK_EQUAL(15, cutter.get_num_flush());
    CHECK_COMPARE(flow_target, >, cutter.get_num_flush());
}

TEST_GROUP_BASE(hx_cutter_decompression_test, HttpDecompressionFixture)
{
};

TEST(hx_cutter_decompression_test, octets_seen_section_not_complete_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = 8;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyHXCutter cutter(20, false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, 7, infractions, &events, flow_target, false, HX_BODY_NOT_COMPLETE);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(6, cutter.get_num_flush());
}

TEST(hx_cutter_decompression_test, octets_seen_last_segment_overrun)
{
    auto* compress_stream = new HttpCompressStream;
    compress_stream->setup(CMP_DEFLATE);
    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    const uint32_t pre_filled_len = MAX_OCTETS - 5;
    auto* pre_filled_buf = new uint8_t[MAX_OCTETS];
    HttpUnitTestSetup::set_partial_buffer(session_data, SRC_SERVER, pre_filled_buf, pre_filled_len);

    const uint32_t flow_target = 8;

    uint8_t scan_buf[scan_buf_size];
    memcpy(scan_buf, deflate_compressed, deflate_compressed_size);

    HttpBodyHXCutter cutter(20, false, nullptr, session_data, SRC_SERVER);

    auto* infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);
    HttpEventGen events;

    auto result = cutter.cut(scan_buf, 1, infractions, &events, flow_target, true, HX_BODY_NOT_COMPLETE);
    CHECK_EQUAL(SCAN_NOT_FOUND, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(0, cutter.get_num_flush());

    result = cutter.cut(scan_buf + 1, 8, infractions, &events, flow_target, false, HX_BODY_LAST_SEG);
    // num_flush is reduced because decompress ran out of space
    CHECK_EQUAL(SCAN_FOUND_PIECE, result);
    CHECK_EQUAL(1, cutter.get_octets_seen());
    CHECK_EQUAL(6, cutter.get_num_flush());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

