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
// http_brotli_decompression_test.cc author Oleksandr Fedorych <ofedoryc@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <string_view>

#include "pub_sub/http_form_data_event.h"
#include "pub_sub/http_transaction_end_event.h"
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

namespace snort
{
unsigned FlowData::flow_data_id = 0;
FlowData::FlowData(unsigned)
    : id(0)
{ }
FlowData::~FlowData() = default;

int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
fd_status_t File_Decomp_StopFree(fd_session_t*) { return File_Decomp_OK; }
uint32_t str_to_hash(const uint8_t*, size_t) { return 0; }

FlowDataStore::~FlowDataStore() = default;
FlowData* FlowDataStore::get(unsigned) const { return nullptr; }
void FlowDataStore::set(FlowData*) { }
Flow::~Flow() = default;

unsigned DataBus::get_id(PubKey const&) { return 0; }
void DataBus::publish(unsigned int, unsigned int, DataEvent&, Flow*) { }

HttpTransactionEndEvent::HttpTransactionEndEvent(const HttpTransaction* const trans)
    : transaction(trans)
{ }

Inspector::Inspector()
    : ref_count(nullptr)
{ }

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
    va_list)
{ }
}

THREAD_LOCAL const snort::Trace* http_trace = nullptr;

HttpParaList::UriParam::UriParam() = default;
HttpParaList::JsNormParam::~JsNormParam()
{ }
HttpParaList::~HttpParaList() = default;

void HttpFormDataEvent::format_as_uri() const { }

unsigned Http2FlowData::inspector_id = 0;
uint32_t Http2FlowData::get_processing_stream_id() const { return 0; }

HttpInspect::HttpInspect(const HttpParaList* params)
    : params(params), xtra_trueip_id(0), xtra_uri_id(0)
    , xtra_host_id(0), xtra_jsnorm_id(0)
{ }
HttpInspect::~HttpInspect() = default;
bool HttpInspect::configure(SnortConfig*) { return true; }
void HttpInspect::show(const SnortConfig*) const { }
bool HttpInspect::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&) { return true; }

HttpCommon::SectionType HttpInspect::get_type_expected(snort::Flow*, HttpCommon::SourceId) const
{ return SEC_DISCARD; }

void HttpInspect::finish_hx_body(snort::Flow*, HttpCommon::SourceId, HttpCommon::HXBodyState,
    bool) const
{ }

void HttpInspect::set_hx_body_state(snort::Flow*, HttpCommon::SourceId, HttpCommon::HXBodyState) const
{ }

bool HttpInspect::get_fp_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&)
{ return false; }

void HttpInspect::eval(snort::Packet*) { }
void HttpInspect::eval(snort::Packet*, HttpCommon::SourceId, const uint8_t*, uint16_t) { }
void HttpInspect::clear(snort::Packet*) { }
bool HttpInspect::get_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&)
{ return false; }

const uint8_t* HttpInspect::adjust_log_packet(snort::Packet*, uint16_t&) { return nullptr; }
StreamSplitter::Status HttpStreamSplitter::scan(snort::Packet*, const uint8_t*, uint32_t,
    uint32_t, uint32_t*)
{ return StreamSplitter::FLUSH; }

StreamSplitter::Status HttpStreamSplitter::scan(snort::Flow*, const uint8_t*, uint32_t,
    uint32_t*, snort::Packet*)
{ return StreamSplitter::FLUSH; }

const snort::StreamBuffer HttpStreamSplitter::reassemble(snort::Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&)
{
    StreamBuffer buf { nullptr, 0 };
    return buf;
}

bool HttpStreamSplitter::finish(snort::Flow*) { return false; }

void HttpStreamSplitter::prep_partial_flush(snort::Flow*, uint32_t, uint32_t, uint32_t,
    HttpEnums::PartialFlushType)
{ }

HttpTransaction::~HttpTransaction() = default;
void HttpTransaction::delete_transaction(HttpTransaction*, HttpFlowData*) { }
HttpInfractions* HttpTransaction::get_infractions(HttpCommon::SourceId) { return nullptr; }

THREAD_LOCAL PegCount HttpModule::peg_counts[PEG_COUNT_MAX] = { };

namespace
{

constexpr uint8_t basic[] = {
    0x1b, 0x25, 0x00, 0xf8, 0xc5, 0x53, 0x96, 0x8b, 0x49, 0x52, 0x64, 0x13,
    0xbc, 0x3d, 0x69, 0x81, 0x46, 0x9a, 0xd4, 0x04, 0x18, 0x8e, 0x40, 0xff,
    0xc6, 0xb8, 0xca, 0xa1, 0x4f, 0x4c
};

constexpr std::string_view basic_str = "<html><body>Decompressed</body></html>";
constexpr std::string_view garbage = "garbage";

constexpr uint8_t bomb[] = {
    0x5b, 0xff, 0x70, 0x82, 0x7f, 0x02, 0x20, 0x1e, 0x0b, 0x04, 0x72, 0xd1,
    0x04, 0x00
};

}

TEST_GROUP_BASE(brotli_decompression_test, HttpDecompressionFixture)
{
    HttpCompressStream* compress_stream = nullptr;
    HttpInfractions* infractions = nullptr;
    HttpEventGen events;

    uint8_t dst[MAX_OCTETS];
    uint32_t dst_size;

    void setup() override
    {
        HttpDecompressionFixture::setup();

        params.decompression_param.decompress_brotli = true;
        infractions = HttpUnitTestSetup::get_infractions(session_data, SRC_SERVER);

        compress_stream = HttpCompressStream::create(CMP_BROTLI, params.decompression_param,
            infractions, &events);
        HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

        ENUMS_EQUAL_INT(CMP_BROTLI, compress_stream->get_compression_id());
    }
};

TEST(brotli_decompression_test, basic)
{
    const auto result = compress_stream->decompress(basic, std::size(basic), dst, dst_size, true, infractions, &events);

    CHECK(result.has_value());
    CHECK_EQUAL(0, *result);
    CHECK_EQUAL(std::size(basic_str), dst_size);
    ENUMS_EQUAL_INT(CMP_NONE, compress_stream->get_compression_id());
    MEMCMP_EQUAL(std::data(basic_str), dst, dst_size);
}

TEST(brotli_decompression_test, failed)
{
    static constexpr uint32_t step = std::size(basic) / 2;
    static constexpr uint32_t src_size = step + std::size(garbage);

    uint8_t src[src_size];

    memcpy(src, std::data(basic), step);
    memcpy(src + step, std::data(garbage), std::size(garbage));

    const auto result = compress_stream->decompress(src, src_size, dst, dst_size, true, infractions, &events);

    CHECK(*infractions & INF_BROTLI_FAILURE);
    CHECK_FALSE(result.has_value());
    CHECK_EQUAL(0, dst_size);
    ENUMS_EQUAL_INT(CMP_NONE, compress_stream->get_compression_id());
}

TEST(brotli_decompression_test, early_end)
{
    static constexpr uint32_t src_size = std::size(basic) + std::size(garbage);
    uint8_t src[src_size];

    memcpy(src, std::data(basic), std::size(basic));
    memcpy(src + std::size(basic), std::data(garbage), std::size(garbage));

    const auto result = compress_stream->decompress(src, src_size, dst, dst_size, true, infractions, &events);

    CHECK(result.has_value());
    CHECK(*infractions & INF_BROTLI_EARLY_END);
    CHECK_EQUAL(0, *result);
    CHECK_EQUAL(std::size(basic_str) + std::size(garbage), dst_size);
    ENUMS_EQUAL_INT(CMP_NONE, compress_stream->get_compression_id());
    MEMCMP_EQUAL(std::data(basic_str), dst, std::size(basic_str));
    MEMCMP_EQUAL(std::data(garbage), dst + std::size(basic_str), std::size(garbage));
}

TEST(brotli_decompression_test, overrun)
{
    auto result = compress_stream->decompress(std::data(bomb), std::size(bomb), dst, dst_size,
        true, infractions, &events);

    CHECK(result.has_value());
    CHECK_EQUAL(std::size(bomb), *result);
    CHECK_EQUAL(MAX_OCTETS, dst_size);
    CHECK_EQUAL(CMP_BROTLI, compress_stream->get_compression_id());

    dst_size = 0;
    result = compress_stream->decompress(std::data(bomb), std::size(bomb), dst, dst_size, true, infractions, &events);

    CHECK(result.has_value());
    CHECK_EQUAL(std::size(bomb), *result);
    CHECK_EQUAL(MAX_OCTETS, dst_size);
    CHECK_EQUAL(CMP_BROTLI, compress_stream->get_compression_id());

    dst_size = 0;
    result = compress_stream->decompress(std::data(bomb), std::size(bomb), dst, dst_size, true, infractions, &events);

    CHECK(result.has_value());
    CHECK_EQUAL(0, *result);
    CHECK_EQUAL(32440, dst_size);
    ENUMS_EQUAL_INT(CMP_NONE, compress_stream->get_compression_id());
}

TEST(brotli_decompression_test, high_expansion)
{
    params.decompression_param.max_expansion_ratio = 1;

    delete compress_stream;
    compress_stream = HttpCompressStream::create(CMP_BROTLI, params.decompression_param,
        infractions, &events);

    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    auto result = compress_stream->decompress(basic, std::size(basic), dst, dst_size, true, infractions, &events);

    CHECK(*infractions & INF_BROTLI_HIGH_EXPANSION);
    CHECK(result.has_value());
    CHECK_EQUAL(0, *result);
    CHECK_EQUAL(std::size(basic_str), dst_size);
    ENUMS_EQUAL_INT(CMP_NONE, compress_stream->get_compression_id());
    MEMCMP_EQUAL(std::data(basic_str), dst, dst_size);

    dst_size = 0;
    result = compress_stream->decompress(basic, std::size(basic), dst, dst_size,
        false, infractions, &events);
    CHECK_FALSE(result.has_value());
    CHECK_EQUAL(0, dst_size);
}

TEST(brotli_decompression_test, high_expansion_overrun)
{
    params.decompression_param.max_expansion_ratio = 6000;

    delete compress_stream;
    compress_stream = HttpCompressStream::create(CMP_BROTLI, params.decompression_param,
        infractions, &events);

    HttpUnitTestSetup::set_compress_stream(session_data, SRC_SERVER, compress_stream);

    auto result = compress_stream->decompress(bomb, std::size(bomb), dst, dst_size, true, infractions, &events);

    CHECK(result.has_value());
    CHECK_EQUAL(std::size(bomb), *result);
    CHECK_EQUAL(MAX_OCTETS, dst_size);
    ENUMS_EQUAL_INT(CMP_BROTLI, compress_stream->get_compression_id());

    dst_size = 0;
    result = compress_stream->decompress(std::data(bomb), std::size(bomb), dst, dst_size, true, infractions, &events);

    CHECK(result.has_value());
    CHECK(*infractions & INF_BROTLI_HIGH_EXPANSION);
    CHECK_EQUAL(std::size(bomb), *result);
    CHECK_EQUAL(MAX_OCTETS, dst_size);
    ENUMS_EQUAL_INT(CMP_NONE, compress_stream->get_compression_id());

    dst_size = 0;
    result = compress_stream->decompress(std::data(bomb), std::size(bomb), dst, dst_size,
        false, infractions, &events);
    CHECK_FALSE(result.has_value());
    CHECK_EQUAL(0, dst_size);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
