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

// http_msg_head_shared_find_next_header_test.cc
// Unit tests for HttpMsgHeadShared::find_next_header() boundary conditions


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_msg_head_shared.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http_unit_test_helpers.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

// Stubs required for linking
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

namespace snort
{
FlowData::FlowData(unsigned) : id(0) {}
FlowData::~FlowData() = default;
FlowDataStore::~FlowDataStore() = default;
Flow::~Flow() = default;
uint32_t str_to_hash(const uint8_t*, size_t) { return 0; }
Inspector::Inspector() {}

Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&)
{
    StreamBuffer buf { nullptr, 0 };
    return buf;
}
unsigned StreamSplitter::max(Flow*) { return 0; }
const char* SnortStrcasestr(const char*, int, const char*) { return nullptr; }
}

// HttpFlowData stubs
unsigned HttpFlowData::inspector_id = 0;
HttpFlowData::HttpFlowData(snort::Flow*, const HttpParaList* params_) :
    snort::FlowData(inspector_id), params(params_) {}
HttpFlowData::~HttpFlowData()
{
    for (int k = 0; k <= 1; k++)
    {
        delete infractions[k];
        delete events[k];
    }
}

HttpParaList::UriParam::UriParam() {}
HttpParaList::JsNormParam::~JsNormParam() {}
HttpParaList::~HttpParaList() {}

// HttpInspect stubs
HttpInspect::HttpInspect(const HttpParaList* para) :
    params(para), xtra_trueip_id(0), xtra_uri_id(0),
    xtra_host_id(0), xtra_jsnorm_id(0) {}
HttpInspect::~HttpInspect() = default;
bool HttpInspect::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&) { return true; }
bool HttpInspect::get_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
HttpCommon::SectionType HttpInspect::get_type_expected(snort::Flow*, HttpCommon::SourceId) const
{ return SEC_DISCARD; }

void HttpInspect::finish_hx_body(snort::Flow*, HttpCommon::SourceId, HttpCommon::HXBodyState,
    bool) const {}
void HttpInspect::set_hx_body_state(snort::Flow*, HttpCommon::SourceId,
    HttpCommon::HXBodyState) const {}
bool HttpInspect::get_fp_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
bool HttpInspect::configure(snort::SnortConfig*) { return true; }
void HttpInspect::show(const snort::SnortConfig*) const {}
void HttpInspect::eval(snort::Packet*) {}
void HttpInspect::eval(snort::Packet*, HttpCommon::SourceId, const uint8_t*, uint16_t) {}
void HttpInspect::clear(snort::Packet*) {}
const uint8_t* HttpInspect::adjust_log_packet(snort::Packet*, uint16_t&) { return nullptr; }

// HttpStreamSplitter stubs
snort::StreamSplitter::Status HttpStreamSplitter::scan(snort::Packet*, const uint8_t*, uint32_t,
    uint32_t, uint32_t*) { return snort::StreamSplitter::FLUSH; }
snort::StreamSplitter::Status HttpStreamSplitter::scan(snort::Flow*, const uint8_t*, uint32_t,
    uint32_t*, snort::Packet*) { return snort::StreamSplitter::FLUSH; }
const snort::StreamBuffer HttpStreamSplitter::reassemble(snort::Flow*, unsigned, unsigned,
    const uint8_t*, unsigned, uint32_t, unsigned&)
{
    snort::StreamBuffer buf { nullptr, 0 };
    return buf;
}
bool HttpStreamSplitter::finish(snort::Flow*) { return false; }
void HttpStreamSplitter::prep_partial_flush(snort::Flow*, uint32_t, uint32_t, uint32_t,
    HttpEnums::PartialFlushType) {}

// HttpMsgSection stubs (http_msg_section.cc not in SOURCES)
HttpMsgSection::HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, HttpCommon::SourceId source_id_, bool buf_owner,
    snort::Flow* flow_, const HttpParaList* params_) :
    msg_text(buf_size, buffer, buf_owner),
    session_data(session_data_),
    flow(flow_),
    params(params_),
    transaction(nullptr),
    trans_num(0),
    status_code_num(0),
    source_id(source_id_),
    version_id(VERS__NOT_PRESENT),
    method_id(METH__NOT_PRESENT),
    tcp_close(false)
{}

static HttpInfractions test_infractions;

void HttpMsgSection::add_infraction(int infraction)
{
    test_infractions += HttpInfractions(infraction);
}

static int test_events = 0;

void HttpMsgSection::create_event(int event_id)
{
    test_events |= event_id;
}

bool HttpMsgSection::run_detection(snort::Packet*) { return false; }
void HttpMsgSection::clear() {}
const Field& HttpMsgSection::classic_normalize(const Field& raw, Field&,
    bool, const HttpParaList::UriParam&) { return raw; }

HttpInfractions* HttpTransaction::get_infractions(HttpCommon::SourceId) { return nullptr; }

// NormalizedHeader stubs
const Field& NormalizedHeader::get_norm(HttpInfractions*, HttpEventGen*,
    const HttpEnums::HeaderId[], const Field[], const int32_t)
{ return Field::FIELD_NULL; }

const Field& NormalizedHeader::get_comma_separated_raw(const HttpMsgHeadShared&,
    HttpInfractions*, HttpEventGen*, const HttpEnums::HeaderId[], const Field[], const int32_t)
{ return Field::FIELD_NULL; }

// Expose protected member function for testing
class HttpMsgHeadTest : public HttpMsgHeadShared
{
public:
    HttpMsgHeadTest(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_) :
        HttpMsgHeadShared(buffer, buf_size, session_data_, source_id_, buf_owner, flow_,
        params_)
    { }

    bool detection_required() const override { return false; }
    void update_flow() override {}
#ifdef REG_TEST
    void print_section(FILE*) override {}
#endif
};

class HttpMsgHeadSharedTestPeer
{
public:
    static int32_t find_next_header_test(HttpMsgHeadShared& msg, const uint8_t* buffer,
        int32_t length, int32_t& num_seps)
    {
        return msg.find_next_header(buffer, length, num_seps);
    }
};

// Test fixture for find_next_header()
TEST_GROUP(find_next_header)
{
    Flow* flow = nullptr;
    HttpParaList params;
    HttpFlowData* flow_data = nullptr;
    HttpMsgHeadTest* msg = nullptr;
    uint8_t dummy = 0;

    void setup() override
    {
        flow = new Flow;
        flow_data = new HttpFlowData(flow, &params);
        flow->gadget = new HttpInspect(&params);
        msg = new HttpMsgHeadTest(&dummy, 0, flow_data, SRC_CLIENT, false, flow, &params);
    }
    void teardown() override
    {
        delete msg;
        delete flow->gadget;
        delete flow_data;
        delete flow;
    }
};

struct FindNextHeaderCase
{
    const char* name;
    const uint8_t* input;
    size_t input_len;
    int32_t exp_num_seps;
    int32_t exp_result;
    bool exp_wrap_inf;
    bool exp_wrap_evt;
    bool partial_flush;
    uint32_t num_excess;
};

static void run_test_case(const FindNextHeaderCase& test_case, HttpMsgHeadTest& msg, HttpFlowData* flow_data)
{
    test_infractions = HttpInfractions();
    test_events = 0;
    HttpUnitTestSetup::set_partial_flush(flow_data, SRC_CLIENT,
        test_case.partial_flush,
        test_case.partial_flush ? test_case.num_excess : 0);

    int32_t num_seps = 0;
    const int32_t input_len = static_cast<int32_t>(test_case.input_len);
    const int32_t result = HttpMsgHeadSharedTestPeer::find_next_header_test(
        msg, test_case.input, input_len, num_seps);

    CHECK_EQUAL_TEXT(test_case.exp_num_seps, num_seps, test_case.name);
    CHECK_EQUAL_TEXT(test_case.exp_result, result, test_case.name);
    CHECK_EQUAL_TEXT(test_case.exp_wrap_inf,
        test_infractions & HttpInfractions(INF_HEADER_WRAPPING),
        test_case.name);
    CHECK_EQUAL_TEXT(test_case.exp_wrap_evt,
        static_cast<bool>(test_events & EVENT_HEADER_WRAPPING),
        test_case.name);
}

// Use explicit byte arrays to avoid implicit trailing '\0' in boundary cases.
TEST(find_next_header, end_of_buffer_cases)
{
    constexpr uint8_t cr_end[] = {
        'H', 'e', 'a', 'd', 'e', 'r', ':', ' ', 'v', 'a', 'l', '\r'
    };
    constexpr uint8_t lf_end[] = {
        'H', 'e', 'a', 'd', 'e', 'r', ':', ' ', 'v', 'a', 'l', '\n'
    };
    constexpr uint8_t crlf_end[] = {
        'H', 'e', 'a', 'd', 'e', 'r', ':', ' ', 'v', 'a', 'l', '\r', '\n'
    };

    static const FindNextHeaderCase cases[] = {
        { "carriage_return_at_buffer_end", cr_end, sizeof(cr_end),
            0, sizeof(cr_end), true, true, false, 0 },
        { "line_feed_at_buffer_end", lf_end, sizeof(lf_end),
            0, sizeof(lf_end), true, true, false, 0 },
        { "carriage_return_line_feed_at_buffer_end", crlf_end, sizeof(crlf_end),
            0, sizeof(crlf_end), true, true, false, 0 }
    };

    for (const auto& test_case : cases)
        run_test_case(test_case, *msg, flow_data);
}

TEST(find_next_header, normal_terminator_cases)
{
    constexpr uint8_t cr_term[] = { 'H', ':', '1', '\r', 'x' };
    constexpr uint8_t lf_term[] = { 'H', ':', '1', '\n', 'x' };
    constexpr uint8_t crlf_term[] = { 'H', ':', '1', '\r', '\n', 'x' };
    constexpr uint8_t leading_crcrlf[] = { '\r', '\r', '\n', 'H', ':', '1' };
    constexpr uint8_t leading_crlf[] = { '\r', '\n', 'h', ':', '1' };
    constexpr uint8_t leading_lfcr[] = { '\n', '\r', 'H', ':', '1' };
    constexpr uint8_t leading_lf[] = { '\n', 'h', ':', '1' };
    constexpr uint8_t leading_cr[] = { '\r', 'h', ':', '1' };

    static const FindNextHeaderCase cases[] = {
        { "carriage_return_followed_by_non_space_ends_header", cr_term,
            sizeof(cr_term), 0, 3, false, false, false, 0 },
        { "line_feed_followed_by_non_space_ends_header", lf_term,
            sizeof(lf_term), 0, 3, false, false, false, 0 },
        { "carriage_return_line_feed_followed_by_non_space_ends_header", crlf_term,
            sizeof(crlf_term), 0, 3, false, false, false, 0 },
        { "leading_carriage_return_carriage_return_line_feed_is_counted_in_num_seps", leading_crcrlf,
            sizeof(leading_crcrlf), 3, 3, false, false, false, 0 },
        { "leading_carriage_return_line_feed_is_counted_in_num_seps", leading_crlf,
            sizeof(leading_crlf), 2, 3, false, false, false, 0 },
        { "leading_line_feed_carriage_return_is_counted_in_num_seps", leading_lfcr,
            sizeof(leading_lfcr), 2, 3, false, false, false, 0 },
        { "leading_line_feed_is_counted_in_num_seps", leading_lf,
            sizeof(leading_lf), 1, 3, false, false, false, 0 },
        { "leading_carriage_return_is_counted_in_num_seps", leading_cr,
            sizeof(leading_cr), 1, 3, false, false, false, 0 }
    };

    for (const auto& test_case : cases)
        run_test_case(test_case, *msg, flow_data);
}

TEST(find_next_header, wrapping_and_partial_flush_cases)
{
    constexpr uint8_t crlf_space[] = { 'H', ':', '1', '\r', '\n', ' ', 'x' };
    constexpr uint8_t cr_space[] = { 'H', ':', '1', '\r', ' ', 'x' };
    constexpr uint8_t cr_tab[] = { 'H', ':', '1', '\r', '\t', 'x' };
    constexpr uint8_t lf_space[] = { 'H', ':', '1', '\n', ' ', 'x' };
    constexpr uint8_t lf_tab[] = { 'H', ':', '1', '\n', '\t', 'x' };
    constexpr uint8_t partial_flush_buf[] = { 'H', ':', '1' };

    static const FindNextHeaderCase cases[] = {
        { "carriage_return_line_feed_followed_by_space_wraps_header", crlf_space,
            sizeof(crlf_space), 0, 7, true, true, false, 0 },
        { "carriage_return_followed_by_space_wraps_header", cr_space,
            sizeof(cr_space), 0, 6, true, true, false, 0 },
        { "carriage_return_followed_by_tab_wraps_header", cr_tab,
            sizeof(cr_tab), 0, 6, true, true, false, 0 },
        { "line_feed_followed_by_space_wraps_header", lf_space,
            sizeof(lf_space), 0, 6, true, true, false, 0 },
        { "line_feed_followed_by_tab_wraps_header", lf_tab,
            sizeof(lf_tab), 0, 6, true, true, false, 0 },
        // Only partial_flush with zero excess takes the defer-parsing path.
        { "partial_flush_without_complete_eol_defers_parsing", partial_flush_buf,
            sizeof(partial_flush_buf), 0, 0, false, false, true, 0 },
        { "partial_flush_with_excess_returns_buffer_length", partial_flush_buf,
            sizeof(partial_flush_buf), 0, 3, false, false, true, 1 }
    };

    for (const auto& test_case : cases)
        run_test_case(test_case, *msg, flow_data);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
