//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// http_transaction_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pub_sub/http_transaction_end_event.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_module.h"
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
// Stubs whose sole purpose is to make the test code link
unsigned FlowData::flow_data_id = 0;
FlowData::FlowData(unsigned, Inspector*) : next(nullptr), prev(nullptr), handler(nullptr), id(0)
{}
FlowData::~FlowData() = default;
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
fd_status_t File_Decomp_StopFree(fd_session_t*) { return File_Decomp_OK; }
uint32_t str_to_hash(const uint8_t *, size_t) { return 0; }
FlowData* Flow::get_flow_data(uint32_t) const { return nullptr; }
int Flow::set_flow_data(FlowData*) { return 0;}
Flow::~Flow() = default;
unsigned DataBus::get_id(PubKey const&) { return 0; }
void DataBus::publish(unsigned int, unsigned int, DataEvent&, Flow*) {}
HttpTransactionEndEvent::HttpTransactionEndEvent(const HttpTransaction* const trans):
    transaction(trans) {}
Inspector::Inspector() { }
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
const StreamBuffer StreamSplitter::reassemble(snort::Flow*, unsigned int, unsigned int, unsigned char const*, unsigned
    int, unsigned int, unsigned int&)
{
    StreamBuffer buf { nullptr, 0 };
    return buf;
}
unsigned StreamSplitter::max(snort::Flow*) { return 0; }
}

HttpParaList::UriParam::UriParam() {}
HttpParaList::JsNormParam::~JsNormParam() {}
HttpParaList::~HttpParaList() {}

unsigned Http2FlowData::inspector_id = 0;
uint32_t Http2FlowData::get_processing_stream_id() const { return 0; }
HttpInspect::HttpInspect(const HttpParaList* para) :
    params(para), xtra_trueip_id(0), xtra_uri_id(0),
    xtra_host_id(0), xtra_jsnorm_id(0)
{ }
HttpInspect::~HttpInspect() = default;
bool HttpInspect::configure(SnortConfig*) { return true; }
void HttpInspect::show(const SnortConfig*) const { }
bool HttpInspect::get_buf(unsigned, snort::Packet*, snort::InspectionBuffer&) { return true; }
HttpCommon::SectionType HttpInspect::get_type_expected(snort::Flow*, HttpCommon::SourceId) const
{ return SEC_DISCARD; }
void HttpInspect::finish_hx_body(snort::Flow*, HttpCommon::SourceId, HttpCommon::HXBodyState,
    bool) const { }
void HttpInspect::set_hx_body_state(snort::Flow*, HttpCommon::SourceId, HttpCommon::HXBodyState) const { }
bool HttpInspect::get_fp_buf(snort::InspectionBuffer::Type, snort::Packet*,
    snort::InspectionBuffer&) { return false; }
void HttpInspect::eval(snort::Packet*) { }
void HttpInspect::eval(snort::Packet*, HttpCommon::SourceId, const uint8_t*, uint16_t) { }
void HttpInspect::clear(snort::Packet*) { }
bool HttpInspect::get_buf(snort::InspectionBuffer::Type, snort::Packet*, snort::InspectionBuffer&) { return false; }
const uint8_t* HttpInspect::adjust_log_packet(snort::Packet*, uint16_t&) { return nullptr; }
StreamSplitter::Status HttpStreamSplitter::scan(snort::Packet*, const uint8_t*, uint32_t, uint32_t, uint32_t*)
{ return StreamSplitter::FLUSH; }
StreamSplitter::Status HttpStreamSplitter::scan(snort::Flow*, const uint8_t*, uint32_t, uint32_t*)
{ return StreamSplitter::FLUSH; }
const snort::StreamBuffer HttpStreamSplitter::reassemble(snort::Flow*, unsigned, unsigned, const
    uint8_t*, unsigned, uint32_t, unsigned&)
{
    StreamBuffer buf { nullptr, 0 };
    return buf;
}
bool HttpStreamSplitter::finish(snort::Flow*) { return false; }
void HttpStreamSplitter::prep_partial_flush(snort::Flow*, uint32_t) { }

THREAD_LOCAL PegCount HttpModule::peg_counts[PEG_COUNT_MAX] = { };

TEST_GROUP(http_transaction_test)
{
    Flow* const flow = new Flow;
    HttpParaList params;
    HttpFlowData* flow_data = new HttpFlowData(flow, &params);
    SectionType* const section_type = HttpUnitTestSetup::get_section_type(flow_data);
    SectionType* const type_expected = HttpUnitTestSetup::get_type_expected(flow_data);

    void setup() override
    {
        flow->gadget = new HttpInspect(&params);
    }
    void teardown() override
    {
        delete flow_data;
        delete flow->gadget;
        delete flow;
    }
};

TEST(http_transaction_test, simple_transaction)
{
    // This test is a request message with a chunked body and trailers followed by a similar
    // response message. No overlap in time.
    // Request
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;
    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<100; k++)
    {
      CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<100; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, orphan_response)
{
    // Response message without a request
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_SERVER] = SEC_STATUS;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow);
    CHECK(trans != nullptr);
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<10; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, simple_pipeline)
{
    // Pipeline with four requests followed by four responses
    HttpTransaction* trans[4];
    for (unsigned k=0; k < 4; k++)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        section_type[SRC_CLIENT] = SEC_REQUEST;
        trans[k] = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
        CHECK(trans[k] != nullptr);
        type_expected[SRC_CLIENT] = SEC_HEADER;
        section_type[SRC_CLIENT] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
        for (unsigned j=0; j < k; j++)
        {
            CHECK(trans[k] != trans[j]);
        }
    }
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    for (unsigned k=0; k < 4; k++)
    {
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_BODY_CL;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
}

TEST(http_transaction_test, concurrent_request_response)
{
    // Response starts before request completes, request completes first
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, pipeline_underflow)
{
    // Underflow scenario with request, two responses, request, response
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

    section_type[SRC_SERVER] = SEC_STATUS;
    trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow);
    CHECK(trans != nullptr);
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans2 = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK((trans2 != nullptr) && (trans2 != trans));
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_STATUS;
    trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow);
    CHECK((trans != nullptr) && (trans != trans2));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, concurrent_request_response_underflow)
{
    // Response starts before request completes, response completes first, second response
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_STATUS;
    HttpTransaction* trans2 = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow);
    CHECK((trans2 != nullptr) && (trans2 != trans));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, basic_continue)
{
    // Request with interim response and final response
    // Request headers
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    // Interim response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    trans->set_one_hundred_response();
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

    // Request body
    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Second response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, multiple_continue)
{
    // Request with interim response and final response
    // Request headers
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    // Interim responses
    for (unsigned k=0; k < 10; k++)
    {
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        trans->set_one_hundred_response();
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }

    // Request body
    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Final response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
}

TEST(http_transaction_test, multiple_orphan_continue)
{
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    // Repeated interim and final response messages without a request
    for (unsigned k=0; k < 10; k++)
    {
        // Interim response
        section_type[SRC_SERVER] = SEC_STATUS;
        HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow);
        CHECK(trans != nullptr);
        trans->set_one_hundred_response();
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_BODY_CHUNK;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_TRAILER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

        // Final response
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_BODY_CHUNK;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_TRAILER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
}

TEST(http_transaction_test, pipeline_continue_pipeline)
{
    // 3.5 requests in pipeline, 3 responses + continue response, body + 3 requests in pipeline,
    // final response + 3 responses
    HttpTransaction* trans[7];
    // Four requests in pipeline, the final one will be continued later
    for (unsigned k=0; k < 4; k++)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        section_type[SRC_CLIENT] = SEC_REQUEST;
        trans[k] = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
        CHECK(trans[k] != nullptr);
        type_expected[SRC_CLIENT] = SEC_HEADER;
        section_type[SRC_CLIENT] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
        for (unsigned j=0; j < k; j++)
        {
            CHECK(trans[k] != trans[j]);
        }
    }
    type_expected[SRC_CLIENT] = SEC_BODY_CL;

    // Three responses to the pipeline
    for (unsigned k=0; k < 3; k++)
    {
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_BODY_CL;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }

    // Interim response to fourth request
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans[3] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    trans[3]->set_one_hundred_response();
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans[3] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));

    // Finish the fourth request
    section_type[SRC_CLIENT] = SEC_BODY_CL;
    CHECK(trans[3] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));

    // Requests 5-7 in pipeline
    for (unsigned k=4; k < 7; k++)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        section_type[SRC_CLIENT] = SEC_REQUEST;
        trans[k] = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
        CHECK(trans[k] != nullptr);
        type_expected[SRC_CLIENT] = SEC_HEADER;
        section_type[SRC_CLIENT] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow));
        for (unsigned j=5; j < k; j++)
        {
            CHECK(trans[k] != trans[j]);
        }
    }
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Final response to 4 and responses to 5-7
    for (unsigned k=3; k < 7; k++)
    {
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
        section_type[SRC_SERVER] = SEC_BODY_CL;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER, flow));
    }
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

