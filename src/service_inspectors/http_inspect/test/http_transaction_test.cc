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

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_module.h"
#include "service_inspectors/http_inspect/http_transaction.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"

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
}

HttpParaList::UriParam::UriParam() {}
HttpParaList::JsNormParam::~JsNormParam() {}
HttpParaList::~HttpParaList() {}

unsigned Http2FlowData::inspector_id = 0;
uint32_t Http2FlowData::get_processing_stream_id() const { return 0; }

THREAD_LOCAL PegCount HttpModule::peg_counts[PEG_COUNT_MAX] = { };

class HttpUnitTestSetup
{
public:
    static SectionType* get_section_type(HttpFlowData* flow_data)
        { assert(flow_data!=nullptr); return flow_data->section_type; }
    static SectionType* get_type_expected(HttpFlowData* flow_data)
        { assert(flow_data!=nullptr); return flow_data->type_expected; }
};

TEST_GROUP(http_transaction_test)
{
    Flow* const flow = new Flow;
    HttpParaList params;
    HttpFlowData* flow_data = new HttpFlowData(flow, &params);
    SectionType* const section_type = HttpUnitTestSetup::get_section_type(flow_data);
    SectionType* const type_expected = HttpUnitTestSetup::get_type_expected(flow_data);

    void teardown() override
    {
        delete flow_data;
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
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;
    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<100; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<100; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, orphan_response)
{
    // Response message without a request
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_SERVER] = SEC_STATUS;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER);
    CHECK(trans != nullptr);
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<10; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, simple_pipeline)
{
    // Pipeline with four requests followed by four responses
    HttpTransaction* trans[4];
    for (unsigned k=0; k < 4; k++)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        section_type[SRC_CLIENT] = SEC_REQUEST;
        trans[k] = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
        CHECK(trans[k] != nullptr);
        type_expected[SRC_CLIENT] = SEC_HEADER;
        section_type[SRC_CLIENT] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
        for (unsigned j=0; j < k; j++)
        {
            CHECK(trans[k] != trans[j]);
        }
    }
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    for (unsigned k=0; k < 4; k++)
    {
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_BODY_CL;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
}

TEST(http_transaction_test, concurrent_request_response)
{
    // Response starts before request completes, request completes first
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, pipeline_underflow)
{
    // Underflow scenario with request, two responses, request, response
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

    section_type[SRC_SERVER] = SEC_STATUS;
    trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER);
    CHECK(trans != nullptr);
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans2 = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK((trans2 != nullptr) && (trans2 != trans));
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_STATUS;
    trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER);
    CHECK((trans != nullptr) && (trans != trans2));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, concurrent_request_response_underflow)
{
    // Response starts before request completes, response completes first, second response
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    section_type[SRC_SERVER] = SEC_STATUS;
    HttpTransaction* trans2 = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER);
    CHECK((trans2 != nullptr) && (trans2 != trans));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans2 == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, basic_continue)
{
    // Request with interim response and final response
    // Request headers
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    // Interim response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    trans->set_one_hundred_response();
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

    // Request body
    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Second response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, multiple_continue)
{
    // Request with interim response and final response
    // Request headers
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
    CHECK(trans != nullptr);
    type_expected[SRC_CLIENT] = SEC_HEADER;
    section_type[SRC_CLIENT] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_BODY_CHUNK;

    // Interim responses
    for (unsigned k=0; k < 10; k++)
    {
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        trans->set_one_hundred_response();
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }

    // Request body
    section_type[SRC_CLIENT] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<4; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    }
    type_expected[SRC_CLIENT] = SEC_TRAILER;
    section_type[SRC_CLIENT] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
    type_expected[SRC_CLIENT] = SEC_REQUEST;

    // Final response
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    section_type[SRC_SERVER] = SEC_BODY_CHUNK;
    for (unsigned k=0; k<6; k++)
    {
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
    section_type[SRC_SERVER] = SEC_TRAILER;
    CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
}

TEST(http_transaction_test, multiple_orphan_continue)
{
    type_expected[SRC_CLIENT] = SEC_REQUEST;
    // Repeated interim and final response messages without a request
    for (unsigned k=0; k < 10; k++)
    {
        // Interim response
        section_type[SRC_SERVER] = SEC_STATUS;
        HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER);
        CHECK(trans != nullptr);
        trans->set_one_hundred_response();
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_BODY_CHUNK;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_TRAILER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

        // Final response
        section_type[SRC_SERVER] = SEC_STATUS;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_BODY_CHUNK;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_TRAILER;
        CHECK(trans == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
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
        trans[k] = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
        CHECK(trans[k] != nullptr);
        type_expected[SRC_CLIENT] = SEC_HEADER;
        section_type[SRC_CLIENT] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
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
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_BODY_CL;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }

    // Interim response to fourth request
    section_type[SRC_SERVER] = SEC_STATUS;
    CHECK(trans[3] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    trans[3]->set_one_hundred_response();
    section_type[SRC_SERVER] = SEC_HEADER;
    CHECK(trans[3] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));

    // Finish the fourth request
    section_type[SRC_CLIENT] = SEC_BODY_CL;
    CHECK(trans[3] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));

    // Requests 5-7 in pipeline
    for (unsigned k=4; k < 7; k++)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        section_type[SRC_CLIENT] = SEC_REQUEST;
        trans[k] = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT);
        CHECK(trans[k] != nullptr);
        type_expected[SRC_CLIENT] = SEC_HEADER;
        section_type[SRC_CLIENT] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT));
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
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_HEADER;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
        section_type[SRC_SERVER] = SEC_BODY_CL;
        CHECK(trans[k] == HttpTransaction::attach_my_transaction(flow_data, SRC_SERVER));
    }
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

