//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_request_body_event_test.cc author Katura Harvey <katharve@cisco.com>

// Unit test for the HttpRequestBodyEvent methods for HTTP/2 request bodies

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "pub_sub/http_request_body_event.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_body_cl.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

// Stubs to make the code link
HttpMsgBody::HttpMsgBody(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_):
    HttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_),
    body_octets(0),
    first_body(0)
{
    msg_text_new.set(buf_size, buffer, buf_owner);
    publish_length = buf_size;
}
void HttpMsgBody::analyze() {}
void HttpMsgBody::publish() {}
void HttpMsgBody::do_file_processing(const Field&) {}
void HttpMsgBody::do_utf_decoding(const Field&, Field&) {}
void HttpMsgBody::do_file_decompression(const Field&, Field&) {}
void HttpMsgBody::do_enhanced_js_normalization(const Field&, Field&) {}
void HttpMsgBody::clean_partial(uint32_t&, uint32_t&, uint8_t*&, uint32_t&) {}
void HttpMsgBody::bookkeeping_regular_flush(uint32_t&, uint8_t*&, uint32_t&, int32_t) {}
#ifdef REG_TEST
void HttpMsgBody::print_body_section(FILE*, const char*) {}
#endif

HttpMsgSection::HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, HttpCommon::SourceId source_id_, bool buf_owner,
    snort::Flow* flow_, const HttpParaList* params_):
    msg_text(buf_size, buffer, buf_owner),
    session_data(session_data_),
    flow(flow_),
    params(params_),
    transaction(HttpTransaction::attach_my_transaction(session_data, source_id_)),
    trans_num(STAT_NOT_PRESENT),
    status_code_num(STAT_NOT_PRESENT),
    source_id(source_id_),
    version_id(VERS__NOT_PRESENT),
    method_id(METH__NOT_PRESENT),
    tcp_close(false)
{}
void HttpMsgSection::update_depth() const{}

HttpTransaction*HttpTransaction::attach_my_transaction(HttpFlowData*, HttpCommon::SourceId)
    { return nullptr; }
Field::Field(int32_t length, const uint8_t* start, bool own_the_buffer_) :
    strt(start), len(length), own_the_buffer(own_the_buffer_)
{}
void Field::set(int32_t length, const uint8_t* start, bool own_the_buffer_)
{
    assert(len == STAT_NOT_COMPUTE);
    assert(strt == nullptr);
    assert(start != nullptr);
    assert(length >= 0);
    assert(length <= MAX_OCTETS);
    strt = start;
    len = length;
    own_the_buffer = own_the_buffer_;
}

void HttpFlowData::half_reset(HttpCommon::SourceId) {}

int32_t HttpMsgBody::get_publish_length() const
{
    return mock().getData("pub_length").getIntValue();
}

uint32_t HttpFlowData::get_h2_stream_id() const
{
    return  mock().getData("stream_id").getUnsignedIntValue();
}


TEST_GROUP(pub_sub_http_request_body_event_test)
{
    void teardown() override
    {
        mock().clear();
    }
};

TEST(pub_sub_http_request_body_event_test, first_event)
{
    int32_t msg_len = 500;
    int32_t length, offset;
    uint32_t stream_id = 1;
    std::string msg(msg_len, 'A');
    mock().setData("pub_length", msg_len);
    mock().setData("stream_id", stream_id);
    HttpMsgBody* body = new HttpMsgBodyCl((const uint8_t*)msg.c_str(), msg_len, nullptr,
        HttpCommon::SRC_CLIENT, false, nullptr, nullptr);
    HttpRequestBodyEvent event(body, 0, false, nullptr);
    const uint8_t* data = event.get_request_body_data(length, offset);
    CHECK(memcmp(data, msg.data(), length) == 0);
    CHECK(length == msg_len);
    CHECK(offset == 0);
    CHECK(event.get_http2_stream_id() == stream_id);
    CHECK_FALSE(event.is_last_request_body_piece());
    delete body;
}

TEST(pub_sub_http_request_body_event_test, last_event)
{
    int32_t msg_len = 500;
    int32_t in_offset = REQUEST_PUBLISH_DEPTH - msg_len;
    int32_t length, offset;
    uint32_t stream_id = 3;
    mock().setData("stream_id", stream_id);
    std::string msg(msg_len, 'A');
    mock().setData("pub_length", msg_len);
    HttpMsgBody* body = new HttpMsgBodyCl((const uint8_t*)msg.c_str(), msg_len, nullptr,
        HttpCommon::SRC_CLIENT, false, nullptr, nullptr);
    HttpRequestBodyEvent event(body, in_offset, true, nullptr);
    const uint8_t* data = event.get_request_body_data(length, offset);
    CHECK(memcmp(data, msg.data(), length) == 0);
    CHECK(length == msg_len);
    CHECK(offset == 1500);
    CHECK(event.get_http2_stream_id() == stream_id);
    CHECK(event.is_last_request_body_piece());
    delete body;
}

TEST(pub_sub_http_request_body_event_test, empty_data_last_event)
{
    int32_t in_offset = 1500;
    int32_t length, offset;
    uint32_t stream_id = 5;
    mock().setData("stream_id", stream_id);
    HttpRequestBodyEvent event(nullptr, in_offset, true, nullptr);
    const uint8_t* data = event.get_request_body_data(length, offset);
    CHECK(data == nullptr);
    CHECK(length == 0);
    CHECK(offset == 1500);
    CHECK(event.get_http2_stream_id() == stream_id);
    CHECK(event.is_last_request_body_piece());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

