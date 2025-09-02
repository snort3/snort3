//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_transaction_end_event_test.cc author Maya Dagon <mdagon@cisco.com>
// Unit test for the HttpTransactionEndEvent

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pub_sub/http_transaction_end_event.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_module.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_transaction.h"
#include "service_inspectors/http_inspect/test/http_unit_test_helpers.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

namespace snort
{
unsigned FlowData::flow_data_id = 0;
FlowData::FlowData(unsigned, Inspector*) : handler(nullptr), id(0)
{ }
FlowData::~FlowData() = default;
FlowData* FlowDataStore::get(uint32_t) const { return nullptr; }
void FlowDataStore::set(FlowData*) { }
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;
unsigned DataBus::get_id(PubKey const&) { return 0; }
void DataBus::publish(unsigned int, unsigned int, DataEvent&, Flow*) { }
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
fd_status_t File_Decomp_StopFree(fd_session_t*) { return File_Decomp_OK; }
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

HttpParaList::UriParam::UriParam() { }
HttpParaList::JsNormParam::~JsNormParam() { }
HttpParaList::~HttpParaList() { }
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
void HttpStreamSplitter::prep_partial_flush(snort::Flow*, uint32_t, uint32_t, uint32_t) { }

HttpMsgHeader::HttpMsgHeader(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgHeadShared(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{}
void HttpMsgHeader::publish(unsigned){}
void HttpMsgHeader::gen_events() {}
void HttpMsgHeader::update_flow() {}
void HttpMsgHeader::prepare_body() {}
#ifdef REG_TEST
void HttpMsgHeader::print_section(FILE*) {}
#endif
HttpMsgHeadShared::HttpMsgHeadShared(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, HttpCommon::SourceId source_id_, bool buf_owner,
    snort::Flow* flow_, const HttpParaList* params_): HttpMsgSection(buffer, buf_size,
    session_data_, source_id_, buf_owner, flow_, params_), own_msg_buffer(buf_owner)
{}
HttpMsgHeadShared::~HttpMsgHeadShared() {}
HttpMsgSection::HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size,
       HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
       const HttpParaList* params_) :
    msg_text(buf_size, buffer, buf_owner),
    session_data(session_data_),
    flow(flow_),
    params(params_),
    transaction(nullptr),
    trans_num(0),
    status_code_num(STAT_NOT_PRESENT),
    source_id(source_id_),
    version_id(VERS__NOT_PRESENT),
    method_id(METH__NOT_PRESENT),
    tcp_close(false)
{}
void HttpMsgSection::clear(){}
bool HttpMsgSection::run_detection(snort::Packet*) { return false; }
void HttpMsgHeadShared::analyze() {}

THREAD_LOCAL PegCount HttpModule::peg_counts[PEG_COUNT_MAX] = { };

//
// get_classic_buffer mock
//
Field odd (3, (const uint8_t *)"odd", false);
Field even (4, (const uint8_t *)"even", false);
static uint32_t test_number = 0;
const Field& HttpMsgSection::get_classic_buffer(unsigned, uint64_t, uint64_t)
{
    return ((test_number % 2) == 0) ? even : odd;
}

TEST_GROUP(pub_sub_http_transaction_end_event_test)
{
    Flow* const flow = new Flow;
    HttpParaList params;
    HttpFlowData* flow_data = new HttpFlowData(flow, &params);
    SectionType* const section_type = HttpUnitTestSetup::get_section_type(flow_data);
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

TEST(pub_sub_http_transaction_end_event_test, no_req_no_status)
{
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    HttpTransactionEndEvent event(trans);
    HttpEnums::VersionId version = event.get_version();
    CHECK(version == HttpEnums::VERS__NOT_PRESENT);
    uint64_t trans_depth = event.get_trans_depth();
    CHECK(trans_depth == 0);
}

TEST(pub_sub_http_transaction_end_event_test, proxied_str_exists)
{
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    char buf[] = "something";
    HttpMsgHeader* hdr = new HttpMsgHeader((uint8_t*)buf, sizeof(buf), flow_data, SRC_CLIENT, false, flow, &params);
    trans->set_header(hdr, SRC_CLIENT);
    HttpTransactionEndEvent event(trans);
    const std::string result = "FORWARDED->odd X-FORWARDED-FOR->odd X-FORWARDED-FROM->odd "
        "CLIENT-IP->odd VIA->odd XROXY-CONNECTION->odd PROXY-CONNECTION->odd";
    test_number = 1;
    std::string proxied = event.get_proxied();
    CHECK(proxied == result);
    test_number = 2;
    proxied = event.get_proxied();
    CHECK(proxied == result);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
