//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
FlowData::FlowData(unsigned, Inspector*) : next(nullptr), prev(nullptr), handler(nullptr), id(0)
{ }
FlowData::~FlowData() = default;
FlowData* Flow::get_flow_data(uint32_t) const { return nullptr; }
int Flow::set_flow_data(FlowData*) { return 0; }
Flow::~Flow() = default;
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
const Field Field::FIELD_NULL { STAT_NO_SOURCE };
const Field& HttpMsgSection::get_classic_buffer(unsigned, uint64_t, uint64_t)
{ return Field::FIELD_NULL; }
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

TEST(pub_sub_http_transaction_end_event_test, version_no_req_no_status)
{
    section_type[SRC_CLIENT] = SEC_REQUEST;
    HttpTransaction* trans = HttpTransaction::attach_my_transaction(flow_data, SRC_CLIENT, flow);
    HttpTransactionEndEvent event(trans);
    HttpEnums::VersionId version = event.get_version();
    CHECK(version == HttpEnums::VERS__NOT_PRESENT);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

