//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_test.cc author Maya Dagon <mdagon@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector/payload_injector.h"
#include "payload_injector/payload_injector_module.h"

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"

#include "payload_injector/payload_injector_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace HttpCommon;

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------
namespace snort
{
uint32_t Active::send_data(snort::Packet*, EncodeFlags, unsigned char const*, unsigned int)
{
    return 1;
}

void Active::block_session(snort::Packet*, bool) { }
void DetectionEngine::disable_all(snort::Packet*) { }
Flow::Flow()
{
    gadget = nullptr;
    flow_state = Flow::FlowState::SETUP;
}

Flow::~Flow() = default;
IpsContext::IpsContext(unsigned int) { }
IpsContext::~IpsContext() = default;
DataBus::DataBus() = default;
DataBus::~DataBus() = default;
SnortConfig::SnortConfig(snort::SnortConfig const*, const char*) { }
SnortConfig::~SnortConfig() = default;

IpsContext ips_context;
SnortConfig conf;
PayloadInjectorConfig pi_conf;
Packet::Packet(bool)
{
    packet_flags = 0;
    flow = nullptr;
    context = &ips_context;
    context->conf = &conf;
}

static void set_not_configured() { conf.payload_injector_config = nullptr; }
static void set_configured() { conf.payload_injector_config = &pi_conf; }

Packet::~Packet() = default;
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
FlowData::~FlowData() = default;
FlowData::FlowData(unsigned int, snort::Inspector*) { }

// Inspector mocks, used by MockInspector class
InspectApi mock_api;
Inspector::Inspector()
{
    set_api(&mock_api);
}

Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

// MockInspector class

class MockInspector : public snort::Inspector
{
public:

    MockInspector() = default;
    ~MockInspector() override = default;
    void eval(snort::Packet*) override { }
    bool configure(snort::SnortConfig*) override { return true; }
};

// Mocks for PayloadInjectorModule::get_http2_payload

static InjectionReturnStatus translation_status = INJECTION_SUCCESS;
InjectionReturnStatus PayloadInjector::get_http2_payload(InjectionControl,
    uint8_t*& http2_payload, uint32_t& payload_len, bool)
{
    if (translation_status == INJECTION_SUCCESS)
    {
        http2_payload = (uint8_t*)snort_alloc(1);
        payload_len = 1;
    }

    return translation_status;
}

// Mocks for snort::Flow::get_flow_data

unsigned Http2FlowData::inspector_id = 0;
Http2Stream::~Http2Stream() = default;
HpackDynamicTable::~HpackDynamicTable() = default;
Http2DataCutter::Http2DataCutter(Http2FlowData* _session_data, HttpCommon::SourceId src_id) :
    session_data(_session_data), source_id(src_id) { }
Http2FlowData::Http2FlowData(snort::Flow*) :
    FlowData(inspector_id),
    flow(nullptr),
    hi(nullptr),
    hpack_decoder
    {
        Http2HpackDecoder(this, SRC_CLIENT, events[SRC_CLIENT], infractions[SRC_CLIENT]),
        Http2HpackDecoder(this, SRC_SERVER, events[SRC_SERVER], infractions[SRC_SERVER])
    },
    data_cutter {Http2DataCutter(this, SRC_CLIENT), Http2DataCutter(this, SRC_SERVER)}
{ }
Http2FlowData::~Http2FlowData() = default;
Http2FlowData http2_flow_data(nullptr);
void Http2FlowData::set_mid_frame(bool val) { continuation_expected[SRC_SERVER] = val; }
bool Http2FlowData::is_mid_frame() const { return continuation_expected[SRC_SERVER]; }
FlowData* snort::Flow::get_flow_data(unsigned int) const { return &http2_flow_data; }

TEST_GROUP(payload_injector_test)
{
    PayloadInjectorModule mod;
    InjectionControl control;
    PayloadInjectorCounts* counts = (PayloadInjectorCounts*)mod.get_counts();
    Flow flow;
    Active active;

    void setup() override
    {
        counts->http_injects = 0;
        counts->http2_injects = 0;
        counts->http2_translate_err = 0;
        counts->http2_mid_frame = 0;
        control.http_page = (const uint8_t*)"test";
        control.http_page_len = 4;
        flow.set_state(Flow::FlowState::INSPECT);
        flow.set_session_flags(SSNFLAG_ESTABLISHED);
        translation_status = INJECTION_SUCCESS;
        http2_flow_data.set_mid_frame(false);
    }
};

TEST(payload_injector_test, not_configured_stream_not_established)
{
    Packet p(false);
    set_not_configured();
    p.flow = &flow;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(status == ERR_INJECTOR_NOT_CONFIGURED);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "Payload injector is not configured") == 0);
}

TEST(payload_injector_test, not_configured_stream_established)
{
    Packet p(false);
    set_not_configured();
    p.flow = &flow;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(status == ERR_INJECTOR_NOT_CONFIGURED);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

TEST(payload_injector_test, configured_stream_not_established)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    flow.update_session_flags(0);
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(status == ERR_STREAM_NOT_ESTABLISHED);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "TCP stream not established") == 0);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

TEST(payload_injector_test, configured_stream_established)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    p.active = &active;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 1);
    CHECK(status == INJECTION_SUCCESS);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    delete flow.gadget;
}

TEST(payload_injector_test, http2_stream0)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http2_injects == 0);
    CHECK(status == ERR_HTTP2_STREAM_ID_0);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "HTTP/2 - injection to stream 0") == 0);
    delete flow.gadget;
}

TEST(payload_injector_test, http2_even_stream_id)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    control.stream_id = 2;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http2_injects == 0);
    CHECK(status == ERR_HTTP2_EVEN_STREAM_ID);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "HTTP/2 - injection to server initiated stream") == 0);
    delete flow.gadget;
}

TEST(payload_injector_test, http2_success)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    p.active = &active;
    control.stream_id = 1;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http2_injects == 1);
    CHECK(status == INJECTION_SUCCESS);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    delete flow.gadget;
}

TEST(payload_injector_test, unidentified_gadget_is_null)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    p.active = &active;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 1);
    CHECK(status == INJECTION_SUCCESS);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

TEST(payload_injector_test, unidentified_gadget_name)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "inspector";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(status == ERR_UNIDENTIFIED_PROTOCOL);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    delete flow.gadget;
}

TEST(payload_injector_test, http2_mid_frame)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    control.stream_id = 1;
    http2_flow_data.set_mid_frame(true);
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http2_mid_frame == 1);
    CHECK(status == ERR_HTTP2_MID_FRAME);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "HTTP/2 - attempt to inject mid frame. Currently not supported.")
        == 0);
    delete flow.gadget;
}

TEST(payload_injector_test, http2_continuation_expected)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    control.stream_id = 1;
    http2_flow_data.set_mid_frame(true);
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http2_mid_frame == 1);
    CHECK(status == ERR_HTTP2_MID_FRAME);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    delete flow.gadget;
}

TEST(payload_injector_test, http2_pkt_from_srvr)
{
    Packet p(false);
    set_configured();
    p.packet_flags = PKT_FROM_SERVER;
    flow.gadget = new MockInspector();
    p.flow = &flow;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(status == ERR_PKT_FROM_SERVER);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    delete flow.gadget;
}

TEST(payload_injector_test, flow_is_null)
{
    Packet p(false);
    set_configured();
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(status == ERR_UNIDENTIFIED_PROTOCOL);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "Unidentified protocol") == 0);
}

TEST_GROUP(payload_injector_translate_err_test)
{
    PayloadInjectorModule mod;
    InjectionControl control;
    PayloadInjectorCounts* counts = (PayloadInjectorCounts*)mod.get_counts();
    Flow flow;
    InjectionReturnStatus status = INJECTION_SUCCESS;

    void setup() override
    {
        counts->http_injects = 0;
        counts->http2_injects = 0;
        counts->http2_translate_err = 0;
        counts->http2_mid_frame = 0;
        control.http_page = (const uint8_t*)"test";
        control.http_page_len = 4;
        flow.set_state(Flow::FlowState::INSPECT);
        flow.set_session_flags(SSNFLAG_ESTABLISHED);
        http2_flow_data.set_mid_frame(false);
        mock_api.base.name = "http2_inspect";
        flow.gadget = new MockInspector();
        control.stream_id = 1;
    }

    void teardown() override
    {
        CHECK(counts->http2_translate_err == 1);
        CHECK(status == translation_status);
        CHECK(flow.flow_state == Flow::FlowState::BLOCK);
        delete flow.gadget;
    }
};

TEST(payload_injector_translate_err_test, http2_page_translation_err)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    translation_status = ERR_PAGE_TRANSLATION;
    status = PayloadInjector::inject_http_payload(&p, control);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string, "Error in translating HTTP block page to HTTP/2. "
        "Unsupported or bad format.") == 0);
}

TEST(payload_injector_translate_err_test, http2_hdrs_size)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    translation_status = ERR_TRANSLATED_HDRS_SIZE;
    status = PayloadInjector::inject_http_payload(&p, control);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string,
        "HTTP/2 translated header size is bigger than expected. Update max size.") == 0);
}

TEST(payload_injector_translate_err_test, conflicting_s2c_traffic)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    translation_status = ERR_CONFLICTING_S2C_TRAFFIC;
    status = PayloadInjector::inject_http_payload(&p, control);
    const char* err_string = PayloadInjector::get_err_string(status);
    CHECK(strcmp(err_string,
        "Conflicting S2C HTTP traffic in progress") == 0);
}
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

