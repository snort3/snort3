//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "flow/session.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
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

void Active::block_session(snort::Packet* p, bool force)
{
    if (force and p->flow)
        p->flow->set_state(Flow::FlowState::BLOCK);
}
void DetectionEngine::disable_all(snort::Packet*) { }
Flow::~Flow() = default;
IpsContext::IpsContext(unsigned int) { }
IpsContext::~IpsContext() = default;
DataBus::DataBus() = default;
DataBus::~DataBus() = default;
SnortConfig::SnortConfig(const char*) { }
SnortConfig::~SnortConfig() = default;
unsigned get_instance_id()
{ return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }

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
FlowData::FlowData(unsigned int) { }
FlowDataStore::~FlowDataStore() = default;

// Inspector mocks, used by MockInspector class
InspectApi mock_api;
Inspector::Inspector()
{
    set_api(&mock_api);
}

Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

// MockInspector class

class MockInspector : public snort::Inspector
{
public:

    MockInspector() = default;
    ~MockInspector() override = default;
    void eval(snort::Packet*) override { }
    bool configure(snort::SnortConfig*) override { return true; }
};

class MockSession : public Session
{
public:
    explicit MockSession(snort::Flow* f, bool has_queued) : Session(f), queued(has_queued) { }

    void clear() override { }
    bool are_client_segments_queued() const override { return queued; }

private:
    bool queued;
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

// Mocks for snort::FlowDataStore::get

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
FlowData* FlowDataStore::get(unsigned) const
{ return &http2_flow_data; }

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
        counts->failed_injects = 0;
        counts->http2_translate_err = 0;
        counts->http2_mid_frame = 0;
        counts->err_unidentified_protocol = 0;
        counts->err_stream_not_established = 0;
        counts->err_injector_not_configured = 0;
        counts->err_conflicting_s2c_traffic = 0;
        counts->err_http2_even_stream = 0;
        counts->err_http2_stream_id_0 = 0;
        counts->err_session_not_tcp = 0;
        counts->err_stale_s2c_data = 0;
        counts->err_s2c_http_proto = 0;
        counts->err_c2s_http_proto = 0;
        counts->err_s2c_http2_proto = 0;
        control.http_page = (const uint8_t*)"test";
        control.http_page_len = 4;
        control.stream_id = 0;
        flow.set_state(Flow::FlowState::INSPECT);
        flow.set_session_flags(SSNFLAG_ESTABLISHED);
        flow.pkt_type = PktType::TCP;
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
    CHECK(counts->err_injector_not_configured == 1);
    CHECK(status == ERR_INJECTOR_NOT_CONFIGURED);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("Payload injector is not configured", err_string);
}

TEST(payload_injector_test, not_configured_stream_established)
{
    Packet p(false);
    set_not_configured();
    p.flow = &flow;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_injector_not_configured == 1);
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
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_stream_not_established == 1);
    CHECK(status == ERR_STREAM_NOT_ESTABLISHED);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("TCP stream not established", err_string);
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
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_http2_stream_id_0 == 1);
    CHECK(status == ERR_HTTP2_STREAM_ID_0);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/2 - injection to stream 0", err_string);
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
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_http2_even_stream == 1);
    CHECK(status == ERR_HTTP2_EVEN_STREAM_ID);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/2 - injection to server initiated stream", err_string);
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
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_unidentified_protocol == 1);
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
    CHECK(counts->http2_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->http2_mid_frame == 1);
    CHECK(status == ERR_HTTP2_MID_FRAME);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/2 - attempt to inject mid frame. Currently not supported.",
        err_string);
    delete flow.gadget;
}

TEST(payload_injector_test, http_pkt_from_srvr)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http_inspect";
    p.packet_flags = PKT_FROM_SERVER;
    flow.gadget = new MockInspector();
    p.flow = &flow;
    p.active = &active;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 1);
    CHECK(status == INJECTION_SUCCESS);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    delete flow.gadget;
}

TEST(payload_injector_test, flow_is_null)
{
    Packet p(false);
    set_configured();
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_unidentified_protocol == 1);
    CHECK(status == ERR_UNIDENTIFIED_PROTOCOL);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("Unidentified protocol", err_string);
}

TEST(payload_injector_test, session_not_tcp)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    p.active = &active;
    flow.pkt_type = PktType::UDP;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_session_not_tcp == 1);
    CHECK(status == ERR_SESSION_NOT_TCP);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("not a TCP stream", err_string);
}

TEST(payload_injector_test, stale_s2c_data)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    p.active = &active;
    p.packet_flags = PKT_FROM_SERVER | PKT_TCP_INJECT_BLOCKED;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_stale_s2c_data == 1);
    CHECK(status == ERR_STALE_S2C_DATA);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("S2C injection blocked: packet fills hole with pending out-of-order, "
        "retransmitted, or overlapping segments", err_string);
}

TEST(payload_injector_test, http_conflicting_s2c_traffic)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    p.active = &active;
    p.packet_flags = PKT_FROM_CLIENT;
    MockSession session(&flow, true);
    flow.session = &session;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_conflicting_s2c_traffic == 1);
    CHECK(status == ERR_CONFLICTING_S2C_TRAFFIC);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("Conflicting S2C HTTP traffic in progress", err_string);
    flow.session = nullptr;
}

TEST(payload_injector_test, http_s2c_proto_blocked)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    p.active = &active;
    p.packet_flags = PKT_FROM_SERVER | PKT_HTTP_INJECT_BLOCKED;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_s2c_http_proto == 1);
    CHECK(status == ERR_S2C_HTTP_PROTO);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/1 injection blocked on server response due to protocol state conflict",
        err_string);
}

TEST(payload_injector_test, http_c2s_proto_blocked)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    p.active = &active;
    p.packet_flags = PKT_HTTP_INJECT_BLOCKED;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_c2s_http_proto == 1);
    CHECK(status == ERR_C2S_HTTP_PROTO);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/1 injection blocked on client request due to protocol state conflict",
        err_string);
}

TEST(payload_injector_test, http2_conflicting_s2c_traffic)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    p.active = &active;
    p.packet_flags = PKT_FROM_CLIENT;
    control.stream_id = 1;
    MockSession session(&flow, true);
    flow.session = &session;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_conflicting_s2c_traffic == 1);
    CHECK(status == ERR_CONFLICTING_S2C_TRAFFIC);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("Conflicting S2C HTTP traffic in progress", err_string);
    delete flow.gadget;
    flow.session = nullptr;
}

TEST(payload_injector_test, http2_s2c_proto_blocked)
{
    Packet p(false);
    set_configured();
    mock_api.base.name = "http2_inspect";
    flow.gadget = new MockInspector();
    p.flow = &flow;
    p.active = &active;
    p.packet_flags = PKT_FROM_SERVER | PKT_HTTP_INJECT_BLOCKED;
    control.stream_id = 1;
    InjectionReturnStatus status = PayloadInjector::inject_http_payload(&p, control);
    CHECK(counts->http_injects == 0);
    CHECK(counts->failed_injects == 1);
    CHECK(counts->err_s2c_http2_proto == 1);
    CHECK(status == ERR_S2C_HTTP2_PROTO);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/2 injection blocked on server response due to protocol state conflict",
        err_string);
    delete flow.gadget;
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
        flow.pkt_type = PktType::TCP;
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
    STRCMP_EQUAL("Error in translating HTTP block page to HTTP/2. "
        "Unsupported or bad format.", err_string);
}

TEST(payload_injector_translate_err_test, http2_hdrs_size)
{
    Packet p(false);
    set_configured();
    p.flow = &flow;
    translation_status = ERR_TRANSLATED_HDRS_SIZE;
    status = PayloadInjector::inject_http_payload(&p, control);
    const char* err_string = PayloadInjector::get_err_string(status);
    STRCMP_EQUAL("HTTP/2 translated header size is bigger than expected. Update max size.",
        err_string);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
