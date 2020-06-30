//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "payload_injector/payload_injector_module.h"

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

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
Flow::Flow() { }
Flow::~Flow() { }
Packet::Packet(bool) { packet_flags = 0; flow = nullptr; }
Packet::~Packet() { }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

TEST_GROUP(payload_injector_test)
{
    PayloadInjectorModule mod;
    InjectionControl control;
    PegCount* counts = mod.get_counts();
    Flow flow;

    void setup() override
    {
        counts[0] = 0;
        control.http_page = (const uint8_t*)"test";
        control.http_page_len = 4;
        flow.set_state(Flow::FlowState::INSPECT);
    }
};

TEST(payload_injector_test, not_configured_stream_not_established)
{
    mod.set_configured(false);
    Packet p(false);
    p.flow = &flow;
    InjectionReturnStatus status = mod.inject_http_payload(&p, control);
    CHECK(counts[0] == 0);
    CHECK(status == ERR_INJECTOR_NOT_CONFIGURED);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

TEST(payload_injector_test, not_configured_stream_established)
{
    mod.set_configured(false);
    Packet p(false);
    p.packet_flags = PKT_STREAM_EST;
    p.flow = &flow;
    InjectionReturnStatus status = mod.inject_http_payload(&p, control);
    CHECK(counts[0] == 0);
    CHECK(status == ERR_INJECTOR_NOT_CONFIGURED);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

TEST(payload_injector_test, configured_stream_not_established)
{
    mod.set_configured(true);
    Packet p(false);
    p.flow = &flow;
    InjectionReturnStatus status = mod.inject_http_payload(&p, control);
    CHECK(counts[0] == 0);
    CHECK(status == ERR_STREAM_NOT_ESTABLISHED);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

TEST(payload_injector_test, configured_stream_established)
{
    mod.set_configured(true);
    Packet p(false);
    p.packet_flags = PKT_STREAM_EST;
    p.flow = &flow;
    InjectionReturnStatus status = mod.inject_http_payload(&p, control);
    CHECK(counts[0] == 1);
    CHECK(status == INJECTION_SUCCESS);
    CHECK(flow.flow_state == Flow::FlowState::BLOCK);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

