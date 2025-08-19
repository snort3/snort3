//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// distill_verdict.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include "distill_verdict_stubs.h"

#include "framework/data_bus.h"
#include "main/analyzer.h"
#include "main/thread_config.h"
#include "memory/memory_cap.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
int SFDAQInstance::finalize_message(DAQ_Msg_h, DAQ_Verdict verdict)
{
    mock().actualCall("finalize_message").onObject(this).withParameter("verdict", verdict);
    return -1;
}
void DeferredTrust::finalize(Active&) { }
void DeferredTrust::set_deferred_trust(unsigned, bool on)
{
    deferred_trust = on ? TRUST_DEFER_ON : TRUST_DEFER_OFF;
}
void Flow::trust() { }

SFDAQInstance* SFDAQ::get_local_instance() { return nullptr; }


unsigned int get_random_seed()
{ return 3193; }
unsigned DataBus::get_id(const PubKey&)
{ return 0; }
void ThreadConfig::update_thread_status(bool) {}
void ThreadConfig::kick_watchdog() {}
}

const FlowCacheConfig& FlowControl::get_flow_cache_config() const
{
    static FlowCacheConfig cfg;
    cfg.allowlist_cache = true;
    return cfg;
}

using namespace snort;

//--------------------------------------------------------------------------
// Distill verdict tests
//--------------------------------------------------------------------------
TEST_GROUP(distill_verdict_tests)
{
    Packet pkt;
    Flow flow{};
    Active act;
    SFDAQInstance* di;
    Analyzer* analyzer;
    ActiveAction* active_action;

    void setup() override
    {
        pkt.active = &act;
        active_action = nullptr;
        pkt.action = &active_action;
        di = new SFDAQInstance(nullptr, 0, nullptr);
        pkt.daq_instance = di;
        analyzer = new Analyzer(di, 0, nullptr);
    }

    void teardown() override
    {
        delete analyzer;
        mock().clear();
    }
};

TEST(distill_verdict_tests, normal_pass)
{
    // Normal pass verdict
    pkt.packet_flags = PKT_FROM_CLIENT;
    act.reset();
    mock().expectNCalls(1, "finalize_message").onObject(di).withParameter("verdict", DAQ_VERDICT_PASS);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
}

TEST(distill_verdict_tests, trust_session_whitelist_on_blocked)
{
    // Trust session whitelist verdict on blocked packet does nothing
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.flags.disable_inspect = false;
    flow.ssn_state.ignore_direction = SSN_DIR_NONE;
    flow.flow_state = Flow::FlowState::INSPECT;
    act.reset();
    act.drop_packet(&pkt, true);
    act.trust_session(&pkt);
    mock().expectNCalls(1, "finalize_message").onObject(di).withParameter("verdict", DAQ_VERDICT_BLOCK);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
}

TEST(distill_verdict_tests, trust_session_whitelist)
{
    // Trust session whitelist verdict
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.flags.disable_inspect = false;
    flow.ssn_state.ignore_direction = SSN_DIR_NONE;
    flow.flow_state = Flow::FlowState::INSPECT;
    act.reset();
    act.trust_session(&pkt);
    mock().expectNCalls(1, "finalize_message").onObject(di).withParameter("verdict", DAQ_VERDICT_WHITELIST);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
}

TEST(distill_verdict_tests, flow_state_whitelist)
{
    // Normal flow state whitelist verdict
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.flags.disable_inspect = false;
    flow.ssn_state.ignore_direction = SSN_DIR_NONE;
    flow.flow_state = Flow::FlowState::ALLOW;
    act.reset();
    mock().expectNCalls(1, "finalize_message").onObject(di).withParameter("verdict", DAQ_VERDICT_WHITELIST);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
    CHECK_TEXT(!flow.flags.disable_inspect, "Disable inspection should not have been called");
}

TEST(distill_verdict_tests, ignore_both_whitelist)
{
    // Normal ignore both directions whitelist verdict
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.flags.disable_inspect = false;
    flow.ssn_state.ignore_direction = SSN_DIR_BOTH;
    flow.flow_state = Flow::FlowState::INSPECT;
    act.reset();
    mock().expectNCalls(1, "finalize_message").onObject(di).withParameter("verdict", DAQ_VERDICT_WHITELIST);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
    CHECK_TEXT(!flow.flags.disable_inspect, "Disable inspection should not have been called");
}

TEST(distill_verdict_tests, deferred_trust_prevent_whitelist)
{
    // Deferred trust prevent whitelist
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.flags.disable_inspect = false;
    flow.ssn_state.ignore_direction = SSN_DIR_NONE;
    flow.flow_state = Flow::FlowState::ALLOW;
    flow.set_deferred_trust(53, true);
    act.reset();
    mock().expectNCalls(1, "finalize_message").onObject(di).withParameter("verdict", DAQ_VERDICT_PASS);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
