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
// distill_verdict.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include "distill_verdict_stubs.h"

#include "framework/data_bus.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/thread_config.h"
#include "managers/plugin_manager.h"
#include "memory/memory_cap.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void OopsHandler::set_current_message(DAQ_Msg_h cur_msg, snort::SFDAQInstance* daq_instance)
{
    mock().actualCall("set_current_message")
        .withConstPointerParameter("msg", cur_msg)
        .withPointerParameter("daq_instance", daq_instance);
}

namespace snort
{
int SFDAQInstance::finalize_message(DAQ_Msg_h msg, DAQ_Verdict verdict)
{
    mock().actualCall("finalize_message").onObject(this)
        .withConstPointerParameter("msg", msg).withParameter("verdict", verdict);
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
static bool thread_status_active = false;
void ThreadConfig::update_thread_status(bool active)
{ thread_status_active = active; }
void ThreadConfig::kick_watchdog() {}

// Mock the log function to copy the log message
char captured_log[64];
void LogMessage(const char* format, va_list& args)
{
    vsnprintf(captured_log, sizeof(captured_log),format, args);
}
void LogMessage(const char* format,...)
{
    va_list args;
    va_start(args, format);
    LogMessage(format, args);
    va_end(args);
}
}

PluginPtr PluginManager::get_plugin(const char*) { return nullptr; }
void PluginManager::empty_trash() { }

using namespace snort;

class AnalyzerTestAccess
{
public:
    static bool handle_command(Analyzer& analyzer)
    { return analyzer.handle_command(); }

    static void handle_uncompleted_commands(Analyzer& analyzer)
    { analyzer.handle_uncompleted_commands(); }

    static void set_state(Analyzer& analyzer, Analyzer::State state)
    { analyzer.set_state(state); }
};

class DeferredTestCommand : public AnalyzerCommand
{
public:
    bool execute(Analyzer& analyzer) override
    {
        ++executions;
        fully_paused_during_execution =
            fully_paused_during_execution or analyzer.is_fully_paused();
        return executions > 1;
    }

    const char* stringify() override
    { return "DEFERRED_TEST"; }

    unsigned executions = 0;
    bool fully_paused_during_execution = false;
};

class ResumeTestCommand : public AnalyzerCommand
{
public:
    bool execute(Analyzer& analyzer) override
    {
        saw_paused = analyzer.get_state() == Analyzer::State::PAUSED;
        saw_fully_paused = analyzer.is_fully_paused();
        analyzer.resume(0);
        return true;
    }

    const char* stringify() override
    { return "RESUME_TEST"; }

    bool saw_paused = false;
    bool saw_fully_paused = false;
};

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
        thread_status_active = false;
        pkt.active = &act;
        active_action = nullptr;
        pkt.action = &active_action;
        di = new SFDAQInstance(nullptr, 0, nullptr);
        pkt.daq_instance = di;
        analyzer = new Analyzer(di, 0, nullptr, 0, 40);
        mock().strictOrder();
    }

    void expect_finalization(DAQ_Verdict verdict)
    {
        mock().expectOneCall("set_current_message")
            .withConstPointerParameter("msg", nullptr)
            .withPointerParameter("daq_instance", nullptr);
        mock().expectOneCall("finalize_message").onObject(di)
            .withConstPointerParameter("msg", pkt.daq_msg).withParameter("verdict", verdict);
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
    expect_finalization(DAQ_VERDICT_PASS);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
}

TEST(distill_verdict_tests, fully_paused_requires_paused_state)
{
    AnalyzerTestAccess::set_state(*analyzer, Analyzer::State::PAUSED);
    CHECK(analyzer->is_fully_paused());

    AnalyzerTestAccess::set_state(*analyzer, Analyzer::State::RUNNING);
    CHECK(!analyzer->is_fully_paused());
}

TEST(distill_verdict_tests, stop_keeps_watchdog_active)
{
    AnalyzerTestAccess::set_state(*analyzer, Analyzer::State::RUNNING);
    CHECK(thread_status_active);

    analyzer->stop();
    CHECK_EQUAL(static_cast<int>(Analyzer::State::STOPPING),
        static_cast<int>(analyzer->get_state()));
    CHECK(thread_status_active);

    AnalyzerTestAccess::set_state(*analyzer, Analyzer::State::STOPPED);
    CHECK(!thread_status_active);
}

TEST(distill_verdict_tests, delayed_command_prevents_fully_paused_state)
{
    auto* command = new DeferredTestCommand;
    command->get();
    AnalyzerTestAccess::set_state(*analyzer, Analyzer::State::PAUSED);
    CHECK(analyzer->is_fully_paused());

    analyzer->execute(command);

    CHECK(!analyzer->is_fully_paused());
    CHECK(AnalyzerTestAccess::handle_command(*analyzer));
    CHECK(!analyzer->is_fully_paused());
    LONGS_EQUAL(1, command->executions);

    AnalyzerTestAccess::handle_uncompleted_commands(*analyzer);

    LONGS_EQUAL(2, command->executions);
    CHECK(!command->fully_paused_during_execution);
    CHECK(analyzer->is_fully_paused());
}

TEST(distill_verdict_tests, resume_command_prevents_fully_paused_state)
{
    auto* command = new ResumeTestCommand;
    command->get();
    AnalyzerTestAccess::set_state(*analyzer, Analyzer::State::PAUSED);
    analyzer->execute(command);

    CHECK(!analyzer->is_fully_paused());
    CHECK(AnalyzerTestAccess::handle_command(*analyzer));

    CHECK(command->saw_paused);
    CHECK(!command->saw_fully_paused);
    CHECK_EQUAL(static_cast<int>(Analyzer::State::RUNNING),
        static_cast<int>(analyzer->get_state()));
    CHECK(!analyzer->is_fully_paused());
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
    expect_finalization(DAQ_VERDICT_BLOCK);
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
    expect_finalization(DAQ_VERDICT_WHITELIST);
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
    expect_finalization(DAQ_VERDICT_WHITELIST);
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
    expect_finalization(DAQ_VERDICT_WHITELIST);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
    CHECK_TEXT(!flow.flags.disable_inspect, "Disable inspection should not have been called");
}

TEST(distill_verdict_tests, sticky_whitelist_tunnel_bypass_demoted)
{
    // A tunnel packet attaching to a flow with WHITELIST set must be demoted to PASS
    // instead of inheriting the verdict
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.last_verdict = DAQ_VERDICT_WHITELIST;
    act.reset();
    act.set_tunnel_bypass();
    PegCount before = daq_stats.internal_whitelist;
    expect_finalization(DAQ_VERDICT_PASS);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
    CHECK(daq_stats.internal_whitelist == before + 1);
    flow.last_verdict = MAX_DAQ_VERDICT;
}

TEST(distill_verdict_tests, sticky_whitelist_inherited_without_bypass)
{
    // Without tunnel however, a flow's sticky WHITELIST is expected to be inherited
    // (in contrast to sticky_whitelist_tunnel_bypass_demoted)
    pkt.flow = &flow;
    pkt.packet_flags = PKT_FROM_CLIENT;
    flow.last_verdict = DAQ_VERDICT_WHITELIST;
    act.reset();
    expect_finalization(DAQ_VERDICT_WHITELIST);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
    flow.last_verdict = MAX_DAQ_VERDICT;
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
    expect_finalization(DAQ_VERDICT_PASS);
    analyzer->post_process_packet(&pkt);
    mock().checkExpectations();
}

TEST(distill_verdict_tests, clear_current_daq_message_clears_crash_report_reference)
{
    mock().expectOneCall("set_current_message")
        .withConstPointerParameter("msg", nullptr)
        .withPointerParameter("daq_instance", nullptr);
    analyzer->clear_current_daq_message();
    mock().checkExpectations();
}

TEST(distill_verdict_tests, logmessage_verify)
{
   STRCMP_EQUAL(captured_log, "Retry queue interval is: 40 ms\n");
}
//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
