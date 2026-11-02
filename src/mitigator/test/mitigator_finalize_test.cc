//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// mitigator_finalize_test.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <csignal>
#include <cstring>
#include <vector>

#include "detection/context_switcher.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/fp_detect.h"
#include "detection/ips_context.h"
#include "detection/regex_offload.h"
#include "detection/signature.h"
#include "detection/treenodes.h"
#include "events/event.h"
#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "filters/sfthreshold.h"
#include "framework/data_bus.h"
#include "framework/ips_action.h"
#include "framework/mpse_batch.h"
#include "latency/packet_latency.h"
#include "main/analyzer.h"
#include "main/process.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "managers/mpse_manager.h"
#include "mitigator/mitigator.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "packet_io/sfdaq_instance.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "time/packet_time.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

//--------------------------------------------------------------------------
// test state
//--------------------------------------------------------------------------

static IpsContext* s_context = nullptr;
static ContextSwitcher s_switcher;
alignas(Analyzer) static unsigned char s_analyzer_storage[sizeof(Analyzer)];
static Analyzer* const s_analyzer = reinterpret_cast<Analyzer*>(s_analyzer_storage);
static const SnortConfig* s_conf = nullptr;
static bool s_fault_while_logging = false;
static SThreadType s_thread_type = STHREAD_TYPE_OTHER;

static OptTreeNode s_rule_otn;
static OptTreeNode s_next_rule_otn;
static OptTreeNode s_dropped_otn;
static OptTreeNode s_blocked_otn;

// distinct from 0, -1 and the unknown-name fallback so the test proves "alert" reaches fpLogEvent
static constexpr IpsAction::Type s_block_action = 5;
static constexpr IpsAction::Type s_drop_action = 6;
static constexpr IpsAction::Type s_unknown_action = 100;

static int count_event(void*, void* user)
{
    ++*static_cast<int*>(user);
    return 0;
}

[[noreturn]] static bool throw_mitigation_action(MitigationAction action)
{ throw MitigationActionException(action, "test_module"); }

static int queued_events(const IpsContext* c)
{
    int count = 0;
    sfeventq_action(c->equeue, count_event, &count);
    return count;
}

static int collect_otn(void* event, void* user)
{
    static_cast<std::vector<const OptTreeNode*>*>(user)->push_back(
        static_cast<EventNode*>(event)->otn);
    return 0;
}

static std::vector<const OptTreeNode*> queued_otns(const IpsContext* c)
{
    std::vector<const OptTreeNode*> otns;
    sfeventq_action(c->equeue, collect_otn, &otns);
    return otns;
}

//--------------------------------------------------------------------------
// mocks for the calls whose ordering is under test
//--------------------------------------------------------------------------

int fpLogEvent(const OptTreeNode* otn, Packet* p, int rate_action)
{
    mock().actualCall("log_event")
        .withUnsignedIntParameter("gid", otn->sigInfo.gid)
        .withUnsignedIntParameter("sid", otn->sigInfo.sid)
        .withIntParameter("rate_action", rate_action)
        .withPointerParameter("packet", p)
        .withBoolParameter("pkth_valid", p->pkth != nullptr);

    // A nested fault takes the re-raise path only if mitigation is marked active.
    if ( s_fault_while_logging )
        mitigation_handle_signal(SIGFPE);

    return 0;
}

void Analyzer::clear_current_daq_message()
{
    mock().actualCall("clear_current_daq_message").onObject(this);
}

namespace snort
{
int SFDAQInstance::finalize_message(DAQ_Msg_h msg, DAQ_Verdict verdict)
{
    mock().actualCall("finalize_message").onObject(this)
        .withConstPointerParameter("msg", msg)
        .withParameter("verdict", verdict)
        .withIntParameter("queued_events", queued_events(s_context))
        .withBoolParameter("pkth_valid", s_context->packet->pkth != nullptr);
    return 0;
}
}

void remove_oops_handler()
{ mock().actualCall("remove_oops_handler"); }

// cppcheck-suppress-begin functionStatic ; test doubles must retain the production member signatures
void ContextSwitcher::stop()
{ mock().actualCall("switcher_stop"); }

//--------------------------------------------------------------------------
// stubs
//--------------------------------------------------------------------------

THREAD_LOCAL ProfileStats eventqPerfStats;
THREAD_LOCAL ProfileStats mpsePerfStats;
THREAD_LOCAL const Trace* detection_trace = nullptr;

Analyzer* Analyzer::get_local_analyzer() { return s_analyzer; }
ContextSwitcher* Analyzer::get_switcher() { return &s_switcher; }
void Analyzer::post_process_packet(Packet*) { }

ContextSwitcher::~ContextSwitcher() = default;
IpsContext* ContextSwitcher::get_context() const { return s_context; }
IpsContext* ContextSwitcher::get_next() const { return nullptr; }
IpsContext* ContextSwitcher::interrupt() { return nullptr; }
IpsContext* ContextSwitcher::complete() { return nullptr; }
void ContextSwitcher::suspend() { }
void ContextSwitcher::resume(IpsContext*) { }
unsigned ContextSwitcher::idle_count() const { return 0; }

OptTreeNode::~OptTreeNode() = default;
OptTreeNode* OtnLookup(GHash*, uint32_t gid, uint32_t sid)
{
    if ( gid == GID_MITIGATOR and sid == MITIGATOR_EVENT_SIGNAL_DROPPED )
        return &s_dropped_otn;
    if ( gid == GID_MITIGATOR and sid == MITIGATOR_EVENT_SIGNAL_BLOCKED )
        return &s_blocked_otn;
    return nullptr;
}

void check_tags(Packet*) { }
void fp_full(Packet*) { }
void fp_partial(Packet*) { }
void fp_complete(Packet*, bool) { }
void populate_trace_data() { }
void sfthreshold_reset() { }

bool MpseManager::is_poll_capable(const MpseApi*) { return false; }
bool MpseManager::is_async_capable(const MpseApi*) { return false; }
RegexOffload* RegexOffload::get_offloader(unsigned, bool) { return nullptr; }
bool RegexOffload::on_hold(const Flow*) const { return false; }
void PacketLatency::push() { }
void PacketLatency::pop(const Packet*) { }
bool PacketLatency::fastpath() { return false; }
Event::Event(unsigned, unsigned, const SigInfo& si, const char**, const char*) : sig_info(si) { }

namespace snort
{
THREAD_LOCAL PacketCount pc;
THREAD_LOCAL bool TimeProfilerStats::enabled = false;
#ifndef _WIN64
THREAD_LOCAL TimeContext* ProfileContext::curr_time = nullptr;
#endif
MemoryContext::MemoryContext(MemoryTracker&) : saved(nullptr) { }
MemoryContext::~MemoryContext() = default;
THREAD_LOCAL MitigatorStats mitigator_stats;

IpsContext::IpsContext(unsigned) { }
IpsContext::~IpsContext() = default;
void IpsContext::snapshot_flow(Flow*) { }
void IpsContext::post_detection() { }
void IpsContext::set_context_data(unsigned, IpsContextData*) { }
IpsContextData* IpsContext::get_context_data(unsigned) const { return nullptr; }

SnortConfig::SnortConfig(const char*) { }
SnortConfig::~SnortConfig() = default;
const SnortConfig* SnortConfig::get_conf() { return s_conf; }

Packet::Packet(bool) { }
Packet::~Packet() = default;
void Packet::release_helpers() { }
bool Packet::is_detection_enabled(bool) { return true; }
void Packet::reset() { }

void Active::drop_packet(const Packet*, bool) { }
void Active::block_session(Packet*, bool) { }
void Active::set_drop_reason(const char*) { }
void Active::apply_delayed_action(Packet*) { }
void Active::reset() { }
bool Active::keep_pruned_flow() const { return false; }
bool Active::keep_timedout_flow() const { return false; }

SFDAQInstance::SFDAQInstance(const char*, unsigned, const SFDAQConfig*) { }
SFDAQInstance::~SFDAQInstance() = default;

unsigned DataBus::get_id(const PubKey&) { return 0; }
void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }
void PacketTracer::restart_timer() { }
bool PacketTracer::is_daq_activated() { return false; }
void TraceApi::filter(const Packet&) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }
IpsPolicy* get_ips_policy() { return nullptr; }
NetworkPolicy* get_network_policy() { return nullptr; }
SThreadType get_thread_type() { return s_thread_type; }
void packet_gettimeofday(struct timeval* tv) { *tv = {}; }
void InspectorManager::probe_first(Packet*) { }
void InspectorManager::probe(Packet*) { }
void InspectorManager::clear(Packet*) { }
void InspectorManager::execute(Packet*) { }
void Stream::check_flow_closed(Packet*) { }
bool MpseBatch::search_sync() { return false; }

IpsAction::Type IpsAction::get_type(const char* name)
{
    if ( !strcmp(name, "block") )
        return s_block_action;
    if ( !strcmp(name, "drop") )
        return s_drop_action;
    return s_unknown_action;
}

bool IpsAction::is_valid_action(IpsAction::Type action)
{ return action != s_unknown_action; }

void ErrorMessage(const char*, ...) { }
void WarningMessage(const char*, ...) { }
void LogMessage(const char*, ...) { }
void MitigationException::print_mitigation_info(int32_t, bool) { }
}
// cppcheck-suppress-end functionStatic

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

TEST_GROUP(mitigator_finalize_tests)
{
    SnortConfig conf;
    IpsContext context;
    Active active;
    SFDAQInstance* daq_instance = nullptr;
    Packet pkt;
    Packet next_pkt;
    DAQ_PktHdr_t pkth {};
    int daq_msg = 0;
    PacketMitigator packet_mitigator;

    void setup() override
    {
        set_otn(s_rule_otn, 1, 1000);
        set_otn(s_next_rule_otn, 1, 1001);
        set_otn(s_dropped_otn, GID_MITIGATOR, MITIGATOR_EVENT_SIGNAL_DROPPED);
        set_otn(s_blocked_otn, GID_MITIGATOR, MITIGATOR_EVENT_SIGNAL_BLOCKED);

        conf.run_flags = RUN_FLAG__INLINE;
        s_conf = &conf;
        context.conf = &conf;

        context.equeue = sfeventq_new(8, 8, sizeof(EventNode));
        s_context = &context;

        daq_instance = new SFDAQInstance(nullptr, 0, nullptr);
        init_packet(pkt);
        init_packet(next_pkt);
        context.packet = &pkt;

        s_fault_while_logging = false;
        s_thread_type = STHREAD_TYPE_PACKET;
        mock().strictOrder();
    }

    void teardown() override
    {
        mock().clear();
        delete daq_instance;
        sfeventq_free(context.equeue);
        context.equeue = nullptr;
        s_context = nullptr;
        s_conf = nullptr;
    }

    static void set_otn(OptTreeNode& otn, uint32_t gid, uint32_t sid)
    {
        otn.sigInfo.gid = gid;
        otn.sigInfo.sid = sid;
    }

    void init_packet(Packet& p)
    {
        p.context = &context;
        p.pkth = &pkth;
        p.active = &active;
        p.daq_instance = daq_instance;
        p.daq_msg = reinterpret_cast<DAQ_Msg_h>(&daq_msg);
    }

    void queue_rule_event(const OptTreeNode& otn)
    {
        EventNode* en = static_cast<EventNode*>(sfeventq_event_alloc(context.equeue));
        CHECK(en);
        en->otn = &otn;
        en->rtn = nullptr;
        LONGS_EQUAL(0, sfeventq_add(context.equeue, en));
    }

    static void expect_log(const OptTreeNode& otn, IpsAction::Type action, Packet& p)
    {
        mock().expectOneCall("log_event")
            .withUnsignedIntParameter("gid", otn.sigInfo.gid)
            .withUnsignedIntParameter("sid", otn.sigInfo.sid)
            .withIntParameter("rate_action", action)
            .withPointerParameter("packet", &p)
            .withBoolParameter("pkth_valid", true);
    }

    void expect_finalization(DAQ_Verdict verdict)
    {
        mock().expectOneCall("clear_current_daq_message").onObject(s_analyzer);
        mock().expectOneCall("finalize_message").onObject(daq_instance)
            .withConstPointerParameter("msg", pkt.daq_msg)
            .withParameter("verdict", verdict)
            .withIntParameter("queued_events", 0)
            .withBoolParameter("pkth_valid", false);
        mock().expectOneCall("switcher_stop");
    }

    bool run_mitigated(MitigationAction action)
    {
        return packet_mitigator(&pkt, throw_mitigation_action, action);
    }
};

TEST(mitigator_finalize_tests, drop_logs_only_mitigator_event_before_releasing_packet)
{
    queue_rule_event(s_rule_otn);

    expect_log(s_dropped_otn, s_drop_action, pkt);
    expect_finalization(DAQ_VERDICT_BLOCK);

    CHECK_FALSE(run_mitigated(MitigationAction::Drop));
    mock().checkExpectations();
    CHECK(pkt.pkth == nullptr);
    LONGS_EQUAL(0, queued_events(&context));
}

TEST(mitigator_finalize_tests, block_logs_only_mitigator_event_before_releasing_packet)
{
    queue_rule_event(s_rule_otn);

    expect_log(s_blocked_otn, s_block_action, pkt);
    expect_finalization(DAQ_VERDICT_BLACKLIST);

    CHECK_FALSE(run_mitigated(MitigationAction::Block));
    mock().checkExpectations();
    CHECK(pkt.pkth == nullptr);
    LONGS_EQUAL(0, queued_events(&context));
}

TEST(mitigator_finalize_tests, ids_mode_logs_mitigator_event_and_passes)
{
    conf.run_flags = 0;
    queue_rule_event(s_rule_otn);

    expect_log(s_dropped_otn, s_drop_action, pkt);
    expect_finalization(DAQ_VERDICT_PASS);

    CHECK_FALSE(run_mitigated(MitigationAction::Drop));
    mock().checkExpectations();
}

TEST(mitigator_finalize_tests, reused_context_does_not_replay_events)
{
    queue_rule_event(s_rule_otn);

    expect_log(s_dropped_otn, s_drop_action, pkt);
    expect_finalization(DAQ_VERDICT_BLOCK);
    CHECK_FALSE(run_mitigated(MitigationAction::Drop));
    mock().checkExpectations();

    // The next packet on the same context sees only its own events.
    context.packet = &next_pkt;
    queue_rule_event(s_next_rule_otn);

    const std::vector<const OptTreeNode*> expected { &s_next_rule_otn };
    CHECK(queued_otns(&context) == expected);
}

TEST(mitigator_finalize_tests, fault_while_logging_takes_nested_fault_path)
{
    auto prev_handler = std::signal(SIGFPE, SIG_IGN);
    s_fault_while_logging = true;

    expect_log(s_dropped_otn, s_drop_action, pkt);
    mock().expectOneCall("remove_oops_handler");
    expect_finalization(DAQ_VERDICT_BLOCK);

    bool escaped = false;
    bool result = true;
    try
    {
        result = run_mitigated(MitigationAction::Drop);
    }
    catch ( const MitigationException& )
    {
        escaped = true;
    }

    std::signal(SIGFPE, prev_handler);
    CHECK_FALSE_TEXT(escaped, "fault while logging mitigator event escaped as MitigationException");
    CHECK_FALSE(result);
    mock().checkExpectations();
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
