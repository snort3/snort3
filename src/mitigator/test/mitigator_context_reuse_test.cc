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
// mitigator_context_reuse_test.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <csignal>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "detection/context_switcher.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/fp_detect.h"
#include "detection/ips_context.h"
#include "detection/ips_context_data.h"
#include "detection/regex_offload.h"
#include "detection/signature.h"
#include "detection/treenodes.h"
#include "events/event.h"
#include "events/event_queue.h"
#include "events/sfeventq.h"
#include "filters/sfthreshold.h"
#include "flow/flow.h"
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
#include "mitigator/mitigator_api.h"
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
static ContextSwitcher* s_switcher = nullptr;
alignas(Analyzer) static unsigned char s_analyzer_storage[sizeof(Analyzer)];
static Analyzer* const s_analyzer = reinterpret_cast<Analyzer*>(s_analyzer_storage);
static const SnortConfig* s_conf = nullptr;

static OptTreeNode s_rule_otn;
static OptTreeNode s_next_rule_otn;
static OptTreeNode s_rebuilt_rule_otn;
static OptTreeNode s_dropped_otn;
static OptTreeNode s_blocked_otn;

static constexpr IpsAction::Type s_block_action = 5;
static constexpr IpsAction::Type s_drop_action = 6;
static constexpr IpsAction::Type s_unknown_action = 100;
static constexpr int s_queued_event_action = -1;

static unsigned s_unwinding_logs = 0;
static SThreadType s_thread_type = STHREAD_TYPE_OTHER;

// thresholds high enough that repeated runs never escalate to Abort
SETUP_MITIGATOR(drop_mitigator, "rebuilt_drop_test",
{
    MitigationPolicy{ MitigationAction::Drop, UINT32_MAX - 1 },
    MitigationPolicy{ MitigationAction::Abort, UINT32_MAX }
});

SETUP_MITIGATOR(block_mitigator, "rebuilt_block_test",
{
    MitigationPolicy{ MitigationAction::Block, UINT32_MAX - 1 },
    MitigationPolicy{ MitigationAction::Abort, UINT32_MAX }
});

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

[[noreturn]] static bool throw_mitigation_action(MitigationAction action)
{ throw MitigationActionException(action, "test_module"); }

[[noreturn]] static void raise_fault()
{ throw MitigationException(SIGSEGV); }

// per-packet inspector state that must be cleared before the context is reused
class PacketContextData : public IpsContextData
{
public:
    void clear() override
    {
        in_use = false;
        ++clears;
    }

    bool in_use = false;
    unsigned clears = 0;
};

//--------------------------------------------------------------------------
// mocks for the calls whose ordering is under test
//--------------------------------------------------------------------------

int fpLogEvent(const OptTreeNode* otn, Packet* p, int rate_action)
{
    // a mock failure cannot leave a destructor run by stack unwinding, so count instead
    if ( std::uncaught_exceptions() )
    {
        ++s_unwinding_logs;
        return 0;
    }

    mock().actualCall("log_event")
        .withUnsignedIntParameter("gid", otn->sigInfo.gid)
        .withUnsignedIntParameter("sid", otn->sigInfo.sid)
        .withIntParameter("rate_action", rate_action)
        .withPointerParameter("packet", p)
        .withConstPointerParameter("msg", p->daq_msg);
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
        .withUnsignedIntParameter("busy_contexts", s_switcher->busy_count())
        .withUnsignedIntParameter("queued_events", queued_otns(s_context).size())
        .withBoolParameter("pkth_valid", s_context->packet->pkth != nullptr);
    return 0;
}
}

//--------------------------------------------------------------------------
// stubs
//--------------------------------------------------------------------------

THREAD_LOCAL ProfileStats eventqPerfStats;
THREAD_LOCAL ProfileStats mpsePerfStats;
THREAD_LOCAL const Trace* detection_trace = nullptr;

// cppcheck-suppress-begin functionStatic ; test doubles must retain the production member signatures
Analyzer* Analyzer::get_local_analyzer() { return s_analyzer; }
ContextSwitcher* Analyzer::get_switcher() { return s_switcher; }
void Analyzer::post_process_packet(Packet*) { }

OptTreeNode::~OptTreeNode() = default;
OptTreeNode* OtnLookup(GHash*, uint32_t gid, uint32_t sid)
{
    if ( gid == GID_MITIGATOR and sid == MITIGATOR_EVENT_SIGNAL_DROPPED )
        return &s_dropped_otn;
    if ( gid == GID_MITIGATOR and sid == MITIGATOR_EVENT_SIGNAL_BLOCKED )
        return &s_blocked_otn;
    return nullptr;
}

void remove_oops_handler() { }
void fp_set_context(IpsContext&) { }
void fp_clear_context(const IpsContext&) { }
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

SnortConfig::SnortConfig(const char*) { }
SnortConfig::~SnortConfig() = default;
const SnortConfig* SnortConfig::get_conf() { return s_conf; }

Packet::Packet(bool) { active_inst = new Active; }
Packet::~Packet() { delete active_inst; }
void Packet::release_helpers() { }
bool Packet::is_detection_enabled(bool) { return true; }
void Packet::reset() { }

Flow::Flow() = default;
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;
void FlowStash::reset() { }
void Flow::release_gadget() { }
void Flow::pin_survivor_flow_data(Inspector&) { }
void Inspector::rem_ref() { }

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
IpsPolicy* get_empty_ips_policy(const SnortConfig*) { return nullptr; }
void set_ips_policy(IpsPolicy*) { }
NetworkPolicy* get_network_policy() { return nullptr; }
SThreadType get_thread_type() { return s_thread_type; }
void packet_gettimeofday(struct timeval* tv) { *tv = {}; }
void InspectorManager::probe_first(Packet*) { }
void InspectorManager::probe(Packet*) { }
void InspectorManager::clear(Packet*) { }
void InspectorManager::execute(Packet*) { }
void Stream::check_flow_closed(Packet*) { }
void Stream::disable_reassembly(Flow*) { }
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
// helpers
//--------------------------------------------------------------------------

static void set_otn(OptTreeNode& otn, uint32_t gid, uint32_t sid)
{
    otn.sigInfo.gid = gid;
    otn.sigInfo.sid = sid;
}

static void configure(SnortConfig& conf, EventQueueConfig& event_queue_conf)
{
    set_otn(s_rule_otn, 1, 1000);
    set_otn(s_next_rule_otn, 1, 1001);
    set_otn(s_rebuilt_rule_otn, 1, 1002);
    set_otn(s_dropped_otn, GID_MITIGATOR, MITIGATOR_EVENT_SIGNAL_DROPPED);
    set_otn(s_blocked_otn, GID_MITIGATOR, MITIGATOR_EVENT_SIGNAL_BLOCKED);

    event_queue_conf.max_events = 8;
    event_queue_conf.log_events = 8;
    conf.event_queue_config = &event_queue_conf;
    conf.run_flags = RUN_FLAG__INLINE;
    s_conf = &conf;
    s_thread_type = STHREAD_TYPE_PACKET;
}

static void queue_rule_event(IpsContext& c, const OptTreeNode& otn)
{
    EventNode* en = static_cast<EventNode*>(sfeventq_event_alloc(c.equeue));
    CHECK(en);
    en->otn = &otn;
    en->rtn = nullptr;
    LONGS_EQUAL(0, sfeventq_add(c.equeue, en));
}

static void expect_log(Packet* p, const OptTreeNode& otn, int rate_action, DAQ_Msg_h msg)
{
    mock().expectOneCall("log_event")
        .withUnsignedIntParameter("gid", otn.sigInfo.gid)
        .withUnsignedIntParameter("sid", otn.sigInfo.sid)
        .withIntParameter("rate_action", rate_action)
        .withPointerParameter("packet", p)
        .withConstPointerParameter("msg", msg);
}

static void expect_finalization(SFDAQInstance& daq, DAQ_Msg_h msg, DAQ_Verdict verdict)
{
    mock().expectOneCall("clear_current_daq_message").onObject(s_analyzer);
    mock().expectOneCall("finalize_message").onObject(&daq)
        .withConstPointerParameter("msg", msg)
        .withParameter("verdict", verdict)
        .withUnsignedIntParameter("busy_contexts", 1)
        .withUnsignedIntParameter("queued_events", 0)
        .withBoolParameter("pkth_valid", false);
}

//--------------------------------------------------------------------------
// wire packet tests
//--------------------------------------------------------------------------

TEST_GROUP(mitigator_context_reuse_tests)
{
    SnortConfig conf;
    EventQueueConfig event_queue_conf {};
    ContextSwitcher switcher;
    IpsContext* context = nullptr;
    PacketContextData* context_data = nullptr;
    SFDAQInstance first_daq { nullptr, 0, nullptr };
    SFDAQInstance next_daq { nullptr, 1, nullptr };
    int first_msg_data = 0;
    int next_msg_data = 0;
    DAQ_Msg_h first_msg = reinterpret_cast<DAQ_Msg_h>(&first_msg_data);
    DAQ_Msg_h next_msg = reinterpret_cast<DAQ_Msg_h>(&next_msg_data);
    PacketMitigator packet_mitigator;

    void setup() override
    {
        configure(conf, event_queue_conf);

        // a single context forces the next packet onto the mitigated one
        context = new IpsContext(1);
        context_data = new PacketContextData;
        context->set_context_data(0, context_data);
        switcher.push(context);
        s_context = context;
        s_switcher = &switcher;

        mock().strictOrder();
    }

    void teardown() override
    {
        mock().clear();
        s_context = nullptr;
        s_switcher = nullptr;
        s_conf = nullptr;
    }

    void start_packet(SFDAQInstance& daq, DAQ_Msg_h msg)
    {
        // fail here rather than on the switcher assert if the context was not released
        UNSIGNED_LONGS_EQUAL(1, switcher.idle_count());
        switcher.start();

        Packet* p = context->packet;
        p->pkth = context->pkth;
        p->daq_instance = &daq;
        p->daq_msg = msg;
        context_data->in_use = true;
    }

    void queue_rule_event(const OptTreeNode& otn)
    { ::queue_rule_event(*context, otn); }

    void expect_log(const OptTreeNode& otn, IpsAction::Type action, DAQ_Msg_h msg)
    { ::expect_log(context->packet, otn, action, msg); }

    bool run_mitigated(MitigationAction action)
    {
        return packet_mitigator(context->packet, throw_mitigation_action, action);
    }

    // emulates inspection that raises an event on the current context
    bool run_inspected(const OptTreeNode& otn)
    {
        return packet_mitigator(context->packet, [this, &otn]()
        {
            queue_rule_event(otn);
            return true;
        });
    }

    void check_context_released()
    {
        UNSIGNED_LONGS_EQUAL(1, switcher.idle_count());
        UNSIGNED_LONGS_EQUAL(0, switcher.busy_count());
        CHECK(context->state == IpsContext::IDLE);
        CHECK(context->packet->pkth == nullptr);
        CHECK(queued_otns(context).empty());
        CHECK_FALSE(context_data->in_use);
    }
};

TEST(mitigator_context_reuse_tests, drop_returns_cleared_context_to_pool)
{
    start_packet(first_daq, first_msg);
    queue_rule_event(s_rule_otn);

    expect_log(s_dropped_otn, s_drop_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLOCK);

    CHECK_FALSE(run_mitigated(MitigationAction::Drop));
    mock().checkExpectations();
    check_context_released();
    UNSIGNED_LONGS_EQUAL(1, context_data->clears);
}

TEST(mitigator_context_reuse_tests, block_returns_cleared_context_to_pool)
{
    start_packet(first_daq, first_msg);
    queue_rule_event(s_rule_otn);

    expect_log(s_blocked_otn, s_block_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLACKLIST);

    CHECK_FALSE(run_mitigated(MitigationAction::Block));
    mock().checkExpectations();
    check_context_released();
    UNSIGNED_LONGS_EQUAL(1, context_data->clears);
}

TEST(mitigator_context_reuse_tests, next_packet_after_drop_reuses_clean_context)
{
    start_packet(first_daq, first_msg);
    queue_rule_event(s_rule_otn);
    expect_log(s_dropped_otn, s_drop_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLOCK);
    CHECK_FALSE(run_mitigated(MitigationAction::Drop));

    start_packet(next_daq, next_msg);
    CHECK_TRUE(run_inspected(s_next_rule_otn));

    const std::vector<const OptTreeNode*> expected { &s_next_rule_otn };
    CHECK(queued_otns(context) == expected);

    expect_log(s_dropped_otn, s_drop_action, next_msg);
    expect_finalization(next_daq, next_msg, DAQ_VERDICT_BLOCK);

    CHECK_FALSE(run_mitigated(MitigationAction::Drop));
    mock().checkExpectations();
    check_context_released();
    UNSIGNED_LONGS_EQUAL(2, context_data->clears);
}

TEST(mitigator_context_reuse_tests, next_packet_after_block_reuses_clean_context)
{
    start_packet(first_daq, first_msg);
    queue_rule_event(s_rule_otn);
    expect_log(s_blocked_otn, s_block_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLACKLIST);
    CHECK_FALSE(run_mitigated(MitigationAction::Block));

    start_packet(next_daq, next_msg);
    CHECK_TRUE(run_inspected(s_next_rule_otn));

    const std::vector<const OptTreeNode*> expected { &s_next_rule_otn };
    CHECK(queued_otns(context) == expected);

    expect_log(s_dropped_otn, s_drop_action, next_msg);
    expect_finalization(next_daq, next_msg, DAQ_VERDICT_BLOCK);

    CHECK_FALSE(run_mitigated(MitigationAction::Drop));
    mock().checkExpectations();
    check_context_released();
    UNSIGNED_LONGS_EQUAL(2, context_data->clears);
}

//--------------------------------------------------------------------------
// rebuilt packet tests
//--------------------------------------------------------------------------

TEST_GROUP(mitigator_rebuilt_packet_tests)
{
    SnortConfig conf;
    EventQueueConfig event_queue_conf {};
    ContextSwitcher switcher;
    IpsContext* wire = nullptr;
    IpsContext* rebuilt = nullptr;
    PacketContextData* rebuilt_data = nullptr;
    SFDAQInstance first_daq { nullptr, 0, nullptr };
    SFDAQInstance next_daq { nullptr, 1, nullptr };
    int first_msg_data = 0;
    int next_msg_data = 0;
    DAQ_Msg_h first_msg = reinterpret_cast<DAQ_Msg_h>(&first_msg_data);
    DAQ_Msg_h next_msg = reinterpret_cast<DAQ_Msg_h>(&next_msg_data);
    PacketMitigator packet_mitigator;

    void setup() override
    {
        configure(conf, event_queue_conf);

        // pushed first so that start() takes the wire context and set_next_packet() this one
        rebuilt = new IpsContext(1);
        rebuilt_data = new PacketContextData;
        rebuilt->set_context_data(0, rebuilt_data);
        switcher.push(rebuilt);

        wire = new IpsContext(1);
        switcher.push(wire);
        s_context = wire;
        s_switcher = &switcher;
        s_unwinding_logs = 0;

        CHECK_TRUE(mitigator_enable_module(std::string(drop_mitigator.config.module)));
        CHECK_TRUE(mitigator_enable_module(std::string(block_mitigator.config.module)));

        mock().strictOrder();
    }

    void teardown() override
    {
        mock().clear();
        s_context = nullptr;
        s_switcher = nullptr;
        s_conf = nullptr;
    }

    void start_packet(SFDAQInstance& daq, DAQ_Msg_h msg)
    {
        // fail here rather than on the switcher assert if a context was not released
        UNSIGNED_LONGS_EQUAL(2, switcher.idle_count());
        switcher.start();

        Packet* p = wire->packet;
        p->pkth = wire->pkth;
        p->daq_instance = &daq;
        p->daq_msg = msg;
    }

    // emulates TcpReassemblerBase::flush_to_seq(): the PDU is inspected in its own
    // context, which queues an event before a mitigated module runs and may fault
    bool run_rebuilt(const OptTreeNode& otn, Mitigator* faulting_module = nullptr)
    {
        return packet_mitigator(wire->packet, [this, &otn, faulting_module]()
        {
            DetectionEngine::set_next_packet(wire->packet);
            DetectionEngine de;
            rebuilt_data->in_use = true;
            queue_rule_event(*rebuilt, otn);

            if ( faulting_module )
                (*faulting_module)(raise_fault);

            return true;
        });
    }

    void check_contexts_released()
    {
        UNSIGNED_LONGS_EQUAL(2, switcher.idle_count());
        UNSIGNED_LONGS_EQUAL(0, switcher.busy_count());
        CHECK(wire->state == IpsContext::IDLE);
        CHECK(rebuilt->state == IpsContext::IDLE);
        CHECK(queued_otns(rebuilt).empty());
        CHECK_FALSE(rebuilt_data->in_use);
    }
};

TEST(mitigator_rebuilt_packet_tests, drop_discards_rebuilt_packet_events)
{
    start_packet(first_daq, first_msg);

    expect_log(wire->packet, s_dropped_otn, s_drop_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLOCK);

    CHECK_FALSE(run_rebuilt(s_rebuilt_rule_otn, &drop_mitigator));
    mock().checkExpectations();
    UNSIGNED_LONGS_EQUAL(0, s_unwinding_logs);
    check_contexts_released();
    UNSIGNED_LONGS_EQUAL(1, rebuilt_data->clears);
}

TEST(mitigator_rebuilt_packet_tests, block_discards_rebuilt_packet_events)
{
    start_packet(first_daq, first_msg);

    expect_log(wire->packet, s_blocked_otn, s_block_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLACKLIST);

    CHECK_FALSE(run_rebuilt(s_rebuilt_rule_otn, &block_mitigator));
    mock().checkExpectations();
    UNSIGNED_LONGS_EQUAL(0, s_unwinding_logs);
    check_contexts_released();
    UNSIGNED_LONGS_EQUAL(1, rebuilt_data->clears);
}

TEST(mitigator_rebuilt_packet_tests, next_rebuilt_packet_after_drop_logs_events)
{
    start_packet(first_daq, first_msg);
    expect_log(wire->packet, s_dropped_otn, s_drop_action, first_msg);
    expect_finalization(first_daq, first_msg, DAQ_VERDICT_BLOCK);
    CHECK_FALSE(run_rebuilt(s_rebuilt_rule_otn, &drop_mitigator));

    start_packet(next_daq, next_msg);
    expect_log(rebuilt->packet, s_next_rule_otn, s_queued_event_action, next_msg);

    CHECK_TRUE(run_rebuilt(s_next_rule_otn));
    mock().checkExpectations();

    switcher.stop();
    check_contexts_released();
    UNSIGNED_LONGS_EQUAL(2, rebuilt_data->clears);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
