//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Cisco and/or its affiliates. All rights reserved.
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

// flow_test.cc author Prajwal Srinivas <psreenat@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "detection/context_switcher.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/flow_config.h"
#include "flow/flow_control.h"
#include "flow/flow_key.h"
#include "flow/flow_stash.h"
#include "flow/ha.h"
#include "flow/session.h"
#include "framework/inspector.h"
#include "framework/data_bus.h"
#include "helpers/policy_switcher.h"
#include "main/analyzer.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "managers/plugin_manager.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "time/clock_defs.h"
#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#define FLOW_RESTART_PUBLISH_TEST
#include "flow_stubs.h"
#undef FLOW_RESTART_PUBLISH_TEST

#include "trace/trace.h"

using namespace snort;

namespace snort
{
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}

char* snort_strdup(const char* str)
{
    assert(str);
    const size_t length = strlen(str) + 1;
    auto* copy = static_cast<char*>(snort_alloc(length));
    memcpy(copy, str, length);
    return copy;
}
}

THREAD_LOCAL class FlowControl* flow_con;

const FlowCacheConfig& FlowControl::get_flow_cache_config() const
{
    static FlowCacheConfig fcc;
    fcc.allowlist_cache = true;
    return fcc;
}

bool FlowControl:: move_to_allowlist(snort::Flow*) { return true; }

static Flow* test_unlink_uni_flow = nullptr;
static Flow* test_relink_uni_flow = nullptr;

FlowControl::FlowControl(const FlowCacheConfig&) { }
FlowControl::~FlowControl() = default;
void FlowControl::unlink_uni(snort::Flow* flow) { test_unlink_uni_flow = flow; }
void FlowControl::relink_uni(snort::Flow* flow) { test_relink_uni_flow = flow; }

Inspector::Inspector() : ref_count(nullptr) { }
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

void Inspector::rem_ref() {}

void Inspector::add_ref() {}

bool HighAvailabilityManager::active() { return false; }

FlowHAState::FlowHAState() = default;

void FlowHAState::reset() {}

void DetectionEngine::onload(const Flow*) {}

Packet* DetectionEngine::set_next_packet(const Packet*, Flow*) { return nullptr; }

ContextSwitcher* Analyzer::get_switcher() { return nullptr; }
snort::IpsContext* ContextSwitcher::get_context() const { return nullptr; }
IpsContext* DetectionEngine::get_context() { return nullptr; }

DetectionEngine::DetectionEngine() { context = nullptr; }

DetectionEngine::~DetectionEngine() = default;

Packet test_packet;
Packet* DetectionEngine::get_current_packet() { return &test_packet; }

bool layer::set_outer_ip_api(const Packet* const, ip::IpApi&, int8_t&)
{ return false; }

uint8_t ip::IpApi::ttl() const { return 0; }

const Layer* layer::get_mpls_layer(const Packet* const) { return nullptr; }

const SnortConfig* SnortConfig::get_conf() { return nullptr; }

PolicySwitcher::PolicySwitcher(snort::Flow*) { }
PolicySwitcher::~PolicySwitcher() { }

TEST_GROUP(nondefault_timeout)
{
};

TEST(nondefault_timeout, hard_expiration)
{
    uint64_t validate = 100;
    Packet pkt(false);
    Flow *flow = new Flow;
    DAQ_PktHdr_t pkthdr;

    pkt.pkth = &pkthdr;
    pkthdr.ts.tv_sec = 0;

    flow->set_default_session_timeout(validate, true);
    flow->set_hard_expiration();
    flow->set_expire(&pkt, validate);

    CHECK( flow->is_hard_expiration() == true);
    CHECK( flow->expire_time == validate );

    delete flow;
}

TEST_GROUP(flow_restart)
{
};

TEST(flow_restart, resets_service_event_generated)
{
    Flow flow;
    flow.flags.svc_event_generated = true;

    flow.restart(false);

    CHECK_FALSE(flow.flags.svc_event_generated);
}

TEST(flow_restart, blocked_flow_regains_uni_candidacy)
{
    FlowCacheConfig fcc;
    FlowControl flow_control(fcc);
    FlowKey flow_key = {};
    Flow flow;

    flow.key = &flow_key;
    flow_con = &flow_control;
    test_unlink_uni_flow = nullptr;
    test_relink_uni_flow = nullptr;

    flow.block();
    CHECK(flow.was_blocked());
    POINTERS_EQUAL(&flow, test_unlink_uni_flow);

    flow.restart(false);
    CHECK_FALSE(flow.was_blocked());
    POINTERS_EQUAL(&flow, test_relink_uni_flow);

    flow.key = nullptr;
    flow_con = nullptr;
}

TEST(flow_restart, bidirectional_blocked_flow_is_not_relinked)
{
    FlowCacheConfig fcc;
    FlowControl flow_control(fcc);
    FlowKey flow_key = {};
    Flow flow;

    flow.key = &flow_key;
    flow_con = &flow_control;
    test_unlink_uni_flow = nullptr;
    test_relink_uni_flow = nullptr;

    flow.ssn_state.session_flags = SSNFLAG_SEEN_BOTH;
    flow.block();
    POINTERS_EQUAL(&flow, test_unlink_uni_flow);

    flow.restart(false);
    CHECK_FALSE(flow.was_blocked());
    CHECK_FALSE(flow.two_way_traffic());
    POINTERS_EQUAL(nullptr, test_relink_uni_flow);

    flow.key = nullptr;
    flow_con = nullptr;
}

TEST(flow_restart, unblocked_flow_keeps_its_candidacy)
{
    FlowCacheConfig fcc;
    FlowControl flow_control(fcc);
    FlowKey flow_key = {};
    Flow flow;

    flow.key = &flow_key;
    flow_con = &flow_control;
    test_relink_uni_flow = nullptr;

    flow.restart(false);
    POINTERS_EQUAL(nullptr, test_relink_uni_flow);

    flow.key = nullptr;
    flow_con = nullptr;
}

TEST_GROUP(uni_candidacy)
{
    FlowCacheConfig fcc;
    FlowControl* flow_control = nullptr;
    FlowKey flow_key = {};

    void setup() override
    {
        flow_control = new FlowControl(fcc);
        flow_con = flow_control;
        test_unlink_uni_flow = nullptr;
        test_relink_uni_flow = nullptr;
    }

    void teardown() override
    {
        flow_con = nullptr;
        delete flow_control;
    }
};

// a standby flow gets its block state from an HA import that assigns ssn_state
// wholesale, bypassing set_block_flags(); both directions have to be reconciled
TEST(uni_candidacy, imported_block_state_is_reconciled_both_ways)
{
    Flow flow;
    flow.key = &flow_key;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT;

    uint32_t prev_session_flags = flow.ssn_state.session_flags;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT | SSNFLAG_BLOCK;
    flow.update_uni_candidacy(prev_session_flags);
    POINTERS_EQUAL(&flow, test_unlink_uni_flow);
    POINTERS_EQUAL(nullptr, test_relink_uni_flow);

    prev_session_flags = flow.ssn_state.session_flags;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT;
    flow.update_uni_candidacy(prev_session_flags);
    POINTERS_EQUAL(&flow, test_relink_uni_flow);

    flow.key = nullptr;
}

// unlike restart(), an import can clear the drop bits while SSNFLAG_SEEN_* stay
// set, and a flow with two way traffic is not a uni prune candidate
TEST(uni_candidacy, bidirectional_flow_is_not_relinked)
{
    Flow flow;
    flow.key = &flow_key;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_BOTH | SSNFLAG_BLOCK;

    const uint32_t prev_session_flags = flow.ssn_state.session_flags;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_BOTH;
    flow.update_uni_candidacy(prev_session_flags);

    CHECK_FALSE(flow.was_blocked());
    POINTERS_EQUAL(nullptr, test_relink_uni_flow);

    flow.key = nullptr;
}

// an import that leaves the block state alone has nothing to undo
TEST(uni_candidacy, unchanged_block_state_is_inert)
{
    Flow flow;
    flow.key = &flow_key;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT;

    const uint32_t prev_session_flags = flow.ssn_state.session_flags;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT | SSNFLAG_ESTABLISHED;
    flow.update_uni_candidacy(prev_session_flags);

    POINTERS_EQUAL(nullptr, test_unlink_uni_flow);
    POINTERS_EQUAL(nullptr, test_relink_uni_flow);

    flow.key = nullptr;
}

TEST(flow_restart, resets_peak_memory_to_current_usage)
{
    Flow flow;
    const size_t initial = flow.get_mem_usage();

    // Model memory retained across a restart plus a transient old-session peak.
    flow.add_mem(256);
    flow.add_mem(512);
    flow.sub_mem(512);
    CHECK(flow.get_peak_mem_usage() > flow.get_mem_usage());

    flow.restart(false);

    UNSIGNED_LONGS_EQUAL(initial + 256, flow.get_mem_usage());
    UNSIGNED_LONGS_EQUAL(flow.get_mem_usage(), flow.get_peak_mem_usage());

    flow.sub_mem(256);
}

TEST_GROUP(inspection_time_presence)
{
};

TEST(inspection_time_presence, inspection_time_addition)
{
    Flow *flow = new Flow;

    flow->flowstats.client_pkts = 3;
    flow->flowstats.server_pkts = 3;

    flow->add_inspection_duration(2);
    flow->add_inspection_duration(3);

    CHECK(flow->get_inspection_duration() == 5);
    CHECK(flow->get_inspected_packet_count() == 6);

    flow->set_state(Flow::FlowState::ALLOW);

    flow->add_inspection_duration(2);

    flow->flowstats.client_pkts = 5;
    flow->flowstats.server_pkts = 5;

    CHECK(flow->get_inspection_duration() == 5);
    CHECK(flow->get_inspected_packet_count() == 6);

    delete flow;
}

class TestFlowData : public FlowData
{
public:
    explicit TestFlowData(unsigned v) : FlowData(module_id), version(v)
    { }
    ~TestFlowData() override = default;

    unsigned get_version() const
    { return version; }

    static unsigned module_id;

    static void init()
    { module_id = FlowData::create_flow_data_id(); }

protected:
    unsigned version;
};

unsigned TestFlowData::module_id = 0;

class HigherIdFlowData : public FlowData
{
public:
    HigherIdFlowData() : FlowData(module_id)
    { }
    ~HigherIdFlowData() override = default;

    static unsigned module_id;

    static void init()
    { module_id = FlowData::create_flow_data_id(); }
};

unsigned HigherIdFlowData::module_id = 0;

static bool restart_cleanup_observed = false;
static bool restart_event_observed = false;

static void observe_restart_cleanup(Packet*, const Flow* flow)
{
    uint32_t stash_value = 0;
    restart_cleanup_observed = !flow->get_flow_data(TestFlowData::module_id)
        && !flow->get_attr("restart-test", stash_value);
    restart_event_observed = true;
}

class TestInspector : public Inspector
{
public:
    TestInspector() = default;
};

class TestSession : public Session
{
public:
    explicit TestSession(Flow* flow) : Session(flow)
    { }

    bool setup_after_restart(Packet* p) override
    {
        restart_setup_calls++;
        restart_packet = p;
        setup_observed_event = restart_event_observed;
        return restart_setup_result;
    }

    void clear() override
    { }

    unsigned restart_setup_calls = 0;
    Packet* restart_packet = nullptr;
    bool setup_observed_event = false;
    bool restart_setup_result = true;
};

TEST_GROUP(flow_restart_event_test)
{
    void setup() override
    {
        reset_test_packet_publish();
        restart_cleanup_observed = false;
        restart_event_observed = false;
    }

    void teardown() override
    { reset_test_packet_publish(); }
};

TEST(flow_restart_event_test, packet_restart_publishes_once_after_cleanup)
{
    TestInspector inspector;
    Flow flow;
    Packet packet(false);
    packet.flow = &flow;
    auto* session = new TestSession(&flow);
    flow.session = session;
    flow.set_client(&inspector);
    flow.set_state(Flow::FlowState::INSPECT);

    TestFlowData::init();
    flow.set_flow_data(new TestFlowData(1));
    uint32_t stash_value = 42;
    flow.set_attr("restart-test", stash_value);
    test_packet_publish_hook = observe_restart_cleanup;

    flow.restart(packet);

    UNSIGNED_LONGS_EQUAL(1, test_packet_publish_count);
    UNSIGNED_LONGS_EQUAL(intrinsic_pub_id, test_packet_publish_pub_id);
    UNSIGNED_LONGS_EQUAL(IntrinsicEventIds::FLOW_STATE_SETUP, test_packet_publish_event_id);
    POINTERS_EQUAL(&packet, test_published_packet);
    POINTERS_EQUAL(&flow, test_published_flow);
    CHECK_TRUE(restart_cleanup_observed);
    UNSIGNED_LONGS_EQUAL(1, session->restart_setup_calls);
    POINTERS_EQUAL(&packet, session->restart_packet);
    CHECK_TRUE(session->setup_observed_event);
    CHECK_TRUE(flow.flow_state == Flow::FlowState::INSPECT);
}

TEST(flow_restart_event_test, packet_restart_allows_flow_when_session_setup_fails)
{
    TestInspector inspector;
    Flow flow;
    Packet packet(false);
    packet.flow = &flow;
    auto* session = new TestSession(&flow);
    session->restart_setup_result = false;
    flow.session = session;
    flow.set_client(&inspector);
    flow.set_state(Flow::FlowState::INSPECT);

    flow.restart(packet);

    UNSIGNED_LONGS_EQUAL(1, test_packet_publish_count);
    UNSIGNED_LONGS_EQUAL(1, session->restart_setup_calls);
    CHECK_TRUE(flow.flow_state == Flow::FlowState::ALLOW);
}

TEST(flow_restart_event_test, packetless_restart_does_not_publish)
{
    TestInspector inspector;
    Flow flow;
    auto* session = new TestSession(&flow);
    flow.session = session;
    flow.set_client(&inspector);
    flow.set_state(Flow::FlowState::INSPECT);

    flow.restart();

    UNSIGNED_LONGS_EQUAL(0, test_packet_publish_count);
    UNSIGNED_LONGS_EQUAL(0, session->restart_setup_calls);
}

TEST_GROUP(flow_data_test)
{
};

TEST(flow_data_test, flow_data_access)
{
    unsigned lower_module_id = FlowData::create_flow_data_id();
    TestFlowData::init();
    HigherIdFlowData::init();
    unsigned higher_module_id = FlowData::create_flow_data_id();

    Flow *flow = new Flow;

    TestFlowData* existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(!existing_fd, "FlowData should not exist");

    // new
    TestFlowData* fd = new TestFlowData(1);
    flow->set_flow_data(fd);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(existing_fd, "FlowData should exist");
    UNSIGNED_LONGS_EQUAL_TEXT(1, existing_fd->get_version(), "FlowData version should be 1");

    // overwrite
    fd = new TestFlowData(2);
    flow->set_flow_data(fd);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(existing_fd, "FlowData should exist");
    UNSIGNED_LONGS_EQUAL_TEXT(2, existing_fd->get_version(), "FlowData version should be 2");

    // free by object
    flow->free_flow_data(fd);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(!existing_fd, "FlowData should not exist");

    HigherIdFlowData* hid_fd = new HigherIdFlowData;
    flow->set_flow_data(hid_fd);
    HigherIdFlowData* hid_existing_fd =
        static_cast<HigherIdFlowData*>(flow->get_flow_data(HigherIdFlowData::module_id));
    CHECK_TEXT(hid_existing_fd, "HigherIdFlowData should exist");

    fd = new TestFlowData(3);
    flow->set_flow_data(fd);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(existing_fd, "FlowData should exist");
    UNSIGNED_LONGS_EQUAL_TEXT(3, existing_fd->get_version(), "FlowData version should be 3");

    // free by id not found lower
    flow->free_flow_data(lower_module_id);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(existing_fd, "FlowData should exist");
    UNSIGNED_LONGS_EQUAL_TEXT(3, existing_fd->get_version(), "FlowData version should be 3");
    hid_existing_fd = static_cast<HigherIdFlowData*>(flow->get_flow_data(HigherIdFlowData::module_id));
    CHECK_TEXT(hid_existing_fd, "HigherIdFlowData should exist");

    // free by id not found higher
    flow->free_flow_data(higher_module_id);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(existing_fd, "FlowData should exist");
    UNSIGNED_LONGS_EQUAL_TEXT(3, existing_fd->get_version(), "FlowData version should be 3");
    hid_existing_fd = static_cast<HigherIdFlowData*>(flow->get_flow_data(HigherIdFlowData::module_id));
    CHECK_TEXT(hid_existing_fd, "HigherIdFlowData should exist");

    // free by id
    flow->free_flow_data(TestFlowData::module_id);
    existing_fd = static_cast<TestFlowData*>(flow->get_flow_data(TestFlowData::module_id));
    CHECK_TEXT(!existing_fd, "FlowData should not exist");
    hid_existing_fd = static_cast<HigherIdFlowData*>(flow->get_flow_data(HigherIdFlowData::module_id));
    CHECK_TEXT(hid_existing_fd, "HigherIdFlowData should exist");
    flow->free_flow_data(hid_existing_fd);
    hid_existing_fd = static_cast<HigherIdFlowData*>(flow->get_flow_data(HigherIdFlowData::module_id));
    CHECK_TEXT(!hid_existing_fd, "HigherIdFlowData should not exist");

    delete flow;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
