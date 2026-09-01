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
// survivor_flow_data_test.cc author Bhumika Sachdeva <bsachdev@cisco.com>

// Exercises the real Flow survivor-pinning path and SurvivorFlowData (not
// the no-op stub other flow/ tests link), proving the A -> B -> C rebind gap.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <set>

#include "detection/context_switcher.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/flow_control.h"
#include "flow/ha.h"
#include "framework/inspector.h"
#include "framework/reload_survivor_subscriptions_impl.h"
#include "helpers/policy_switcher.h"
#include "main/analyzer.h"
#include "managers/inspector_manager.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "utils/util.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#define SURVIVOR_FLOW_DATA_TEST
#include "flow_stubs.h"
#undef SURVIVOR_FLOW_DATA_TEST

using namespace snort;

namespace snort
{
const SnortConfig* SnortConfig::get_conf() { return nullptr; }

char* snort_strdup(const char* str)
{
    CHECK(str);
    const size_t length = strlen(str) + 1;
    auto* copy = static_cast<char*>(snort_alloc(length));
    memcpy(copy, str, length);
    return copy;
}

// real ref-counting -- unlike every other flow/ test's no-op version, this
// one needs to actually observe whether SurvivorFlowData is holding a ref
Inspector::Inspector()
{
    ref_count = new std::atomic_uint[2];
    ref_count[0] = 0;
    ref_count[1] = 0;
}

Inspector::~Inspector()
{
    CHECK_EQUAL(0u, ref_count[0].load());
    CHECK_EQUAL(0u, ref_count[1].load());
    delete[] ref_count;
}

bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
void Inspector::add_ref() { ++ref_count[1]; }
void Inspector::rem_ref() { --ref_count[1]; }
void Inspector::add_global_ref() { ++ref_count[0]; }
void Inspector::rem_global_ref() { --ref_count[0]; }

// controllable stand-in for the real is_pending_tterm(): tests mark which
// Inspector*s are "removed but still referenced".
static std::set<const Inspector*> pending;

bool InspectorManager::is_pending_tterm(const Inspector* pin)
{ return pending.count(pin) > 0; }

void InspectorManager::thread_drain_pending_tterm_if_pending(const Inspector*) { }
}

unsigned get_instance_id() { return 0; }

// remaining link-time needs of flow.cc/flow_data.cc/flow_stash.cc, mirrored
// from flow_test.cc's own stub set (not reused directly to keep Inspector's
// ref-counting real for this file only). The functionStatic suppressions on
// each stub match its non-static declaration in the linked TU (flow_control.cc,
// ha.cc, context_switcher.cc, ip.cc) -- we cannot legally make them
// static here without breaking the class signature.
THREAD_LOCAL class FlowControl* flow_con;

// cppcheck-suppress functionStatic ; stub matches non-static declaration in flow_control.cc
const FlowCacheConfig& FlowControl::get_flow_cache_config() const
{
    static FlowCacheConfig fcc;
    fcc.allowlist_cache = true;
    return fcc;
}

// cppcheck-suppress functionStatic ; stub matches non-static declaration in flow_control.cc
bool FlowControl::move_to_allowlist(snort::Flow*) { return true; }

bool HighAvailabilityManager::active() { return false; }
FlowHAState::FlowHAState() = default;
// cppcheck-suppress functionStatic ; stub matches non-static declaration in ha.cc
void FlowHAState::reset() { }

void DetectionEngine::onload(const Flow*) { }
Packet* DetectionEngine::set_next_packet(const Packet*, Flow*) { return nullptr; }
IpsContext* DetectionEngine::get_context() { return nullptr; }
DetectionEngine::DetectionEngine() { context = nullptr; }
DetectionEngine::~DetectionEngine() = default;

Packet test_packet;
Packet* DetectionEngine::get_current_packet() { return &test_packet; }

ContextSwitcher* Analyzer::get_switcher() { return nullptr; }
// cppcheck-suppress functionStatic ; stub matches non-static declaration in context_switcher.cc
snort::IpsContext* ContextSwitcher::get_context() const { return nullptr; }

bool layer::set_outer_ip_api(const Packet* const, ip::IpApi&, int8_t&) { return false; }
// cppcheck-suppress functionStatic ; stub matches non-static declaration in ip.cc
uint8_t ip::IpApi::ttl() const { return 0; }
const Layer* layer::get_mpls_layer(const Packet* const) { return nullptr; }

PolicySwitcher::PolicySwitcher(snort::Flow*) { }
PolicySwitcher::~PolicySwitcher() { }

namespace
{
class TestInspector : public Inspector
{
public:
    TestInspector() = default;
};
}

TEST_GROUP(survivor_flow_data)
{
    void setup() override
    {
        pending.clear();
    }
};

// sanity: a single removed inspector gets pinned and stays referenced
// after the flow rebinds away from it
TEST(survivor_flow_data, single_pending_gadget_stays_pinned_across_rebind)
{
    TestInspector a, b;
    Flow flow;

    flow.set_gadget(&a);
    // cppcheck-suppress danglingLifetime ; false positive: pending is cleared in setup() before every test; &a is inserted and queried only while a is alive in this test
    pending.insert(&a);  // a is now "removed" while still gadget

    flow.set_gadget(&b);           // rebind away from removed a

    CHECK_EQUAL(1u, a.get_ref(1)); // SurvivorFlowData's pin, not the ordinary ref
    CHECK_EQUAL(1u, b.get_ref(1));

    // flow's destructor runs before a/b's (declared after them): it frees
    // the SurvivorFlowData pin on a and drops b's ordinary gadget ref
    flow.clear_gadget();
}

// A rebind from an inspector that is not pending must not create survivor
// flow data or retain an extra reference beyond the ordinary gadget refs.
TEST(survivor_flow_data, non_pending_gadget_rebind_does_not_pin_survivor)
{
    TestInspector a, b;
    Flow flow;

    flow.set_gadget(&a);
    CHECK_EQUAL(1u, a.get_ref(1));

    flow.set_gadget(&b);

    CHECK_EQUAL(0u, a.get_ref(1));
    CHECK_EQUAL(1u, b.get_ref(1));
    CHECK(nullptr == flow.get_flow_data(SurvivorFlowData::get_flow_data_id()));

    flow.clear_gadget();

    CHECK_EQUAL(0u, b.get_ref(1));
    CHECK(nullptr == flow.get_flow_data(SurvivorFlowData::get_flow_data_id()));
}

// Regression guard: A -> B -> C where BOTH A and B are pending_tterm at
// their respective rebind. Each must be pinned when the flow is rebound
// away from it while it is still the gadget; before this fix the second
// one (B) silently was not.
TEST(survivor_flow_data, second_distinct_pending_inspector_is_also_pinned)
{
    TestInspector a, b, c;
    Flow flow;

    flow.set_gadget(&a);
    pending.insert(&a);
    flow.set_gadget(&b);            // A -> B: A is pending, gets pinned correctly
    CHECK_EQUAL(1u, a.get_ref(1));

    // cppcheck-suppress danglingLifetime ; false positive: pending is cleared in setup() before every test; &b is inserted and queried only while b is alive in this test
    pending.insert(&b);  // B is now ALSO removed, while still gadget
    flow.set_gadget(&c);             // B -> C: B should get pinned too

    CHECK_EQUAL(1u, a.get_ref(1));   // A's earlier pin: still fine
    CHECK_EQUAL(1u, b.get_ref(1));   // B's pin: the case this fix restores

    // flow's destructor runs before a/b/c's: it should free the
    // SurvivorFlowData pin(s) and drop c's ordinary gadget ref
    flow.clear_gadget();
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
