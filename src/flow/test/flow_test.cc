//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/context_switcher.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/flow_config.h"
#include "flow/flow_control.h"
#include "flow/flow_stash.h"
#include "flow/ha.h"
#include "framework/inspector.h"
#include "framework/data_bus.h"
#include "main/analyzer.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "time/clock_defs.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "flow_stubs.h"

using namespace snort;
THREAD_LOCAL class FlowControl* flow_con;

const FlowCacheConfig& FlowControl::get_flow_cache_config() const
{
    static FlowCacheConfig fcc;
    fcc.allowlist_cache = true;
    return fcc;
}

bool FlowControl:: move_to_allowlist(snort::Flow*) { return true; }

void Inspector::rem_ref() {}

void Inspector::add_ref() {}

bool HighAvailabilityManager::active() { return false; }

FlowHAState::FlowHAState() = default;

void FlowHAState::reset() {}

void DetectionEngine::onload(Flow*) {}

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


