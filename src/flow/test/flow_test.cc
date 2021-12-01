//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/flow_stash.h"
#include "flow/ha.h"
#include "framework/inspector.h"
#include "framework/data_bus.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

Packet::Packet(bool) { }
Packet::~Packet()  = default;

void Inspector::rem_ref() {}

void Inspector::add_ref() {}

bool HighAvailabilityManager::active() { return false; }

FlowHAState::FlowHAState() = default;

void FlowHAState::reset() {}

FlowStash::~FlowStash() = default;

void FlowStash::reset() {}

void DetectionEngine::onload(Flow*) {}

Packet* DetectionEngine::set_next_packet(Packet*, Flow*) { return nullptr; }

IpsContext* DetectionEngine::get_context() { return nullptr; }

DetectionEngine::DetectionEngine() = default;

DetectionEngine::~DetectionEngine() = default;

bool layer::set_outer_ip_api(const Packet* const, ip::IpApi&, int8_t&)
{ return false; }

uint8_t ip::IpApi::ttl() const { return 0; }

const Layer* layer::get_mpls_layer(const Packet* const) { return nullptr; }

void DataBus::publish(const char*, Packet*, Flow*) {}

const SnortConfig* SnortConfig::get_conf() { return nullptr; }

TEST_GROUP(nondefault_timeout)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(nondefault_timeout, hard_expiration)
{
    uint64_t validate = 100;
    Packet pkt(false);
    Flow *flow = new Flow();
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

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}


