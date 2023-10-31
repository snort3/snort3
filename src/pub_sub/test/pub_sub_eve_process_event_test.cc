//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_eve_process_event_test.cc author Cliff Judge <cljudge@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pub_sub/eve_process_event.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

Packet::Packet(bool)
    : flow(nullptr), packet_flags(0), xtradata_mask(0), proto_bits(0), alt_dsize(0), num_layers(0),
    disable_inspect(true), sect(PS_NONE), active_inst(nullptr), pkth(nullptr), pkt(nullptr), layers(nullptr),
    user_inspection_policy_id(0), user_ips_policy_id(0), user_network_policy_id(0), vlan_idx(0),
    ts_packet_flags(0), allocated(false)
{ }
Packet::~Packet() = default;

TEST_GROUP(pub_sub_eve_process_event_test)
{
    void teardown() override
    {
        mock().clear();
    }
};

TEST(pub_sub_eve_process_event_test, eve_process_event)
{
    Packet p;
    std::vector<std::string> alpn = {"h3"};
    EveProcessEvent event(p, "process", 10);
    event.set_user_agent("chrome");
    event.set_server_name("www.google.com");
    event.set_alpn(alpn);
    CHECK(event.get_process_name() == "process");
    CHECK(event.get_process_confidence() == 10);
    CHECK(event.get_user_agent() == "chrome");
    CHECK(event.get_server_name() == "www.google.com");
    CHECK(event.get_alpn()[0] == "h3");
    CHECK(event.get_packet() == &p);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

