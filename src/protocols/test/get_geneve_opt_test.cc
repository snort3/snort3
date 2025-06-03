//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// get_geneve_opt_test.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/expect_flow.h"
#include "framework/api_options.h"
#include "packet_io/sfdaq_instance.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

void snort::ExpectFlow::reset_expect_flows() {}
const char* PacketManager::get_proto_name(ProtocolId) { return nullptr; }
const vlan::VlanTagHdr* layer::get_vlan_layer(const Packet*) { return nullptr; }
const geneve::GeneveLyr* layer::get_geneve_layer(const Packet*, bool) { return nullptr; }
void ip::IpApi::reset() {}
int SFDAQInstance::inject(_daq_msg const*, int, unsigned char const*, unsigned int) { return -1; }

uint8_t PacketManager::max_layers = DEFAULT_LAYERMAX;

TEST_GROUP(get_geneve_opt_tests)
{
};

TEST(get_geneve_opt_tests, no_geneve_data)
{
    Packet packet;
    auto vec = packet.get_geneve_options(false);
    CHECK_TRUE( vec.empty() );
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------
int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

