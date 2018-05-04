//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// proto_ref_test.cc author Victor Roemer, <viroemer@cisco.com>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>

#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "target_based/snort_protocols.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

TEST_GROUP(protocol_reference)
{};

// Service Protocols
//
// Verify normal behaviour of service protocols being registered.
//   1. Check that ID's are unique
//   2. Check that same ID's are returned on |add| and |find|
//   3. Check the builtin tests
//     * is_network_protocol()
//     * is_builtin_protocol()
//     * is_service_protocol()
TEST(protocol_reference, service_protocols)
{
    ProtocolReference refs;

    SnortProtocolId t0 = refs.add("test0");
    SnortProtocolId t1 = refs.add("test1");
    SnortProtocolId t2 = refs.add("test2");
    SnortProtocolId t3 = refs.add("test3");

    CHECK( refs.find("test0") == t0 );
    CHECK( refs.find("test1") == t1 );
    CHECK( refs.find("test2") == t2 );
    CHECK( refs.find("test3") == t3 );

    CHECK( t0 < t1 and t1 < t2 and t2 < t3 );

    CHECK( !is_network_protocol(t0) );
    CHECK( !is_builtin_protocol(t0) );
    CHECK( is_service_protocol(t0) );

    CHECK( !is_network_protocol(t1) );
    CHECK( !is_builtin_protocol(t1) );
    CHECK( is_service_protocol(t1) );

    CHECK( !is_network_protocol(t2) );
    CHECK( !is_builtin_protocol(t2) );
    CHECK( is_service_protocol(t2) );

    CHECK( !is_network_protocol(t3) );
    CHECK( !is_builtin_protocol(t3) );
    CHECK( is_service_protocol(t3) );
}

// Builtin Protocols (ip, icmp, tcp, udp, user and file)
//
// Verify normal behaviour of the builtin protocols.
//   1. Check the builtin protocols match the hardcoded ID's
//   2. Check the builtin tests
//     * is_network_protocol()
//     * is_builtin_protocol()
//     * is_service_protocol()
TEST(protocol_reference, builtin_protocols) 
{
    ProtocolReference refs;

    SnortProtocolId unknown = refs.add("unknown");
    CHECK( unknown == UNKNOWN_PROTOCOL_ID );
    CHECK( !is_network_protocol(unknown) );
    CHECK( is_builtin_protocol(unknown) );
    CHECK( !is_service_protocol(unknown) );

    SnortProtocolId ip = refs.add("ip");
    CHECK( ip == SNORT_PROTO_IP );
    CHECK( is_network_protocol(ip) );
    CHECK( is_builtin_protocol(ip) );
    CHECK( !is_service_protocol(ip) );

    SnortProtocolId icmp = refs.add("icmp");
    CHECK( icmp == SNORT_PROTO_ICMP );
    CHECK( is_network_protocol(icmp) );
    CHECK( is_builtin_protocol(icmp) );
    CHECK( !is_service_protocol(icmp) );

    SnortProtocolId tcp = refs.add("tcp");
    CHECK( tcp == SNORT_PROTO_TCP );
    CHECK( is_network_protocol(tcp) );
    CHECK( is_builtin_protocol(tcp) );
    CHECK( !is_service_protocol(tcp) );

    SnortProtocolId udp = refs.add("udp");
    CHECK( udp == SNORT_PROTO_UDP );
    CHECK( is_network_protocol(udp) );
    CHECK( is_builtin_protocol(udp) );
    CHECK( !is_service_protocol(udp) );

    SnortProtocolId user = refs.add("user");
    CHECK( user == SNORT_PROTO_USER );
    CHECK( !is_network_protocol(user) );
    CHECK( is_builtin_protocol(user) );
    CHECK( is_service_protocol(user) );

    SnortProtocolId file = refs.add("file");
    CHECK( file == SNORT_PROTO_FILE );
    CHECK( !is_network_protocol(file) );
    CHECK( is_builtin_protocol(file) );
    CHECK( is_service_protocol(file) );
}

// Find none
//
// Verify UNKNOWN_PROTOCOL_ID is returned for non-existent protocols
TEST(protocol_reference, find_none)
{
    ProtocolReference refs;
    CHECK(refs.find("nothing") == UNKNOWN_PROTOCOL_ID);
}

// Double add
//
// Verify protocols only added once
TEST(protocol_reference, double_add)
{
    ProtocolReference refs;
    SnortProtocolId id = refs.add("http");
    CHECK( id == refs.add("http") );
}

// Nullptr add
//
// Verify UNKNOWN_PROTOCOL_ID is returned when calling add with a null string
TEST(protocol_reference, nullptr_add)
{
    ProtocolReference refs;
    CHECK( refs.add(nullptr) == UNKNOWN_PROTOCOL_ID );
}

// Reverse Lookup Unknown
//
// Verify "unknown" is returned when looking up UNKNOWN_PROTOCOL_ID
TEST(protocol_reference, reverse_lookup)
{
    ProtocolReference refs;
    CHECK( std::string(refs.get_name(UNKNOWN_PROTOCOL_ID)) == "unknown");
}

// Construct from old references
//
// Verify construction from an previously existing ProtocolReference
TEST(protocol_reference, constructors)
{
    ProtocolReference old;
    SnortProtocolId unknown = old.find("unknown");
    SnortProtocolId custom = old.add("custom");

    ProtocolReference refs(&old);
    CHECK( refs.find("custom") == custom );
    CHECK( refs.find("unknown") == unknown );
}

// Verify calling get_name(id) where id > id_map.size() returns "unknown".
TEST(protocol_reference, getname_gt_mapsize)
{
    ProtocolReference refs;
    CHECK( std::string(refs.get_name(100)) == "unknown"  );
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

