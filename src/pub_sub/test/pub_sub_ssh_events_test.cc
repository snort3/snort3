//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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

// pub_sub_ssh_events_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <cstring>

#include "pub_sub/ssh_events.h"
#include "service_inspectors/ssh/ssh.h"
#include "protocols/packet.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
Packet::Packet(bool)
    : flow(nullptr), packet_flags(0), xtradata_mask(0), proto_bits(0), alt_dsize(0), num_layers(0),
    ip_proto_next(IpProtocol::PROTO_NOT_SET), disable_inspect(true), sect(PS_NONE), active_inst(nullptr), pkth(nullptr),
    pkt(nullptr), layers(nullptr), user_inspection_policy_id(0), user_ips_policy_id(0), user_network_policy_id(0),
    inspection_started_timestamp(0), vlan_idx(0), ts_packet_flags(0), allocated(false), daq_msg(nullptr)
{ }
Packet::~Packet() = default;
}

TEST_GROUP(pub_sub_ssh_events_test) { };

TEST(pub_sub_ssh_events_test, ssh_algo_event_complete_access)
{
    const char* kex_algos = "Diffie-sha256,Diffie-sha512";
    const char* host_key_algos = "SSH2-sha512,SSH1-sha256,SSHFP";
    const char* cipher_c2s = "ctrk-SHA256,ctrl-sha512";
    const char* cipher_s2c = "XSHA256,XSHA1";
    const char* mac_c2s = "HMAC-SHA256,HMAC-sha512";
    const char* mac_s2c = "HMAC-sha512,HMAC-SHA256";
    const char* comp_c2s = "none,OpenSSH";
    const char* comp_s2c = "none,OpenSSH";

    SshAlgoEvent::Algorithms algos;
    memset(&algos, 0, sizeof(algos));

    algos.named.kex_algorithms = kex_algos;
    algos.named.server_host_key_algorithms = host_key_algos;
    algos.named.encryption_algorithms_client_to_server = cipher_c2s;
    algos.named.encryption_algorithms_server_to_client = cipher_s2c;
    algos.named.mac_algorithms_client_to_server = mac_c2s;
    algos.named.mac_algorithms_server_to_client = mac_s2c;
    algos.named.compression_algorithms_client_to_server = comp_c2s;
    algos.named.compression_algorithms_server_to_client = comp_s2c;

    SshAlgoEvent event(algos, PKT_FROM_CLIENT);

    CHECK(event.get_direction() == PKT_FROM_CLIENT);

    CHECK(event.get_kex_algorithms() == kex_algos);
    CHECK(event.get_server_host_key_algorithms() == host_key_algos);
    CHECK(event.get_encryption_algorithms_client_to_server() == cipher_c2s);
    CHECK(event.get_encryption_algorithms_server_to_client() == cipher_s2c);
    CHECK(event.get_mac_algorithms_client_to_server() == mac_c2s);
    CHECK(event.get_mac_algorithms_server_to_client() == mac_s2c);
    CHECK(event.get_compression_algorithms_client_to_server() == comp_c2s);
    CHECK(event.get_compression_algorithms_server_to_client() == comp_s2c);
}

TEST(pub_sub_ssh_events_test, ssh_state_change_event)
{
    Packet test_packet;
    const std::string version_str = "SSH-2.0-OpenSSH_8.0";
    
    SshEvent inbound_event(SSH_VERSION_STRING, SSH_NOT_FINISHED, version_str,
                          PKT_FROM_CLIENT, &test_packet, "inbound", SSH_VERSION_2);

    CHECK(inbound_event.get_event_type() == SSH_VERSION_STRING);
    CHECK(inbound_event.get_validation_result() == SSH_NOT_FINISHED);
    CHECK(inbound_event.get_version_str() == version_str);
    CHECK(inbound_event.get_direction() == PKT_FROM_CLIENT);
    CHECK(inbound_event.get_packet() == &test_packet);
    STRCMP_EQUAL("inbound", inbound_event.get_login_direction());
    CHECK(inbound_event.get_ssh_version() == SSH_VERSION_2);

    SshEvent outbound_event(SSH_VALIDATION, SSH_VALID_KEXINIT, version_str,
                           PKT_FROM_SERVER, &test_packet, "outbound", SSH_VERSION_1);

    CHECK(outbound_event.get_event_type() == SSH_VALIDATION);
    CHECK(outbound_event.get_validation_result() == SSH_VALID_KEXINIT);
    CHECK(outbound_event.get_direction() == PKT_FROM_SERVER);
    CHECK(outbound_event.get_packet() == &test_packet);
    STRCMP_EQUAL("outbound", outbound_event.get_login_direction());
    CHECK(outbound_event.get_ssh_version() == SSH_VERSION_1);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
