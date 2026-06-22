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

// ssh_kexinit_test.cc author Mykola Korniichuk <mkorniic@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <arpa/inet.h>

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "main/thread_config.h"
#include "protocols/packet.h"
#include "pub_sub/ssh_events.h"
#include "service_inspectors/ssh/ssh.h"
#include "service_inspectors/ssh/ssh_module.h"
#include "service_inspectors/ssh/ssh_splitter.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace
{
bool algo_event_seen = false;
uint8_t algo_direction = 0;
std::array<std::string, 8> captured_algos;
unsigned queued_gid = 0;
unsigned queued_sid = 0;
}

namespace snort
{
unsigned FlowData::flow_data_id = 0;

unsigned FlowData::create_flow_data_id()
{ return ++flow_data_id; }

FlowData::FlowData(unsigned u) : id(u) {}
FlowData::~FlowData() = default;

FlowDataStore::~FlowDataStore() = default;
FlowData* FlowDataStore::get(unsigned) const { return nullptr; }
void FlowDataStore::set(FlowData*) {}

Flow::~Flow() = default;

Packet::Packet(bool)
    : flow(nullptr), packet_flags(0), xtradata_mask(0), proto_bits(0), alt_dsize(0), num_layers(0),
    ip_proto_next(IpProtocol::PROTO_NOT_SET), disable_inspect(true), sect(PS_NONE), active_inst(nullptr), pkth(nullptr),
    pkt(nullptr), layers(nullptr), user_inspection_policy_id(0), user_ips_policy_id(0), user_network_policy_id(0),
    inspection_started_timestamp(0), vlan_idx(0), vlan_idx_outer(0), ts_packet_flags(0), allocated(false), daq_msg(nullptr)
{ }

Packet::~Packet() = default;
bool Packet::test_session_flags(uint32_t) { return false; }

Inspector::Inspector() : ref_count(0) {}
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

const StreamBuffer StreamSplitter::reassemble(Flow*, unsigned, unsigned, const uint8_t*, unsigned, uint32_t, unsigned&)
{
    StreamBuffer buf{nullptr, 0};
    return buf;
}

unsigned StreamSplitter::max(Flow*) { return 0; }

int DetectionEngine::queue_event(unsigned gid, unsigned sid)
{
    queued_gid = gid;
    queued_sid = sid;
    return 0;
}

unsigned DataBus::get_id(const PubKey&) { return 1; }

// cppcheck-suppress constParameterReference
void DataBus::publish(unsigned, unsigned event_id, DataEvent& event, Flow*)
{
    if (event_id != SshEventIds::ALGORITHM)
        return;

    const auto& algo = static_cast<const SshAlgoEvent&>(event);
    algo_event_seen = true;
    algo_direction = algo.get_direction();
    captured_algos[0] = algo.get_kex_algorithms();
    captured_algos[1] = algo.get_server_host_key_algorithms();
    captured_algos[2] = algo.get_encryption_algorithms_client_to_server();
    captured_algos[3] = algo.get_encryption_algorithms_server_to_client();
    captured_algos[4] = algo.get_mac_algorithms_client_to_server();
    captured_algos[5] = algo.get_mac_algorithms_server_to_client();
    captured_algos[6] = algo.get_compression_algorithms_client_to_server();
    captured_algos[7] = algo.get_compression_algorithms_server_to_client();
}

bool Stream::missed_packets(Flow*, uint8_t) { return false; }
void Stream::stop_inspection(Flow*, Packet*, char, int32_t, int) {}

void ConfigLogger::log_value(const char*, int, bool) {}

unsigned get_instance_id() { return 0; }

}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) {}
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) {}

unsigned ThreadConfig::get_instance_max() { return 1; }

#include "service_inspectors/ssh/ssh.cc"

namespace snort
{
THREAD_LOCAL bool TimeProfilerStats::enabled = false;
}

namespace
{
constexpr uint32_t DECLARED_NAME_LIST_LENGTH_EXCEEDS_PACKET = 0x1000;

std::vector<uint8_t> make_ssh2_kexinit_packet(uint32_t first_list_length = 0)
{
    std::vector<uint8_t> pkt(sizeof(SSH2KeyExchange) + (NUM_KEXINIT_LISTS * sizeof(uint32_t)) +
        sizeof(SSHKeyExchangeFinal), 0);

    auto* keyx = reinterpret_cast<SSH2KeyExchange*>(pkt.data());
    keyx->msg.len = htonl(static_cast<uint32_t>(pkt.size() - sizeof(uint32_t)));
    keyx->msg.plen = 0;
    keyx->msg.code = SSH_MSG_KEXINIT;

    uint8_t* p = pkt.data() + sizeof(SSH2KeyExchange);
    uint32_t n = htonl(first_list_length);
    memcpy(p, &n, sizeof(uint32_t));

    for (int i = 1; i < NUM_KEXINIT_LISTS; ++i)
    {
        p += sizeof(uint32_t);
        uint32_t z = 0;
        memcpy(p, &z, sizeof(uint32_t));
    }

    return pkt;
}

void reset_captured_state()
{
    algo_event_seen = false;
    algo_direction = 0;
    queued_gid = 0;
    queued_sid = 0;
    for (auto& s : captured_algos)
        s.clear();
}
}

TEST_GROUP(ssh_kexinit_test)
{
    Flow f;
    Packet p{true};

    void setup() override
    {
        reset_captured_state();
        // cppcheck-suppress unreadVariable
        p.flow = &f;
    }
};

TEST(ssh_kexinit_test, empty_kexinit_lists_publish_empty_strings)
{
    auto data = make_ssh2_kexinit_packet();
    p.data = data.data();
    p.dsize = static_cast<uint16_t>(data.size());

    SSHData session = {};

    CHECK_TRUE(process_ssh2_kexinit(&session, &p, SSH_DIR_FROM_CLIENT));
    CHECK_TRUE(session.state_flags & SSH_FLG_CLIENT_KEXINIT_SEEN);
    CHECK_TRUE(algo_event_seen);
    CHECK_EQUAL(PKT_FROM_CLIENT, algo_direction);

    for (const auto& s : captured_algos)
        STRCMP_EQUAL("", s.c_str());
}

TEST(ssh_kexinit_test, oversized_name_list_rejected_with_payload_size_event)
{
    auto data = make_ssh2_kexinit_packet(DECLARED_NAME_LIST_LENGTH_EXCEEDS_PACKET);
    p.data = data.data();
    p.dsize = static_cast<uint16_t>(data.size());

    SSHData session = {};

    CHECK_FALSE(process_ssh2_kexinit(&session, &p, SSH_DIR_FROM_SERVER));
    CHECK_FALSE(algo_event_seen);
    CHECK_EQUAL(static_cast<unsigned>(GID_SSH), queued_gid);
    CHECK_EQUAL(static_cast<unsigned>(SSH_EVENT_PAYLOAD_SIZE), queued_sid);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
