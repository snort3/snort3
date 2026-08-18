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
// encode_format_test.cc author Mykola Korniichuk <mkorniic@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>

#include "detection/detection_engine.h"
#include "flow/expect_flow.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "managers/codec_manager.h"
#include "packet_io/packet_tracer.h"
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_instance.h"
#include "profiler/time_profiler_defs.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "stream/stream.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//--------------------------------------------------------------------------
// Stubs
//--------------------------------------------------------------------------

THREAD_LOCAL const snort::Trace* decode_trace = nullptr;

CodecManager* CodecManager::get_instance() { return nullptr; }
THREAD_LOCAL ProtocolIndex CodecManager::grinder = 0;
THREAD_LOCAL ProtocolId CodecManager::grinder_id = ProtocolId::ETHERTYPE_NOT_SET;

void sum_stats(PegCount*, PegCount*, unsigned, bool) {}

int SFDAQInstance::inject(_daq_msg const*, int, unsigned char const*, unsigned int) { return -1; }
// cppcheck-suppress functionStatic
int SFDAQInstance::ioctl(DAQ_IoctlCmd, void*, size_t) { return DAQ_SUCCESS; }
// cppcheck-suppress functionStatic
bool SFDAQInstance::can_invoke_inject_drop() const { return false; }

namespace snort
{

THREAD_LOCAL bool TimeProfilerStats::enabled = false;

SfIpRet SfIp::set(const void* src, int fam)
{
    if (fam == AF_INET) memcpy(&ip8[12], src, 4);
    else if (fam == AF_INET6) memcpy(ip8, src, 16);
    family = fam;
    return SFIP_SUCCESS;
}
SfIpRet SfIp::set(const void* src) { memcpy(ip8, src, 16); family = AF_INET6; return SFIP_SUCCESS; }

void ip::IpApi::reset() { type = IAT_NONE; }
void ip::IpApi::set(const ip::IP4Hdr* h)
    { if (h) { type = IAT_4; iph = h; src.set(&h->ip_src, AF_INET); dst.set(&h->ip_dst, AF_INET); } }
void ip::IpApi::set(const ip::IP6Hdr* h)
    { if (h) { type = IAT_6; iph = h; src.set(h->get_src()); dst.set(h->get_dst()); } }
IpProtocol ip::IpApi::proto() const
{
    if (type == IAT_4) return ((const ip::IP4Hdr*)iph)->proto();
    if (type == IAT_6) return ((const ip::IP6Hdr*)iph)->next();
    return IpProtocol::PROTO_NOT_SET;
}
// cppcheck-suppress functionStatic
const uint8_t* ip::IpApi::ip_data() const { return nullptr; }

void ExpectFlow::reset_expect_flows() {}
void PacketTracer::log(const char*, ...) {}
void PacketTracer::log_msg_only(const char*, ...) {}

int DetectionEngine::queue_event(unsigned, unsigned) { return 0; }
Packet* DetectionEngine::get_encode_packet() { return nullptr; }

bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t*) { return false; }
uint8_t Stream::get_flow_ttl(Flow*, char, bool) { return 0; }

// cppcheck-suppress functionStatic
bool SnortConfig::tunnel_bypass_enabled(uint16_t) const { return false; }

bool TextLog_Print(TextLog*, const char*, ...) { return true; }
bool TextLog_Putc(TextLog*, char) { return true; }
bool TextLog_Write(TextLog*, const char*, int) { return true; }

void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}

Buffer::Buffer(uint8_t* buf, uint32_t sz) : base(buf), end(0), off(0), max_len(sz) {}
EncState::EncState(const ip::IpApi& api, EncodeFlags f, IpProtocol pr, uint8_t t, uint16_t ds)
    : ip_api(api), flags(f), dsize(ds), next_ethertype(ProtocolId::ETHERTYPE_NOT_SET),
      next_proto(pr), ttl(t) {}

uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) {}

} // namespace snort

//--------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------

TEST_GROUP(encode_format_tests) {};

TEST(encode_format_tests, def_flag_ipv4_no_ip_layer)
{
    Packet p;
    p.num_layers = 0;
    layer::set_packet_pointer(&p);

    Packet c;
    int ret = PacketManager::encode_format(
        ENC_FLAG_DEF | ENC_FLAG_FWD, &p, &c, PSEUDO_PKT_MAX, nullptr, 0);

    CHECK_EQUAL(-1, ret);
}

TEST(encode_format_tests, def_flag_ipv6_no_frag_layer_at_max_layers)
{
    static uint8_t ip6hdr[40] = { 0x60 };  // version=6, rest zero

    Packet p;
    p.ptrs.ip_api.set(reinterpret_cast<const ip::IP6Hdr*>(ip6hdr));
    p.ptrs.decode_flags = DECODE_FRAG;
    for (int i = 0; i < 40; i++)
        p.layers[i].prot_id = ProtocolId::ETHERTYPE_IPV4;  // no FRAGMENT
    p.num_layers = 40;
    layer::set_packet_pointer(&p);

    Packet c;
    int ret = PacketManager::encode_format(
        ENC_FLAG_DEF | ENC_FLAG_FWD, &p, &c, PSEUDO_PKT_MAX, nullptr, 0);

    CHECK_EQUAL(-1, ret);
}

TEST(encode_format_tests, def_flag_ipv6_not_a_fragment)
{
    static uint8_t ip6hdr[40] = { 0x60 };

    Packet p;
    p.ptrs.ip_api.set(reinterpret_cast<const ip::IP6Hdr*>(ip6hdr));
    p.ptrs.decode_flags = 0;
    p.layers[0].prot_id = ProtocolId::ETHERTYPE_IPV6;
    p.num_layers = 1;
    layer::set_packet_pointer(&p);

    Packet c;
    int ret = PacketManager::encode_format(
        ENC_FLAG_DEF | ENC_FLAG_FWD, &p, &c, PSEUDO_PKT_MAX, nullptr, 0);

    CHECK_EQUAL(-1, ret);
}

//--------------------------------------------------------------------------
// main
//--------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
