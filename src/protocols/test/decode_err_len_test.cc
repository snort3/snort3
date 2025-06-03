//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// decode_err_len_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "flow/expect_cache.h"
#include "flow/expect_flow.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "managers/codec_manager.h"
#include "packet_io/packet_tracer.h"
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_instance.h"
#include "profiler/profiler_defs.h"
#include "stream/stream.h"
#include "trace/trace_api.h"

#include "protocols/packet.h"
#include "protocols/packet_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;


//------------------------------
// Stubs
//------------------------------
bool snort::TextLog_Print(TextLog* const, const char*, ...) { return true; }
bool snort::TextLog_Write(TextLog* const, const char*, int) { return true; }
bool snort::TextLog_Putc(TextLog* const, char) { return true; }
void snort::trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }
void TraceApi::filter(const Packet&) {}
uint8_t TraceApi::get_constraints_generation() { return 0; }

void ExpectFlow::reset_expect_flows() {}
bool SnortConfig::tunnel_bypass_enabled(uint16_t) const { return false; }
const vlan::VlanTagHdr* layer::get_vlan_layer(const Packet*) { return nullptr; }
const geneve::GeneveLyr* layer::get_geneve_layer(const Packet*, bool) { return nullptr; }
void ip::IpApi::reset() {}
void PacketTracer::log_msg_only(const char*, ...) {}
void PacketTracer::log(const char*, ...) {}
int DetectionEngine::queue_event(unsigned, unsigned) { return 0; }
Packet* DetectionEngine::get_encode_packet() { return nullptr; }
void show_percent_stats(PegCount*, const char*[], unsigned, const char*) {}
void layer::set_packet_pointer(const Packet* const) {}
bool layer::set_inner_ip_api(const Packet* const, ip::IpApi&, int8_t&) { return true; }
int layer::get_inner_ip_lyr_index(const Packet* const) { return 0; }
int layer::get_inner_ip6_frag_index(const Packet* const) { return 0; }
uint8_t Stream::get_flow_ttl(Flow*, char, bool) { return 0; }
bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t*) { return false; }
int SFDAQInstance::inject(_daq_msg const*, int, unsigned char const*, unsigned int) { return -1; }
void sum_stats(PegCount*, PegCount*, unsigned, bool) {}
IpsContext::IpsContext(unsigned):
    packet(nullptr), encode_packet(nullptr), pkth (nullptr), buf(nullptr),
    stash(nullptr), otnx(nullptr), equeue(nullptr), context_num(0),
    active_rules(IpsContext::NONE), state(IpsContext::IDLE), check_tags(false), clear_inspectors(false),
    data(0), depends_on(nullptr), next_to_process(nullptr) { searches.context = nullptr; }
IpsContext::~IpsContext() {}
Buffer::Buffer(uint8_t*, uint32_t) :
    base(nullptr), end(0), max_len(0), off(0) {}
EncState::EncState(const ip::IpApi& api, EncodeFlags f, IpProtocol pr, uint8_t t, uint16_t data_size) :
    ip_api(api), flags(f), dsize(data_size), next_ethertype(ProtocolId::ETHERTYPE_NOT_SET),
    next_proto(pr), ttl(t) {}

THREAD_LOCAL bool TimeProfilerStats::enabled = false;
THREAD_LOCAL const Trace* decode_trace = nullptr;
std::array<uint8_t, num_protocol_ids> CodecManager::s_proto_map {
    { 0 }
};

THREAD_LOCAL ProtocolId CodecManager::grinder_id = ProtocolId::ETHERTYPE_NOT_SET;
THREAD_LOCAL uint8_t CodecManager::grinder = 0;

//-----------------------------
// Mocks
//-----------------------------
class MockCodec : public Codec
{
public:
    MockCodec() : Codec("mock_codec") { }

    bool decode(const RawData& raw, CodecData& codec_data, DecodeData&) override
    {
        codec_data.lyr_len = raw.len +1;
        codec_data.next_prot_id = ProtocolId::FINISHED_DECODE;
        return true;
    }
};

MockCodec mock_cd;
std::array<Codec*, UINT8_MAX> CodecManager::s_protocols { { &mock_cd } };

//-----------------------------
// Test
//-----------------------------

TEST_GROUP(decode_err_len_tests)
{
};

TEST(decode_err_len_tests, layer_len_more_than_raw)
{
    Packet p(false);
    p.context = new IpsContext();
    _daq_msg msg;
    memset(&msg, 0, sizeof(_daq_msg));
    p.daq_msg = &msg;
    PacketManager::decode(&p, nullptr, nullptr, 10, false);
    CHECK_TRUE((p.ptrs.decode_flags & DECODE_ERR_LEN) != 0);
    delete p.context;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
