//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../dce_co.h"
#include "../dce_smb.h"
#include "../dce_tcp.h"

#include "detection/detection_engine.h"
#include "main/policy.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"

#include "catch/catch.hpp"

#include <array>
#include <vector>

using namespace snort;

namespace
{
constexpr uint16_t co_hdr_len = sizeof(DceRpcCoHdr);
constexpr unsigned pdu_count = 4;

Packet test_packet;
DceEndianness test_endianness;
std::vector<uint16_t> detect_sizes;

void make_auth3_pdu(uint8_t* data, uint32_t call_id)
{
    auto* hdr = reinterpret_cast<DceRpcCoHdr*>(data);
    const uint16_t frag_length = co_hdr_len;
    const uint16_t auth_length = 0;

    hdr->pversion.major = DCERPC_PROTO_MAJOR_VERS__5;
    hdr->pversion.minor = DCERPC_PROTO_MINOR_VERS__0;
    hdr->ptype = DCERPC_PDU_TYPE__AUTH3;
    hdr->pfc_flags = DCERPC_CO_PFC_FLAGS__FIRST_FRAG | DCERPC_CO_PFC_FLAGS__LAST_FRAG;
    hdr->packed_drep[0] = DCE2_LITTLE_ENDIAN;
    hdr->packed_drep[1] = 0;
    hdr->packed_drep[2] = 0;
    hdr->packed_drep[3] = 0;
    hdr->frag_length = DceRpcHtons(&frag_length, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    hdr->auth_length = DceRpcHtons(&auth_length, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    hdr->call_id = DceRpcHtonl(&call_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);
}

void reset_packet(const uint8_t* data, uint16_t dsize)
{
    test_endianness.reset();
    test_packet.data = nullptr;
    test_packet.dsize = 0;
    test_packet.alt_dsize = 0;
    test_packet.packet_flags = 0;
    test_packet.flow = nullptr;
    test_packet.context = nullptr;
    test_packet.pseudo_type = PSEUDO_PKT_MAX;
    test_packet.data = data;
    test_packet.dsize = dsize;
    test_packet.packet_flags = PKT_FROM_CLIENT;
    test_packet.endianness = &test_endianness;
    detect_sizes.clear();
}

void cleanup_packet()
{
    test_packet.endianness = nullptr;
}
}

THREAD_LOCAL dce2TcpStats dce2_tcp_stats;
THREAD_LOCAL dce2SmbStats dce2_smb_stats;

namespace snort
{
Packet::Packet(bool)
{
}

Packet::~Packet()
{
}

void Packet::reset()
{
}

Packet* DetectionEngine::get_current_packet()
{
    return &test_packet;
}

bool DetectionEngine::detect(Packet* p, bool)
{
    detect_sizes.push_back(p->dsize);
    return false;
}

int DetectionEngine::queue_event(unsigned, unsigned)
{
    return 0;
}

SfIpRet SfIp::set(const void*, int)
{
    return SFIP_SUCCESS;
}

void Active::block_session(Packet*, bool) { }
void Active::set_drop_reason(const char*) { }
bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t*) { return false; }
IpsPolicy* get_ips_policy() { return nullptr; }
}

DceEndianness::DceEndianness()
{
    reset();
}

void DceEndianness::reset()
{
    hdr_byte_order = DCE2_SENTINEL;
    data_byte_order = DCE2_SENTINEL;
    stub_data_offset = DCE2_SENTINEL;
}

bool DceEndianness::get_offset_endianness(int32_t, uint8_t&)
{
    return false;
}

void DCE2_Detect(DCE2_SsnData*)
{
    DetectionEngine::detect(&test_packet);
}

Packet* DCE2_GetRpkt(Packet*, DCE2_RpktType, const uint8_t*, uint32_t)
{
    return nullptr;
}

uint16_t DCE2_GetRpktMaxData(DCE2_RpktType)
{
    return 0;
}

DCE2_Ret DCE2_AddDataToRpkt(Packet*, const uint8_t*, uint32_t)
{
    return DCE2_RET__ERROR;
}

void DCE2_SmbInitRdata(uint8_t*, int)
{
}

DCE2_Buffer* DCE2_BufferNew(uint32_t, uint32_t)
{
    return nullptr;
}

DCE2_Ret DCE2_BufferAddData(DCE2_Buffer*, const uint8_t*, uint32_t, uint32_t,
    DCE2_BufferMinAddFlag)
{
    return DCE2_RET__ERROR;
}

void DCE2_BufferDestroy(DCE2_Buffer*)
{
}

DCE2_Queue* DCE2_QueueNew(DCE2_QueueDataFree)
{
    return nullptr;
}

DCE2_Ret DCE2_QueueEnqueue(DCE2_Queue*, void*)
{
    return DCE2_RET__ERROR;
}

void* DCE2_QueueDequeue(DCE2_Queue*)
{
    return nullptr;
}

void DCE2_QueueEmpty(DCE2_Queue*)
{
}

void* DCE2_QueueFirst(DCE2_Queue*)
{
    return nullptr;
}

void* DCE2_QueueNext(DCE2_Queue*)
{
    return nullptr;
}

void DCE2_QueueDestroy(DCE2_Queue*)
{
}

void set_smb_reassembled_data(uint8_t*, uint16_t)
{
}

void DceExpSsnManager::create_expected_session(const SfIp*, uint16_t, const char*)
{
}

TEST_CASE("DCE CO detects complete packed PDUs with PDU-sized packet view", "[dce_co]")
{
    std::array<uint8_t, co_hdr_len * pdu_count> data = {};

    for (unsigned i = 0; i < pdu_count; ++i)
        make_auth3_pdu(data.data() + (i * co_hdr_len), i + 1);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = true;
    config.common.common.max_frag_len = DCE2_SENTINEL;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    reset_packet(data.data(), data.size());

    DCE2_CoProcess(&sd, &cot, data.data(), data.size());

    REQUIRE(detect_sizes.size() == pdu_count);
    for (auto dsize : detect_sizes)
        CHECK(dsize == co_hdr_len);

    cleanup_packet();
}
