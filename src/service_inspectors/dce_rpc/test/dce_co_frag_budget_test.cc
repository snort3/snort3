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

// dce_co_frag_budget_test.cc author Karthik Subramanian <ksubram6@cisco.com>

// Covers the DCE/TCP PAF-flush fragment reassembly budget (CSCwv76928) at
// boundaries that packet-level tests cannot isolate: exact cap/cap+1 behavior,
// reset versus persistent-latch lifetime, normal LAST and repeated-FIRST paths
// in both directions, buffer-full and append-error triggers, limit=0, and the
// SMB transport exclusion. Regression pcaps live under
// tests/src/service_inspectors/dce_rpc/reassembly_budget/.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../dce_co.h"
#include "../dce_smb.h"
#include "../dce_smb_module.h"
#include "../dce_tcp.h"

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"

#include "catch/catch.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

// --- test doubles: file-static observable state ---
namespace
{

constexpr uint16_t co_hdr_len = sizeof(DceRpcCoHdr);
constexpr uint16_t req_hdr_len = sizeof(DceRpcCoRequest);
constexpr uint16_t resp_hdr_len = sizeof(DceRpcCoResponse);

Packet test_packet;
Active test_active;
IpsContext test_context;
SnortConfig test_config;
IpsPolicy test_ips_policy;
DAQ_PktHdr_t test_pkth = {};
DceEndianness test_endianness;
Packet reassembled_packet;
DceEndianness reassembled_endianness;
std::array<uint8_t, Packet::max_dsize> reassembled_data = {};
Packet* pending_detect_packet = nullptr;
bool test_forwarding_packet = true;

unsigned budget_events = 0;
unsigned dce_detect_calls = 0;
unsigned engine_detect_calls = 0;
unsigned top_packet_detects = 0;
unsigned pseudo_packet_detects = 0;
unsigned reassembled_packet_requests = 0;
unsigned block_session_calls = 0;
Packet* blocked_packet = nullptr;
bool block_session_forced = false;
unsigned drop_reason_calls = 0;
std::string recorded_drop_reason;
uint32_t reassembled_stub_len = 0;
uint32_t reassembled_data_offset = 0;
bool reassembled_packet_contract_valid = true;
bool detect_target_contract_valid = true;
uint16_t rpkt_max_data = 65535;
unsigned buffer_add_calls = 0;
std::vector<unsigned> buffer_add_fail_calls;

void make_request_pdu(uint8_t* data, uint32_t call_id, uint16_t stub_len, uint8_t flags)
{
    auto* hdr = reinterpret_cast<DceRpcCoHdr*>(data);
    const uint16_t frag_length = co_hdr_len + req_hdr_len + stub_len;
    const uint16_t auth_length = 0;

    hdr->pversion.major = DCERPC_PROTO_MAJOR_VERS__5;
    hdr->pversion.minor = DCERPC_PROTO_MINOR_VERS__0;
    hdr->ptype = DCERPC_PDU_TYPE__REQUEST;
    hdr->pfc_flags = flags;
    hdr->packed_drep[0] = DCE2_LITTLE_ENDIAN;
    hdr->packed_drep[1] = 0;
    hdr->packed_drep[2] = 0;
    hdr->packed_drep[3] = 0;
    hdr->frag_length = DceRpcHtons(&frag_length, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    hdr->auth_length = DceRpcHtons(&auth_length, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    hdr->call_id = DceRpcHtonl(&call_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);

    auto* req = reinterpret_cast<DceRpcCoRequest*>(data + co_hdr_len);
    uint32_t alloc_hint = 0;
    uint16_t ctx_id = 0;
    uint16_t opnum = 0;
    req->alloc_hint = DceRpcHtonl(&alloc_hint, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    req->context_id = DceRpcHtons(&ctx_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    req->opnum = DceRpcHtons(&opnum, DCERPC_BO_FLAG__LITTLE_ENDIAN);

    memset(data + co_hdr_len + req_hdr_len, 'A', stub_len);
}

// Build a FIRST-only REQUEST PDU with stub_len bytes of stub data.
void make_first_request_pdu(uint8_t* data, uint32_t call_id, uint16_t stub_len)
{
    make_request_pdu(data, call_id, stub_len, DCERPC_CO_PFC_FLAGS__FIRST_FRAG);
}

void make_response_pdu(uint8_t* data, uint32_t call_id, uint16_t stub_len, uint8_t flags)
{
    auto* hdr = reinterpret_cast<DceRpcCoHdr*>(data);
    const uint16_t frag_length = co_hdr_len + resp_hdr_len + stub_len;
    const uint16_t auth_length = 0;

    hdr->pversion.major = DCERPC_PROTO_MAJOR_VERS__5;
    hdr->pversion.minor = DCERPC_PROTO_MINOR_VERS__0;
    hdr->ptype = DCERPC_PDU_TYPE__RESPONSE;
    hdr->pfc_flags = flags;
    hdr->packed_drep[0] = DCE2_LITTLE_ENDIAN;
    hdr->packed_drep[1] = 0;
    hdr->packed_drep[2] = 0;
    hdr->packed_drep[3] = 0;
    hdr->frag_length = DceRpcHtons(&frag_length, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    hdr->auth_length = DceRpcHtons(&auth_length, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    hdr->call_id = DceRpcHtonl(&call_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);

    auto* resp = reinterpret_cast<DceRpcCoResponse*>(data + co_hdr_len);
    uint32_t alloc_hint = 0;
    uint16_t ctx_id = 0;
    resp->alloc_hint = DceRpcHtonl(&alloc_hint, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    resp->context_id = DceRpcHtons(&ctx_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    resp->cancel_count = 0;
    resp->reserved = 0;

    memset(data + co_hdr_len + resp_hdr_len, 'A', stub_len);
}

void reset_state(const uint8_t* data, uint16_t dsize, uint32_t packet_direction = PKT_FROM_CLIENT,
    PolicyMode policy_mode = POLICY_MODE__INLINE, bool forwarding_packet = true)
{
    test_endianness.reset();
    reassembled_endianness.reset();
    test_ips_policy.policy_mode = policy_mode;
    test_context.conf = &test_config;
    test_pkth.flags = forwarding_packet ? 0 : DAQ_PKT_FLAG_NOT_FORWARDING;
    test_forwarding_packet = forwarding_packet;

    test_packet.data = nullptr;
    test_packet.pkt = nullptr;
    test_packet.pktlen = 0;
    test_packet.dsize = 0;
    test_packet.alt_dsize = 0;
    test_packet.packet_flags = 0;
    test_packet.flow = nullptr;
    test_packet.context = &test_context;
    test_packet.data = data;
    test_packet.pkt = data;
    test_packet.pkth = &test_pkth;
    test_packet.pktlen = dsize;
    test_packet.dsize = dsize;
    test_packet.packet_flags = packet_direction;
    test_packet.endianness = &test_endianness;
    test_packet.active = &test_active;
    test_packet.pseudo_type = PSEUDO_PKT_MAX;

    reassembled_packet.data = nullptr;
    reassembled_packet.pkt = nullptr;
    reassembled_packet.pktlen = 0;
    reassembled_packet.dsize = 0;
    reassembled_packet.alt_dsize = 0;
    reassembled_packet.packet_flags = 0;
    reassembled_packet.flow = nullptr;
    reassembled_packet.context = nullptr;
    reassembled_packet.pkth = nullptr;
    reassembled_packet.endianness = nullptr;
    reassembled_packet.active = nullptr;
    reassembled_packet.pseudo_type = PSEUDO_PKT_MAX;

    pending_detect_packet = nullptr;
    budget_events = 0;
    dce_detect_calls = 0;
    engine_detect_calls = 0;
    top_packet_detects = 0;
    pseudo_packet_detects = 0;
    reassembled_packet_requests = 0;
    block_session_calls = 0;
    blocked_packet = nullptr;
    block_session_forced = false;
    drop_reason_calls = 0;
    recorded_drop_reason.clear();
    reassembled_stub_len = 0;
    reassembled_data_offset = 0;
    reassembled_packet_contract_valid = true;
    detect_target_contract_valid = true;
    rpkt_max_data = 65535;
    buffer_add_calls = 0;
    buffer_add_fail_calls.clear();
}

void cleanup()
{
    pending_detect_packet = nullptr;
    test_packet.data = nullptr;
    test_packet.pkt = nullptr;
    test_packet.pktlen = 0;
    test_packet.dsize = 0;
    test_packet.endianness = nullptr;
    test_packet.active = nullptr;
    test_packet.context = nullptr;
    test_packet.pkth = nullptr;
    reassembled_packet.data = nullptr;
    reassembled_packet.pkt = nullptr;
    reassembled_packet.pktlen = 0;
    reassembled_packet.dsize = 0;
    reassembled_packet.endianness = nullptr;
    reassembled_packet.active = nullptr;
    recorded_drop_reason.clear();
}

// These tests drive DCE2_CoProcess directly and so never reach the flow
// teardown that normally frees the tracker. Reuse the production cleanup rather
// than hand-rolling one, so a buffer added to DCE2_CoTracker later cannot leak
// here without also leaking in dce_tcp.
void destroy_tracker(DCE2_CoTracker& cot)
{
    DCE2_CoCleanTracker(&cot);
}

} // namespace

// --- module stats ---
THREAD_LOCAL dce2TcpStats dce2_tcp_stats;
THREAD_LOCAL dce2SmbStats dce2_smb_stats;

// --- stubs ---

IpsPolicy::IpsPolicy(PolicyId id) :
    policy_id(id),
    enable_builtin_rules(false),
    var_id(0),
    var_table(nullptr),
    ip_vartable(nullptr),
    portVarTable(nullptr),
    nonamePortVarTable(nullptr),
    obfuscate_pii(false)
{ }

IpsPolicy::~IpsPolicy() = default;

namespace snort
{
IpsContext::IpsContext(unsigned) { }
IpsContext::~IpsContext() = default;

SnortConfig::SnortConfig(const char*) { }
SnortConfig::~SnortConfig() = default;

IpsPolicy* get_ips_policy()
{ return &test_ips_policy; }

Packet::Packet(bool) { }
Packet::~Packet() { }
// cppcheck-suppress functionStatic ; test double must retain the production member signature
void Packet::reset() { }

Packet* DetectionEngine::get_current_packet()
{ return &test_packet; }

// cppcheck-suppress constParameterPointer ; signature must match DetectionEngine::detect
bool DetectionEngine::detect(Packet* p, bool)
{
    ++engine_detect_calls;

    if (p == &test_packet)
        ++top_packet_detects;
    else if (p == &reassembled_packet)
        ++pseudo_packet_detects;
    else
        detect_target_contract_valid = false;

    return false;
}

int DetectionEngine::queue_event(unsigned gid, unsigned sid)
{
    if (gid == GID_DCE2 && sid == DCE2_CO_EXCESSIVE_FRAG_REASSEMBLIES)
        ++budget_events;
    return 0;
}

// cppcheck-suppress functionStatic ; test double must retain the production member signature
SfIpRet SfIp::set(const void*, int)
{ return SFIP_SUCCESS; }

// cppcheck-suppress functionStatic ; test double must retain the production member signature
void Active::block_session(Packet* p, bool force)
{
    ++block_session_calls;
    blocked_packet = p;
    block_session_forced = force;
}

// cppcheck-suppress functionStatic ; test double must retain the production member signature
void Active::set_drop_reason(const char* reason)
{
    ++drop_reason_calls;
    recorded_drop_reason = reason ? reason : "";
}

bool SFDAQ::forwarding_packet(const DAQ_PktHdr_t*)
{ return test_forwarding_packet; }
}

DceEndianness::DceEndianness() { reset(); }
void DceEndianness::reset()
{
    hdr_byte_order = DCE2_SENTINEL;
    data_byte_order = DCE2_SENTINEL;
    stub_data_offset = DCE2_SENTINEL;
}
bool DceEndianness::get_offset_endianness(int32_t, uint8_t&)
{ return false; }

void DCE2_SmbInitRdata(uint8_t*, int);

void DCE2_Detect(DCE2_SsnData* sd)
{
    ++dce_detect_calls;
    Packet* detect_packet = pending_detect_packet ? pending_detect_packet : &test_packet;

    if (detect_packet == &reassembled_packet)
    {
        const uint32_t expected_size = reassembled_data_offset + reassembled_stub_len;

        reassembled_packet_contract_valid = reassembled_packet_contract_valid && sd &&
            (detect_packet != &test_packet) &&
            (detect_packet->data == reassembled_data.data()) &&
            (detect_packet->dsize == expected_size) &&
            ((detect_packet->packet_flags & PKT_PSEUDO) != 0) &&
            (detect_packet->pseudo_type == PSEUDO_PKT_DCE_FRAG) &&
            (detect_packet->endianness == &reassembled_endianness) &&
            (reassembled_endianness.stub_data_offset ==
                static_cast<int32_t>(reassembled_data_offset)) &&
            (sd->ropts.stub_data == detect_packet->data + reassembled_data_offset) &&
            (reassembled_stub_len > 0) &&
            (detect_packet->data[reassembled_data_offset] == 'A');

        pending_detect_packet = nullptr;
    }

    DetectionEngine::detect(detect_packet);
}

Packet* DCE2_GetRpkt(Packet* parent, DCE2_RpktType type, const uint8_t* data, uint32_t data_len)
{
    ++reassembled_packet_requests;

    const bool from_client = parent && parent->is_from_client();
    uint32_t smb_offset = 0;
    uint32_t co_offset = 0;

    if (type == DCE2_RPKT_TYPE__TCP_CO_FRAG)
        co_offset = from_client ? DCE2_MOCK_HDR_LEN__CO_CLI : DCE2_MOCK_HDR_LEN__CO_SRV;
    else if (type == DCE2_RPKT_TYPE__SMB_CO_FRAG)
    {
        smb_offset = from_client ? DCE2_MOCK_HDR_LEN__SMB_CLI : DCE2_MOCK_HDR_LEN__SMB_SRV;
        co_offset = from_client ? DCE2_MOCK_HDR_LEN__CO_CLI : DCE2_MOCK_HDR_LEN__CO_SRV;
    }

    const uint32_t data_offset = smb_offset + co_offset;
    const bool valid_request = (parent == &test_packet) &&
        (co_offset > 0) && data && (data_len > 0) &&
        (data_len <= Packet::max_dsize - data_offset) && !pending_detect_packet;

    if (!valid_request)
    {
        reassembled_packet_contract_valid = false;
        return nullptr;
    }

    memset(reassembled_data.data(), 0, data_offset);
    const int direction = from_client ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
    if (smb_offset > 0)
        DCE2_SmbInitRdata(reassembled_data.data(), direction);
    DCE2_CoInitRdata(reassembled_data.data() + smb_offset, direction);
    memcpy(reassembled_data.data() + data_offset, data, data_len);

    reassembled_endianness.reset();
    reassembled_packet.data = reassembled_data.data();
    reassembled_packet.pkt = reassembled_data.data();
    reassembled_packet.pkth = parent->pkth;
    reassembled_packet.pktlen = data_offset + data_len;
    reassembled_packet.dsize = static_cast<uint16_t>(data_offset + data_len);
    reassembled_packet.alt_dsize = 0;
    reassembled_packet.packet_flags = parent->packet_flags | PKT_PSEUDO;
    reassembled_packet.flow = parent->flow;
    reassembled_packet.context = parent->context;
    reassembled_packet.endianness = &reassembled_endianness;
    reassembled_packet.active = parent->active;
    reassembled_packet.pseudo_type = PSEUDO_PKT_DCE_FRAG;

    reassembled_stub_len = data_len;
    reassembled_data_offset = data_offset;
    pending_detect_packet = &reassembled_packet;
    return &reassembled_packet;
}

uint16_t DCE2_GetRpktMaxData(DCE2_RpktType)
{ return rpkt_max_data; }

DCE2_Ret DCE2_AddDataToRpkt(Packet*, const uint8_t*, uint32_t)
{ return DCE2_RET__ERROR; }

void DCE2_SmbInitRdata(uint8_t*, int) { }

// Working buffer stubs so the fragment path can seed and check the buffer.
DCE2_Buffer* DCE2_BufferNew(uint32_t size, uint32_t min_add)
{
    auto* buf = static_cast<DCE2_Buffer*>(calloc(1, sizeof(DCE2_Buffer)));
    if (!buf)
        return nullptr;
    if (size > 0)
    {
        buf->data = static_cast<uint8_t*>(calloc(1, size));
        if (!buf->data)
        {
            free(buf);
            return nullptr;
        }
    }
    buf->size = size;
    buf->min_add_size = min_add;
    return buf;
}

DCE2_Ret DCE2_BufferAddData(DCE2_Buffer* buf, const uint8_t* data,
    uint32_t len, uint32_t offset, DCE2_BufferMinAddFlag)
{
    ++buffer_add_calls;
    for (unsigned fail_call : buffer_add_fail_calls)
    {
        if (buffer_add_calls == fail_call)
            return DCE2_RET__ERROR;
    }

    if (!buf || !buf->data)
        return DCE2_RET__ERROR;
    uint32_t end = offset + len;
    if (end > buf->size)
    {
        uint32_t new_size = end + buf->min_add_size;
        auto* p = static_cast<uint8_t*>(realloc(buf->data, new_size));
        if (!p)
            return DCE2_RET__ERROR;
        buf->data = p;
        buf->size = new_size;
    }
    memmove(buf->data + offset, data, len);
    if (end > buf->len)
        buf->len = end;
    return DCE2_RET__SUCCESS;
}

void DCE2_BufferDestroy(DCE2_Buffer* buf)
{
    if (buf)
    {
        free(buf->data);
        free(buf);
    }
}

// Queue stubs — pending_ctx_ids must appear non-empty so REQUESTs proceed.
static DCE2_Queue test_queue;

DCE2_Queue* DCE2_QueueNew(DCE2_QueueDataFree)
{
    memset(&test_queue, 0, sizeof(test_queue));
    test_queue.num_nodes = 1;
    return &test_queue;
}

DCE2_Ret DCE2_QueueEnqueue(DCE2_Queue*, void*)
{ return DCE2_RET__SUCCESS; }

void* DCE2_QueueDequeue(DCE2_Queue*)
{ return nullptr; }

void DCE2_QueueEmpty(DCE2_Queue*) { }
void* DCE2_QueueFirst(DCE2_Queue*) { return nullptr; }
void* DCE2_QueueNext(DCE2_Queue*) { return nullptr; }
void DCE2_QueueDestroy(DCE2_Queue*) { }

void set_smb_reassembled_data(uint8_t*, uint16_t) { }
// The tests exercise SMB1 geometry only; return the SMB1-sized region.
unsigned get_smb_cli_mock_hdr_len()
{ return (unsigned)(sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq)); }

void DceExpSsnManager::create_expected_session(const SfIp*, uint16_t, const char*) { }

// --- test cases ---

// cppcheck-suppress [syntaxError, unmatchedSuppression] ; Catch2 TEST_CASE is configuration-dependent
TEST_CASE("fragment reassembly budget fires at the configured limit", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    // 70 PDUs in one flush: the first seeds the buffer, the next 50 consume the
    // budget, and the following attempt trips the latch before reassembly.
    constexpr unsigned n_pdus = 70;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    for (unsigned i = 0; i < n_pdus; ++i)
        make_first_request_pdu(data.data() + i * pdu_size, i + 1, stub_len);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    // max_frag_reassemblies uses the in-class default.

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    REQUIRE(cot.frag_budget_tripped == false);

    reset_state(data.data(), static_cast<uint16_t>(data.size()));
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    // Exactly the configured number of reassemblies are allowed; the next
    // attempt alerts and blocks without building another pseudo packet.
    CHECK(cot.frag_reassembled == config.max_frag_reassemblies);
    CHECK(reassembled_packet_requests == config.max_frag_reassemblies);
    CHECK(pseudo_packet_detects == config.max_frag_reassemblies);
    CHECK(dce_detect_calls == config.max_frag_reassemblies + 1U);
    CHECK(engine_detect_calls == config.max_frag_reassemblies + 1U);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 1);
    CHECK(top_packet_detects == 1);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);

    // Budget fires exactly once (SID 133:66).
    CHECK(budget_events == 1);

    // Latch prevents further reassemblies.
    CHECK(cot.frag_budget_tripped == true);
    CHECK(block_session_calls == 1);
    CHECK(blocked_packet == &test_packet);
    CHECK(block_session_forced == true);
    CHECK(drop_reason_calls == 1);
    CHECK(recorded_drop_reason == "dce_tcp");

    // The latch is flow-scoped, unlike the counter. A later flush on the same
    // tracker must not reassemble or emit the event/action a second time.
    constexpr unsigned followup_pdus = 3;
    std::vector<uint8_t> followup(pdu_size * followup_pdus, 0);
    for (unsigned i = 0; i < followup_pdus; ++i)
        make_first_request_pdu(followup.data() + i * pdu_size, n_pdus + i + 1, stub_len);

    const auto requests_before = dce2_tcp_stats.co_request;
    const auto fragments_before = dce2_tcp_stats.co_req_fragments;
    const auto reassemblies_before = dce2_tcp_stats.co_cli_frag_reassembled;
    reset_state(followup.data(), static_cast<uint16_t>(followup.size()));
    DCE2_CoProcess(&sd, &cot, followup.data(), static_cast<uint16_t>(followup.size()));

    CHECK(dce2_tcp_stats.co_request - requests_before == followup_pdus);
    CHECK(dce2_tcp_stats.co_req_fragments - fragments_before == followup_pdus);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled - reassemblies_before == 0);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 1);
    CHECK(cot.frag_reassembled == 0);
    CHECK(reassembled_packet_requests == 0);
    CHECK(pseudo_packet_detects == 0);
    CHECK(top_packet_detects == 1);
    CHECK(dce_detect_calls == 1);
    CHECK(engine_detect_calls == 1);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 0);
    CHECK(block_session_calls == 0);
    CHECK(drop_reason_calls == 0);
    CHECK(cot.frag_budget_tripped == true);

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("passive budget trips do not latch the flow", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    constexpr unsigned n_pdus = 5;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    for (unsigned i = 0; i < n_pdus; ++i)
        make_first_request_pdu(data.data() + i * pdu_size, i + 1, stub_len);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    config.max_frag_reassemblies = 2;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    reset_state(data.data(), static_cast<uint16_t>(data.size()), PKT_FROM_CLIENT,
        POLICY_MODE__PASSIVE, false);
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    CHECK(cot.frag_reassembled == config.max_frag_reassemblies);
    CHECK(reassembled_packet_requests == config.max_frag_reassemblies);
    CHECK(pseudo_packet_detects == config.max_frag_reassemblies);
    CHECK(dce_detect_calls == config.max_frag_reassemblies + 1U);
    CHECK(engine_detect_calls == config.max_frag_reassemblies + 1U);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 0);
    CHECK(top_packet_detects == 1);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);

    // The first PDU seeds, two reassemble, and the remaining two exceed budget.
    CHECK(budget_events == 2);
    CHECK(cot.frag_budget_tripped == false);
    CHECK(block_session_calls == 0);
    CHECK(drop_reason_calls == 0);

    constexpr unsigned followup_pdus = 2;
    std::vector<uint8_t> followup(pdu_size * followup_pdus, 0);
    for (unsigned i = 0; i < followup_pdus; ++i)
        make_first_request_pdu(followup.data() + i * pdu_size, n_pdus + i + 1, stub_len);

    const auto requests_before = dce2_tcp_stats.co_request;
    const auto fragments_before = dce2_tcp_stats.co_req_fragments;
    const auto reassemblies_before = dce2_tcp_stats.co_cli_frag_reassembled;
    reset_state(followup.data(), static_cast<uint16_t>(followup.size()), PKT_FROM_CLIENT,
        POLICY_MODE__PASSIVE, false);
    DCE2_CoProcess(&sd, &cot, followup.data(), static_cast<uint16_t>(followup.size()));

    CHECK(dce2_tcp_stats.co_request - requests_before == followup_pdus);
    CHECK(dce2_tcp_stats.co_req_fragments - fragments_before == followup_pdus);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled - reassemblies_before == followup_pdus);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 0);
    CHECK(cot.frag_reassembled == followup_pdus);
    CHECK(reassembled_packet_requests == followup_pdus);
    CHECK(pseudo_packet_detects == followup_pdus);
    CHECK(top_packet_detects == 0);
    CHECK(dce_detect_calls == followup_pdus);
    CHECK(engine_detect_calls == followup_pdus);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 0);
    CHECK(cot.frag_budget_tripped == false);
    CHECK(block_session_calls == 0);
    CHECK(drop_reason_calls == 0);

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("budget is per flush and does not accumulate across flushes", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    // Under the cap on every flush, so no flush may trip regardless of how
    // many flushes the flow lives for. This is the long-lived-flow case: a
    // per-session counter would trip on the third flush here.
    constexpr unsigned n_pdus = 40;
    constexpr unsigned n_flushes = 10;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    for (unsigned i = 0; i < n_pdus; ++i)
        make_first_request_pdu(data.data() + i * pdu_size, i + 1, stub_len);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    for (unsigned f = 0; f < n_flushes; ++f)
    {
        const auto reassemblies_before = dce2_tcp_stats.co_cli_frag_reassembled;
        reset_state(data.data(), static_cast<uint16_t>(data.size()));
        DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

        // The first flush seeds an empty fragment buffer. Later flushes begin
        // with the fragment retained by the preceding flush.
        const unsigned expected_reassemblies = (f == 0) ? n_pdus - 1 : n_pdus;
        CHECK(cot.frag_reassembled == expected_reassemblies);
        CHECK(reassembled_packet_requests == expected_reassemblies);
        CHECK(pseudo_packet_detects == expected_reassemblies);
        CHECK(top_packet_detects == ((f == 0) ? 1 : 0));
        CHECK(dce_detect_calls == n_pdus);
        CHECK(engine_detect_calls == n_pdus);
        CHECK(dce2_tcp_stats.co_cli_frag_reassembled - reassemblies_before ==
            expected_reassemblies);
        CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 0);
        CHECK(reassembled_packet_contract_valid == true);
        CHECK(detect_target_contract_valid == true);
        CHECK(pending_detect_packet == nullptr);
        CHECK(budget_events == 0);
        CHECK(block_session_calls == 0);
        CHECK(drop_reason_calls == 0);
        CHECK(cot.frag_budget_tripped == false);
    }

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("budget disabled when max_frag_reassemblies is zero", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    constexpr unsigned n_pdus = 70;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    for (unsigned i = 0; i < n_pdus; ++i)
        make_first_request_pdu(data.data() + i * pdu_size, i + 1, stub_len);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    config.max_frag_reassemblies = 0;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    reset_state(data.data(), static_cast<uint16_t>(data.size()));
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    // limit=0 skips the budget check entirely.
    CHECK(cot.frag_reassembled == n_pdus - 1);
    CHECK(reassembled_packet_requests == n_pdus - 1);
    CHECK(pseudo_packet_detects == n_pdus - 1);
    CHECK(dce_detect_calls == n_pdus);
    CHECK(engine_detect_calls == n_pdus);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == n_pdus - 1);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 0);
    CHECK(top_packet_detects == 1);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 0);
    CHECK(cot.frag_budget_tripped == false);
    CHECK(block_session_calls == 0);
    CHECK(drop_reason_calls == 0);

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("normal LAST reassemblies honor a custom fragment budget", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    constexpr unsigned n_pdus = 4;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    make_request_pdu(data.data(), 1, stub_len, DCERPC_CO_PFC_FLAGS__FIRST_FRAG);
    make_request_pdu(data.data() + pdu_size, 1, stub_len, DCERPC_CO_PFC_FLAGS__LAST_FRAG);
    make_request_pdu(data.data() + 2 * pdu_size, 2, stub_len,
        DCERPC_CO_PFC_FLAGS__FIRST_FRAG);
    make_request_pdu(data.data() + 3 * pdu_size, 2, stub_len,
        DCERPC_CO_PFC_FLAGS__LAST_FRAG);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    config.max_frag_reassemblies = 1;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    reset_state(data.data(), static_cast<uint16_t>(data.size()));
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    CHECK(dce2_tcp_stats.co_request == n_pdus);
    CHECK(dce2_tcp_stats.co_req_fragments == n_pdus);
    CHECK(cot.frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 1);
    CHECK(reassembled_packet_requests == config.max_frag_reassemblies);
    CHECK(reassembled_stub_len == 2);
    CHECK(pseudo_packet_detects == config.max_frag_reassemblies);
    CHECK(top_packet_detects == 1);
    CHECK(dce_detect_calls == 2);
    CHECK(engine_detect_calls == 2);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 1);
    CHECK(cot.frag_budget_tripped == true);
    CHECK(block_session_calls == 1);
    CHECK(blocked_packet == &test_packet);
    CHECK(block_session_forced == true);
    CHECK(drop_reason_calls == 1);
    CHECK(recorded_drop_reason == "dce_tcp");

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("server fragment restarts honor the fragment budget", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + resp_hdr_len + stub_len;
    constexpr unsigned n_pdus = 4;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    for (unsigned i = 0; i < n_pdus; ++i)
    {
        make_response_pdu(data.data() + i * pdu_size, i + 1, stub_len,
            DCERPC_CO_PFC_FLAGS__FIRST_FRAG);
    }

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    config.max_frag_reassemblies = 2;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);

    reset_state(data.data(), static_cast<uint16_t>(data.size()), PKT_FROM_SERVER);
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    CHECK(dce2_tcp_stats.co_response == n_pdus);
    CHECK(dce2_tcp_stats.co_resp_fragments == n_pdus);
    CHECK(cot.frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.co_srv_frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == 0);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 1);
    CHECK(reassembled_packet_requests == config.max_frag_reassemblies);
    CHECK(pseudo_packet_detects == config.max_frag_reassemblies);
    CHECK(top_packet_detects == 1);
    CHECK(dce_detect_calls == 3);
    CHECK(engine_detect_calls == 3);
    CHECK(reassembled_data_offset == DCE2_MOCK_HDR_LEN__CO_SRV);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 1);
    CHECK(cot.frag_budget_tripped == true);
    CHECK(block_session_calls == 1);
    CHECK(blocked_packet == &test_packet);
    CHECK(block_session_forced == true);
    CHECK(drop_reason_calls == 1);
    CHECK(recorded_drop_reason == "dce_tcp");

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("full fragment-buffer flushes honor the fragment budget", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    constexpr unsigned n_pdus = 6;
    constexpr uint16_t buffer_limit = 3;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    constexpr uint8_t flags[n_pdus] =
    {
        DCERPC_CO_PFC_FLAGS__FIRST_FRAG, 0, 0,
        DCERPC_CO_PFC_FLAGS__FIRST_FRAG, 0, 0
    };
    for (unsigned i = 0; i < n_pdus; ++i)
        make_request_pdu(data.data() + i * pdu_size, 1, stub_len, flags[i]);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    config.max_frag_reassemblies = 1;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    reset_state(data.data(), static_cast<uint16_t>(data.size()));
    rpkt_max_data = buffer_limit;
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    CHECK(buffer_add_calls == n_pdus);
    CHECK(dce2_tcp_stats.co_request == n_pdus);
    CHECK(dce2_tcp_stats.co_req_fragments == n_pdus);
    CHECK(cot.frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 1);
    CHECK(reassembled_packet_requests == config.max_frag_reassemblies);
    CHECK(reassembled_stub_len == buffer_limit);
    CHECK(pseudo_packet_detects == config.max_frag_reassemblies);
    CHECK(top_packet_detects == 1);
    CHECK(dce_detect_calls == 2);
    CHECK(engine_detect_calls == 2);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 1);
    CHECK(cot.frag_budget_tripped == true);
    CHECK(block_session_calls == 1);
    CHECK(blocked_packet == &test_packet);
    CHECK(block_session_forced == true);
    CHECK(drop_reason_calls == 1);
    CHECK(recorded_drop_reason == "dce_tcp");

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("fragment append failures honor the fragment budget", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    constexpr unsigned n_pdus = 4;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    make_request_pdu(data.data(), 1, stub_len, DCERPC_CO_PFC_FLAGS__FIRST_FRAG);
    make_request_pdu(data.data() + pdu_size, 1, stub_len, 0);
    make_request_pdu(data.data() + 2 * pdu_size, 2, stub_len,
        DCERPC_CO_PFC_FLAGS__FIRST_FRAG);
    make_request_pdu(data.data() + 3 * pdu_size, 2, stub_len, 0);

    dce2TcpProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;
    config.max_frag_reassemblies = 1;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__TCP;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);

    reset_state(data.data(), static_cast<uint16_t>(data.size()));
    buffer_add_fail_calls = { 2, 4 };
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    CHECK(buffer_add_calls == n_pdus);
    CHECK(dce2_tcp_stats.co_request == n_pdus);
    CHECK(dce2_tcp_stats.co_req_fragments == n_pdus);
    CHECK(cot.frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == config.max_frag_reassemblies);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 1);
    CHECK(reassembled_packet_requests == config.max_frag_reassemblies);
    CHECK(reassembled_stub_len == stub_len);
    CHECK(pseudo_packet_detects == config.max_frag_reassemblies);
    CHECK(top_packet_detects == 1);
    CHECK(dce_detect_calls == 2);
    CHECK(engine_detect_calls == 2);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 1);
    CHECK(cot.frag_budget_tripped == true);
    CHECK(block_session_calls == 1);
    CHECK(blocked_packet == &test_packet);
    CHECK(block_session_forced == true);
    CHECK(drop_reason_calls == 1);
    CHECK(recorded_drop_reason == "dce_tcp");

    destroy_tracker(cot);
    cleanup();
}

TEST_CASE("TCP fragment budget state does not suppress SMB reassembly", "[dce_co]")
{
    constexpr uint16_t stub_len = 1;
    constexpr uint16_t pdu_size = co_hdr_len + req_hdr_len + stub_len;
    constexpr unsigned n_pdus = 2;

    std::vector<uint8_t> data(pdu_size * n_pdus, 0);
    for (unsigned i = 0; i < n_pdus; ++i)
        make_first_request_pdu(data.data() + i * pdu_size, i + 1, stub_len);

    dce2SmbProtoConf config = {};
    config.common.common.disable_defrag = false;
    config.common.common.max_frag_len = DCE2_SENTINEL;

    DCE2_SsnData sd = {};
    sd.trans = DCE2_TRANS_TYPE__SMB;
    sd.server_policy = DCE2_POLICY__WINXP;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = &config;

    dce2_smb_stats = {};
    memset(&dce2_tcp_stats, 0, sizeof(dce2_tcp_stats));

    DCE2_CoTracker cot;
    DCE2_CoInitTracker(&cot);
    cot.pending_ctx_ids = DCE2_QueueNew(nullptr);
    cot.frag_budget_tripped = true;

    reset_state(data.data(), static_cast<uint16_t>(data.size()));
    DCE2_CoProcess(&sd, &cot, data.data(), static_cast<uint16_t>(data.size()));

    CHECK(dce2_smb_stats.co_request == n_pdus);
    CHECK(dce2_smb_stats.co_req_fragments == n_pdus);
    CHECK(dce2_smb_stats.co_cli_frag_reassembled == 1);
    CHECK(dce2_tcp_stats.co_cli_frag_reassembled == 0);
    CHECK(dce2_tcp_stats.tcp_frag_budget_blocks == 0);
    CHECK(cot.frag_reassembled == 0);
    CHECK(reassembled_packet_requests == 1);
    CHECK(reassembled_data_offset ==
        DCE2_MOCK_HDR_LEN__SMB_CLI + DCE2_MOCK_HDR_LEN__CO_CLI);
    CHECK(pseudo_packet_detects == 1);
    CHECK(top_packet_detects == 1);
    CHECK(dce_detect_calls == 2);
    CHECK(engine_detect_calls == 2);
    CHECK(reassembled_packet_contract_valid == true);
    CHECK(detect_target_contract_valid == true);
    CHECK(pending_detect_packet == nullptr);
    CHECK(budget_events == 0);
    CHECK(cot.frag_budget_tripped == true);
    CHECK(block_session_calls == 0);
    CHECK(drop_reason_calls == 0);

    destroy_tracker(cot);
    cleanup();
}
