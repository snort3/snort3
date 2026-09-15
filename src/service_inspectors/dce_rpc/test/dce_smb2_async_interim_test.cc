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

// dce_smb2_async_interim_test.cc author Steve Chew <stechew@cisco.com>

// Every StructureSize-9 body is ambiguous: 9 is the ERROR Response body, the TREE_CONNECT
// Request body and the SESSION_SETUP Response body.  Each handler resolves the ambiguity by
// asking Smb2Error() whether the header belongs to an error response, so that one predicate
// has to be right about three separate header shapes:
//
//   - an async interim response (SMB2_FLAGS_SERVER_TO_REDIR + SMB2_FLAGS_ASYNC_COMMAND +
//     STATUS_PENDING), which carries no parsable body and must be dropped.  STATUS_PENDING
//     has severity SUCCESS, so a severity-only test does not classify it as an error and it
//     falls through to whichever branch StructureSize 9 happens to hit -- a different wrong
//     answer per command, and for CLOSE a destructive one.
//   - an SMB 3.x request, whose header reuses the low half of the Status field for
//     ChannelSequence (MS-SMB2 3.2.4.1.6).  A bare "status != 0" test misfires on those.
//   - a genuine error response, which must still be counted.  The final response to an async
//     request keeps SMB2_FLAGS_ASYNC_COMMAND set and carries the real status, so a guard that
//     keys on the async flag alone would swallow real errors.
//
// The handlers are exercised directly rather than through a pcap because one crafted header
// has to reach eight commands, including SESSION_SETUP and CLOSE, which no capture in the
// suite hits with an interim response.  The companion pcap test asserts on the emitted trace
// line, which a unit test cannot do: SMB_DEBUG short-circuits on a null Trace.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../dce_smb2.h"
#include "../dce_smb2_commands.h"
#include "../dce_smb2_utils.h"

#include "detection/detection_engine.h"
#include "file_api/file_flows.h"
#include "file_api/file_lib.h"
#include "file_api/file_service.h"
#include "flow/flow.h"
#include "hash/hash_key_operations.h"
#include "utils/util.h"

#include "catch/catch.hpp"

#include <cstdarg>
#include <cstring>
#include <string>

using namespace snort;

namespace
{
FlowKey test_key {};
Flow test_flow;
Packet test_packet;

constexpr uint64_t test_sid = 0x1122334455667788ULL;
constexpr uint32_t test_tid = 0x99;
constexpr uint64_t test_mid = 42;
constexpr uint64_t test_file_id = 0xdeadbeefULL;

// MS-SMB2 2.2.1.2 SMB2_FLAGS_SERVER_TO_REDIR, set on every response.  Spelled out here
// rather than taken from dce_smb2.h so that this file builds unchanged against a tree that
// does not define it yet, which is what makes the before/after comparison meaningful.
constexpr uint32_t flags_response = 0x00000001;
constexpr uint32_t flags_async_response = flags_response | SMB2_FLAGS_ASYNC_COMMAND;

// A status severity of ERROR, i.e. what the code is meant to react to.
constexpr uint32_t SMB2_STATUS_ACCESS_DENIED = 0xC0000022;

// Severity ERROR, but a legitimate intermediate step rather than a failure: the second leg
// of NTLM authentication (MS-SMB2 3.3.5.5) carries it on a normal SESSION_SETUP Response.
constexpr uint32_t SMB2_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;

// MS-SMB2 3.2.4.1.6: an SMB 3.x request puts ChannelSequence in the low half of the field
// the response uses for Status.  This is the value observed in config_reload's capture.
constexpr uint32_t test_channel_sequence = 0x4177;

void store_le16(uint8_t* p, uint16_t v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

void store_le32(uint8_t* p, uint32_t v)
{
    for ( unsigned i = 0; i < 4; ++i )
        p[i] = (v >> (8 * i)) & 0xff;
}

void store_le64(uint8_t* p, uint64_t v)
{
    for ( unsigned i = 0; i < 8; ++i )
        p[i] = (v >> (8 * i)) & 0xff;
}

// A wire-format SMB2 header, built as bytes so the test does not depend on host endianness
// the way a struct assignment would.  Offsets are MS-SMB2 2.2.1.2; the ASYNC and SYNC
// layouts agree on every field this touches.
class Hdr
{
public:
    Hdr(uint16_t command, uint32_t status, uint32_t flags)
    {
        raw[0] = 0xFE;
        raw[1] = 'S';
        raw[2] = 'M';
        raw[3] = 'B';
        store_le16(raw + 4, SMB2_HEADER_LENGTH);
        store_le32(raw + 8, status);
        store_le16(raw + 12, command);
        store_le32(raw + 16, flags);
        store_le64(raw + 24, test_mid);
        store_le32(raw + 36, test_tid);
        store_le64(raw + 40, test_sid);
    }

    const Smb2Hdr* operator*() const
    { return reinterpret_cast<const Smb2Hdr*>(raw); }

private:
    uint8_t raw[SMB2_HEADER_LENGTH] { };
};

// A zero-filled command body that reports StructureSize N.  Every field beyond the size is
// zero, which each request parser reads as "nothing follows" -- CREATE, for instance, sees
// NameOffset 0 and returns without touching the name.
template<uint16_t N>
class Body
{
public:
    Body()
    { store_le16(raw, N); }

    const uint8_t* begin() const { return raw; }
    const uint8_t* end() const { return raw + sizeof(raw); }

private:
    uint8_t raw[N] { };
};

// MS-SMB2 2.2.2 ERROR Response: StructureSize 9, and also the exact size a TREE_CONNECT
// Request body and a SESSION_SETUP Response body report.
using Body9 = Body<SMB2_ERROR_RESPONSE_STRUC_SIZE>;
using BodyCreateRequest = Body<SMB2_CREATE_REQUEST_STRUC_SIZE>;

// One session with a single disk tree, plus the caches the handlers reach into.
class Fixture
{
public:
    Fixture()
    {
        dce2_smb_stats = { };
        test_key = { };
        test_flow.key = &test_key;
        test_packet.flow = &test_flow;
        DCE2_Smb2FtrackerLruInit();
        DCE2_SmbSessionCacheInit(1024 * 1024);
        ssd = new DCE2_Smb2SsnData();
        str = new DCE2_Smb2SessionTracker(test_sid);
        ttr = new DCE2_Smb2TreeTracker(test_tid, SMB2_SHARE_TYPE_DISK);
        str->insertTtracker(test_tid, ttr);
        ssd->flow = &test_flow;
    }

    // An open file with an outstanding request against it, i.e. the state a CLOSE is
    // supposed to tear down only once its final response arrives.
    void open_file()
    {
        ttr->insertFtracker(test_file_id,
            new DCE2_Smb2FileTracker(test_file_id, ttr, str, &test_flow));
        str->insertRtracker(ssd->flow_key, test_mid,
            new DCE2_Smb2RequestTracker(test_file_id));
    }

    bool file_still_open() const
    {
        return (ttr->findFtracker(test_file_id) != nullptr)
            and (str->findRtracker(ssd->flow_key, test_mid) != nullptr);
    }

    ~Fixture()
    {
        // ~str reads from the connection trackers, so it must die while ssd is still alive.
        delete str;
        delete ssd;
        delete smb2_session_cache;
        smb2_session_cache = nullptr;
        DCE2_Smb2FtrackerLruTerm();
    }

    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    DCE2_Smb2SsnData* ssd = nullptr;
    DCE2_Smb2SessionTracker* str = nullptr;
    DCE2_Smb2TreeTracker* ttr = nullptr;  // owned by str
};
}

THREAD_LOCAL dce2SmbStats dce2_smb_stats;
THREAD_LOCAL const snort::Trace* dce_smb_trace = nullptr;

namespace snort
{
Flow::Flow() = default;
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;
// cppcheck-suppress functionStatic ; test double must retain the production member signature
void FlowStash::reset() { }

Packet::Packet(bool)
{
}

Packet::~Packet()
{
}

// cppcheck-suppress functionStatic ; test double must retain the production member signature
void Packet::reset()
{
}

Packet* DetectionEngine::get_current_packet()
{
    return &test_packet;
}

int DetectionEngine::queue_event(unsigned, unsigned)
{
    return 0;
}

void DetectionEngine::disable_all(Packet*)
{
}

int64_t FileService::get_max_file_depth(FileConfig*)
{
    return 0;
}

FileFlows* FileFlows::get_file_flows(Flow*, bool)
{
    return nullptr;
}

// cppcheck-suppress functionStatic ; test double must retain the production member signature
FileContext* FileFlows::get_file_context(uint64_t, bool, bool&, uint64_t)
{
    return nullptr;
}

// cppcheck-suppress functionStatic ; test double must retain the production member signature
bool FileFlows::file_process(Packet*, uint64_t, const uint8_t*, int, uint64_t, FileDirection,
    uint64_t, FilePosition, const uint8_t*, uint32_t, const uint8_t*, uint32_t,
    const std::string&, const bool)
{
    return false;
}

// cppcheck-suppress functionStatic ; test double must retain the production member signature
void FileInfo::set_file_name(const char*, uint32_t) { }
// cppcheck-suppress functionStatic ; test double must retain the production member signature
void FileInfo::set_file_size(uint64_t) { }
// cppcheck-suppress functionStatic ; test double must retain the production member signature
uint64_t FileInfo::get_file_size() const { return 0; }

void DetectionEngine::set_file_data(const DataPointer&) { }

uint32_t str_to_hash(const uint8_t*, size_t) { return 0; }

void WarningMessage(const char*, ...) { }

uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }

void trace_vprintf(const char*, unsigned char, const char*, const Packet*, const char*, va_list) { }
}

void DCE2_CoCleanTracker(DCE2_CoTracker*)
{
}

void DCE2_CoConfigureTracker(DCE2_CoTracker*, uint32_t*, uint32_t)
{
}

void DCE2_CoInitTracker(DCE2_CoTracker*)
{
}

void DCE2_CoProcess(DCE2_SsnData*, DCE2_CoTracker*, const uint8_t*, uint16_t)
{
}

void DCE2_FileDetect()
{
}

char* DCE2_SmbGetFileName(const uint8_t*, uint32_t, bool, uint16_t* file_name_len)
{
    if ( file_name_len )
        *file_name_len = 0;
    return nullptr;
}

void dce_alert(uint32_t, uint32_t, dce2CommonStats*, const DCE2_SsnData&)
{
}

//--------------------------------------------------------------------------
// async interim responses: STATUS_PENDING, severity SUCCESS, no parsable body.
// Every one of these must be dropped before StructureSize is used to tell a request from a
// response, because for each command 9 means something different.
//--------------------------------------------------------------------------

TEST_CASE("ioctl async interim response is discarded", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_IOCTL, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    DCE2_Smb2IoctlCommand(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_ioctl_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_ioctl_err_resp == 0);
}

TEST_CASE("create async interim response is discarded", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_CREATE, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    DCE2_Smb2Create(f.ssd, *hdr, body.begin(), body.end(), test_mid, test_sid, test_tid);

    CHECK(dce2_smb_stats.v2_crt_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_crt_err_resp == 0);
}

// A regression lock rather than a reproduction: TREE_CONNECT's request branch is empty, so an
// interim response that falls through to it is silently ignored and no counter moves.  The case
// is here so that a future fix which starts parsing StructureSize 9 as a TREE_CONNECT Request
// body -- 9 is that body's size -- is caught.
TEST_CASE("tree connect async interim response is discarded", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_TREE_CONNECT, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    DCE2_Smb2TreeConnect(f.ssd, *hdr, body.begin(), body.end(), f.str, test_tid);

    CHECK(dce2_smb_stats.v2_tree_cnct_err_resp == 0);
    CHECK(dce2_smb_stats.v2_tree_cnct_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_tree_cnct_resp_hdr_err == 0);
    CHECK(dce2_smb_stats.v2_tree_cnct_ignored == 0);
}

// StructureSize 9 is also the SESSION_SETUP Response size, so an interim response that gets
// this far is parsed as a real setup response and mints a tracker for a session that was
// never established.
TEST_CASE("session setup async interim response creates no session tracker",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_SESSION_SETUP, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    REQUIRE(DCE2_Smb2FindSidInSsd(f.ssd, test_sid) == nullptr);

    DCE2_Smb2Setup(f.ssd, *hdr, test_sid, body.begin(), body.end());

    CHECK(DCE2_Smb2FindSidInSsd(f.ssd, test_sid) == nullptr);
    CHECK(dce2_smb_stats.v2_setup_err_resp == 0);
    CHECK(dce2_smb_stats.v2_setup_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_setup_resp_hdr_err == 0);
}

// CLOSE reports 24 for its request and 60 for its response, so StructureSize 9 matches
// neither and reaches the terminal else -- which does not merely count, it drops the file
// and request trackers.  A server that answers a CLOSE with an interim response would
// therefore destroy the tracking state for a transfer still in flight, before the real
// response arrives to do it deliberately.
TEST_CASE("close async interim response leaves the file trackers in place",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    f.open_file();
    Hdr hdr(SMB2_COM_CLOSE, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    const bool open_before = f.file_still_open();
    REQUIRE(open_before);

    DCE2_Smb2CloseCmd(f.ssd, *hdr, body.begin(), body.end(), f.ttr, f.str, test_mid);

    const bool open_after = f.file_still_open();
    CHECK(open_after);
    CHECK(dce2_smb_stats.v2_cls_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_cls_err_resp == 0);
}

TEST_CASE("read async interim response is discarded", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_READ, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    DCE2_Smb2Read(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_read_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_read_err_resp == 0);
}

TEST_CASE("write async interim response is discarded", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_WRITE, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    DCE2_Smb2Write(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_wrt_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_wrt_err_resp == 0);
}

TEST_CASE("set info async interim response is discarded", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_SET_INFO, SMB2_STATUS_PENDING, flags_async_response);
    Body9 body;

    DCE2_Smb2SetInfo(f.ssd, *hdr, body.begin(), body.end(), f.ttr);

    CHECK(dce2_smb_stats.v2_stinf_inv_str_sz == 0);
    CHECK(dce2_smb_stats.v2_stinf_err_resp == 0);
}

//--------------------------------------------------------------------------
// SMB 3.x requests: ChannelSequence occupies the field the response uses for Status
//--------------------------------------------------------------------------

TEST_CASE("tree connect request with a channel sequence is not an error response",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_TREE_CONNECT, test_channel_sequence, 0);
    Body9 body;   // StructureSize 9 is also the TREE_CONNECT Request body size

    DCE2_Smb2TreeConnect(f.ssd, *hdr, body.begin(), body.end(), f.str, test_tid);

    CHECK(dce2_smb_stats.v2_tree_cnct_err_resp == 0);
    CHECK(dce2_smb_stats.v2_tree_cnct_inv_str_sz == 0);
}

//--------------------------------------------------------------------------
// controls: a real error response still has to be counted
//--------------------------------------------------------------------------

TEST_CASE("ioctl error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_IOCTL, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2IoctlCommand(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_ioctl_err_resp == 1);
    CHECK(dce2_smb_stats.v2_ioctl_inv_str_sz == 0);
}

TEST_CASE("create error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_CREATE, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2Create(f.ssd, *hdr, body.begin(), body.end(), test_mid, test_sid, test_tid);

    CHECK(dce2_smb_stats.v2_crt_err_resp == 1);
    CHECK(dce2_smb_stats.v2_crt_inv_str_sz == 0);
}

TEST_CASE("tree connect error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_TREE_CONNECT, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2TreeConnect(f.ssd, *hdr, body.begin(), body.end(), f.str, test_tid);

    CHECK(dce2_smb_stats.v2_tree_cnct_err_resp == 1);
    CHECK(dce2_smb_stats.v2_tree_cnct_inv_str_sz == 0);
}

TEST_CASE("session setup error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_SESSION_SETUP, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2Setup(f.ssd, *hdr, test_sid, body.begin(), body.end());

    CHECK(dce2_smb_stats.v2_setup_err_resp == 1);
    CHECK(DCE2_Smb2FindSidInSsd(f.ssd, test_sid) == nullptr);
}

TEST_CASE("close error response is counted and keeps the file trackers",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    f.open_file();
    Hdr hdr(SMB2_COM_CLOSE, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2CloseCmd(f.ssd, *hdr, body.begin(), body.end(), f.ttr, f.str, test_mid);

    CHECK(dce2_smb_stats.v2_cls_err_resp == 1);
    CHECK(dce2_smb_stats.v2_cls_inv_str_sz == 0);
    const bool still_open = f.file_still_open();
    CHECK(still_open);
}

TEST_CASE("read error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_READ, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2Read(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_read_err_resp == 1);
    CHECK(dce2_smb_stats.v2_read_inv_str_sz == 0);
}

TEST_CASE("write error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_WRITE, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2Write(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_wrt_err_resp == 1);
    CHECK(dce2_smb_stats.v2_wrt_inv_str_sz == 0);
}

TEST_CASE("set info error response is counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_SET_INFO, SMB2_STATUS_ACCESS_DENIED, flags_response);
    Body9 body;

    DCE2_Smb2SetInfo(f.ssd, *hdr, body.begin(), body.end(), f.ttr);

    CHECK(dce2_smb_stats.v2_stinf_err_resp == 1);
    CHECK(dce2_smb_stats.v2_stinf_inv_str_sz == 0);
}

//--------------------------------------------------------------------------
// controls: only STATUS_PENDING is interim.  The final response to an async request keeps
// SMB2_FLAGS_ASYNC_COMMAND set and carries the real status, so a guard that keys on the flag
// alone would swallow genuine errors -- these fail on such a guard and pass on a correct one.
//--------------------------------------------------------------------------

TEST_CASE("final async error response is still counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_IOCTL, SMB2_STATUS_ACCESS_DENIED, flags_async_response);
    Body9 body;

    DCE2_Smb2IoctlCommand(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_ioctl_err_resp == 1);
    CHECK(dce2_smb_stats.v2_ioctl_inv_str_sz == 0);
}

TEST_CASE("final async create error response is still counted", "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_CREATE, SMB2_STATUS_ACCESS_DENIED, flags_async_response);
    Body9 body;

    DCE2_Smb2Create(f.ssd, *hdr, body.begin(), body.end(), test_mid, test_sid, test_tid);

    CHECK(dce2_smb_stats.v2_crt_err_resp == 1);
    CHECK(dce2_smb_stats.v2_crt_inv_str_sz == 0);
}

//--------------------------------------------------------------------------
// controls: the interim test has to stay confined to bodies that could be an ERROR Response,
// and to headers that could be a response at all.  Both of these fail on a guard that keys on
// flags and status without also checking StructureSize and direction.
//--------------------------------------------------------------------------

// A header that looks interim but carries a full CREATE Request body.  StructureSize 57 rules
// out an ERROR Response, so the body is what it says it is and has to be parsed: doing so
// creates the tree tracker for the mid-stream session.  A guard that returns on flags and
// status alone drops the request instead, which loses tracking state and is reachable by any
// client willing to set two header bits.
TEST_CASE("create request body with an interim-looking header is still parsed",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_CREATE, SMB2_STATUS_PENDING, flags_async_response);
    BodyCreateRequest body;

    DCE2_Smb2Create(f.ssd, *hdr, body.begin(), body.end(), test_mid, test_sid, test_tid);

    auto created = DCE2_Smb2FindSidInSsd(f.ssd, test_sid);
    REQUIRE(created != nullptr);
    CHECK(created->findTtracker(test_tid) != nullptr);
    CHECK(dce2_smb_stats.v2_crt_err_resp == 0);
    CHECK(dce2_smb_stats.v2_crt_inv_str_sz == 0);
    // v2_crt_req_hdr_err is deliberately not asserted: the body's NameOffset is 0, which the
    // request parser counts on its own account.  What matters here is that the request was
    // parsed at all, which the tree tracker above proves.
}

// STATUS_PENDING on a header without SMB2_FLAGS_SERVER_TO_REDIR is not an interim response --
// only a server sends those.  It is a malformed request, and StructureSize 9 is neither an
// IOCTL Request (57) nor an IOCTL Response (49), so the truthful classification is an invalid
// structure size.  Giving it the interim free pass instead lets a client suppress inspection
// of its own traffic by setting one flag.
TEST_CASE("client originated pending status is not an interim response",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_IOCTL, SMB2_STATUS_PENDING, SMB2_FLAGS_ASYNC_COMMAND);
    Body9 body;

    DCE2_Smb2IoctlCommand(f.ssd, *hdr, body.begin(), body.end(), f.str, f.ttr, test_mid);

    CHECK(dce2_smb_stats.v2_ioctl_inv_str_sz == 1);
    CHECK(dce2_smb_stats.v2_ioctl_err_resp == 0);
}

// Not a bug this test set is trying to fix, pinned so a fix does not change it by accident.
// STATUS_MORE_PROCESSING_REQUIRED has severity ERROR, so both the old status test and the new
// severity test call the second leg of NTLM authentication an error response and skip creating
// the session -- even though it is a normal SESSION_SETUP Response.  Any change here should be
// a deliberate one with its own test.
TEST_CASE("session setup more processing required is treated as an error response",
    "[dce_smb2_async_interim]")
{
    Fixture f;
    Hdr hdr(SMB2_COM_SESSION_SETUP, SMB2_STATUS_MORE_PROCESSING_REQUIRED, flags_response);
    Body9 body;

    DCE2_Smb2Setup(f.ssd, *hdr, test_sid, body.begin(), body.end());

    CHECK(dce2_smb_stats.v2_setup_err_resp == 1);
    CHECK(DCE2_Smb2FindSidInSsd(f.ssd, test_sid) == nullptr);
}
