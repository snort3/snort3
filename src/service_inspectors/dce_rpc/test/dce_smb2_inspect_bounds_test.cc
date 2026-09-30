//--------------------------------------------------------------------------
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

// Covers truncated initial and compound SMB2 headers plus the negotiate body.
// Buffers are sized to the exact input so an unfixed build also fails under ASAN.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../dce_smb2.h"
#include "../dce_smb2_commands.h"
#include "../dce_smb2_utils.h"
#include "../dce_smb_module.h"

#include "detection/detection_engine.h"
#include "file_api/file_flows.h"
#include "file_api/file_lib.h"
#include "file_api/file_service.h"
#include "flow/flow.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "catch/catch.hpp"

#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

namespace
{
FlowKey test_key {};
Flow test_flow;
Packet test_packet;

constexpr uint64_t test_sid = 0x1122334455667788ULL;
constexpr uint32_t test_tid = 0x99;
constexpr uint64_t test_mid = 42;

// MS-SMB2 2.2.1.2 SMB2_FLAGS_SERVER_TO_REDIR, set on every response.
constexpr uint32_t flags_response = 0x00000001;

// NBSS_SESSION_TYPE__MESSAGE.  Any nonzero length keeps NbssIsEmptyCtrl from treating the
// frame as a keep-alive and skipping past it before the SMB2 header is reached.
constexpr uint8_t nbss_type_message = 0x00;

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

// Build the wire header as bytes to avoid host-endian struct layout.
void write_smb2_hdr(uint8_t* dst, uint16_t command, uint32_t next_command)
{
    dst[0] = 0xFE;
    dst[1] = 'S';
    dst[2] = 'M';
    dst[3] = 'B';
    store_le16(dst + 4, SMB2_HEADER_LENGTH);
    store_le16(dst + 12, command);
    store_le32(dst + 16, flags_response);
    store_le32(dst + 20, next_command);
    store_le64(dst + 24, test_mid);
    store_le32(dst + 36, test_tid);
    store_le64(dst + 40, test_sid);
}

// Keep the allocation exact so out-of-bounds reads cross the allocation boundary.
class Wire
{
public:
    explicit Wire(size_t smb_bytes) : buf(sizeof(NbssHdr) + smb_bytes)
    {
        buf[0] = nbss_type_message;
        buf[1] = static_cast<uint8_t>((smb_bytes >> 16) & 0xff);
        buf[2] = static_cast<uint8_t>((smb_bytes >> 8) & 0xff);
        buf[3] = static_cast<uint8_t>(smb_bytes & 0xff);
    }

    uint8_t* smb() { return buf.data() + sizeof(NbssHdr); }

    void install()
    {
        test_packet.data = buf.data();
        test_packet.dsize = static_cast<uint16_t>(buf.size());
        test_packet.packet_flags = PKT_PDU_HEAD;
    }

private:
    std::vector<uint8_t> buf;
};

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
        ssd->flow = &test_flow;
        // Null selects the shipping compound-request default.
        ssd->sd.config = nullptr;
    }

    ~Fixture()
    {
        delete ssd;
        delete smb2_session_cache;
        smb2_session_cache = nullptr;
        DCE2_Smb2FtrackerLruTerm();
    }

    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    DCE2_Smb2SsnData* ssd = nullptr;
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
// path 1: the existing minimum leaves no command body
//--------------------------------------------------------------------------

// At the existing minimum, smb_data equals end and structure_size is out of bounds.
// cppcheck-suppress [syntaxError, unmatchedSuppression] ; Catch2 TEST_CASE is configuration-dependent
TEST_CASE("smb2 header with no command body is rejected", "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    Wire wire(SMB2_HEADER_LENGTH);
    write_smb2_hdr(wire.smb(), SMB2_COM_NEGOTIATE, 0);
    wire.install();

    DCE2_Smb2Process(f.ssd);

    CHECK(dce2_smb_stats.v2_hdr_err == 1);
    CHECK(dce2_smb_stats.total_mc_sessions == 0);
}

//--------------------------------------------------------------------------
// path 2: a compound header starting at the buffer end
//--------------------------------------------------------------------------

// The first header's next_command points exactly at end, where the old loop accepted a
// header with no remaining bytes.
TEST_CASE("compound header starting at the buffer end is rejected",
    "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    constexpr uint16_t body_len = sizeof(uint16_t);
    constexpr uint32_t next_command = SMB2_HEADER_LENGTH + body_len;

    Wire wire(SMB2_HEADER_LENGTH + body_len);
    write_smb2_hdr(wire.smb(), SMB2_COM_NEGOTIATE, next_command);
    // Avoid entering a negotiate-body read; only the compound hop is under test.
    store_le16(wire.smb() + SMB2_HEADER_LENGTH, 0);
    wire.install();

    DCE2_Smb2Process(f.ssd);

    CHECK(dce2_smb_stats.v2_hdr_err == 1);
    CHECK(dce2_smb_stats.total_mc_sessions == 0);
}

// A bad following offset must not suppress accounting for the current command.
TEST_CASE("current command is counted before rejecting its bad next command offset",
    "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    dce2SmbProtoConf config { };
    f.ssd->sd.config = &config;
    constexpr uint16_t body_len = sizeof(uint16_t);
    constexpr uint32_t next_command = SMB2_HEADER_LENGTH + body_len + 8;

    Wire wire(SMB2_HEADER_LENGTH + body_len);
    write_smb2_hdr(wire.smb(), SMB2_COM_MAX, next_command);
    store_le16(wire.smb() + SMB2_HEADER_LENGTH, 0);
    wire.install();

    DCE2_Smb2Process(f.ssd);

    CHECK(dce2_smb_stats.v2_msgs_uninspected == 1);
    CHECK(dce2_smb_stats.v2_bad_next_cmd_offset == 1);
}

//--------------------------------------------------------------------------
// the negotiate body must also be complete
//--------------------------------------------------------------------------

// The command claims a negotiate response, but the body is truncated before capabilities.
TEST_CASE("truncated negotiate response body is rejected", "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    constexpr uint16_t body_len = sizeof(uint16_t);

    Wire wire(SMB2_HEADER_LENGTH + body_len);
    write_smb2_hdr(wire.smb(), SMB2_COM_NEGOTIATE, 0);
    store_le16(wire.smb() + SMB2_HEADER_LENGTH, SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE);
    wire.install();

    DCE2_Smb2Process(f.ssd);

    CHECK(dce2_smb_stats.v2_hdr_err == 1);
    CHECK(dce2_smb_stats.total_mc_sessions == 0);
}

// A following compound command must not supply bytes missing from the negotiate response.
TEST_CASE("truncated negotiate response cannot consume the next compound header",
    "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    constexpr uint16_t body_len = 8;
    constexpr uint32_t next_command = SMB2_HEADER_LENGTH + body_len;

    Wire wire(next_command + SMB2_HEADER_LENGTH + sizeof(uint16_t));
    write_smb2_hdr(wire.smb(), SMB2_COM_NEGOTIATE, next_command);
    store_le16(wire.smb() + SMB2_HEADER_LENGTH, SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE);
    write_smb2_hdr(wire.smb() + next_command, SMB2_COM_NEGOTIATE, 0);
    store_le16(wire.smb() + next_command + SMB2_HEADER_LENGTH, 0);
    wire.install();

    DCE2_Smb2Process(f.ssd);

    CHECK(dce2_smb_stats.v2_hdr_err == 1);
    CHECK(dce2_smb_stats.total_mc_sessions == 0);
}

// The IOCTL handler must validate the complete request before reading ctl_code or file IDs.
TEST_CASE("truncated ioctl request body is rejected", "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    Smb2Hdr hdr { };
    uint8_t body[sizeof(uint16_t)] { };
    store_le16(body, SMB2_IOCTL_REQUEST_STRUC_SIZE);

    DCE2_Smb2IoctlCommand(f.ssd, &hdr, body, body + sizeof(body), nullptr, nullptr, test_mid);

    CHECK(dce2_smb_stats.v2_hdr_err == 1);
}

// The response layout has a different fixed size and needs its own boundary check.
TEST_CASE("truncated ioctl response body is rejected", "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    Smb2Hdr hdr { };
    uint8_t body[sizeof(uint16_t)] { };
    store_le16(body, SMB2_IOCTL_RESPONSE_STRUC_SIZE);

    DCE2_Smb2IoctlCommand(f.ssd, &hdr, body, body + sizeof(body), nullptr, nullptr, test_mid);

    CHECK(dce2_smb_stats.v2_hdr_err == 1);
}

//--------------------------------------------------------------------------
// negative control: valid traffic remains unaffected
//--------------------------------------------------------------------------

// A complete response must pass both checks and still count the session.
TEST_CASE("complete negotiate response is still parsed and counted",
    "[dce_smb2_inspect_bounds]")
{
    Fixture f;
    constexpr size_t body_len = sizeof(Smb2NegotiateResponseHdr);

    Wire wire(SMB2_HEADER_LENGTH + body_len);
    write_smb2_hdr(wire.smb(), SMB2_COM_NEGOTIATE, 0);
    uint8_t* body = wire.smb() + SMB2_HEADER_LENGTH;
    store_le16(body, SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE);
    store_le32(body + offsetof(Smb2NegotiateResponseHdr, capabilities),
        SMB2_GLOBAL_CAP_MULTI_CHANNEL);
    wire.install();

    DCE2_Smb2Process(f.ssd);

    CHECK(dce2_smb_stats.total_mc_sessions == 1);
    CHECK(dce2_smb_stats.v2_hdr_err == 0);
}
