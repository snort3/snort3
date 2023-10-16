//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb1.h author Bhargava Jandhyala <bjandhya@cisco.com>

#ifndef DCE_SMB1_H
#define DCE_SMB1_H

// This provides smb session data and SMBv1 specific trackers

#include "protocols/packet.h"
#include "profiler/profiler_defs.h"

#include "dce_co.h"
#include "dce_smb_common.h"
#include "dce_smb_module.h"
#include "smb_message.h"

enum DCE2_SmbSsnState
{
    DCE2_SMB_SSN_STATE__START         = 0x00,
    DCE2_SMB_SSN_STATE__NEGOTIATED    = 0x01,
    DCE2_SMB_SSN_STATE__FP_CLIENT     = 0x02,  // Fingerprinted client
    DCE2_SMB_SSN_STATE__FP_SERVER     = 0x04   // Fingerprinted server
};

enum DCE2_SmbDataState
{
    DCE2_SMB_DATA_STATE__NETBIOS_HEADER,
    DCE2_SMB_DATA_STATE__SMB_HEADER,
    DCE2_SMB_DATA_STATE__NETBIOS_PDU
};

enum DCE2_SmbFileDirection
{
    DCE2_SMB_FILE_DIRECTION__UNKNOWN = 0,
    DCE2_SMB_FILE_DIRECTION__UPLOAD,
    DCE2_SMB_FILE_DIRECTION__DOWNLOAD
};

enum SmbAndXCom
{
    SMB_ANDX_COM__NONE,
    SMB_ANDX_COM__OPEN_ANDX,
    SMB_ANDX_COM__READ_ANDX,
    SMB_ANDX_COM__WRITE_ANDX,
    SMB_ANDX_COM__TREE_CONNECT_ANDX,
    SMB_ANDX_COM__SESSION_SETUP_ANDX,
    SMB_ANDX_COM__LOGOFF_ANDX,
    SMB_ANDX_COM__NT_CREATE_ANDX,
    SMB_ANDX_COM__MAX
};

struct DCE2_SmbWriteAndXRaw
{
    int remaining;  // A signed integer so it can be negative
    DCE2_Buffer* buf;
};

struct DCE2_SmbFileChunk
{
    uint64_t offset;
    uint32_t length;
    uint8_t* data;
};

struct DCE2_SmbFileTracker
{
    struct
    {
        int file_id;   // A signed integer so it can be set to sentinel
        uint16_t u_id;
        uint16_t tree_id;
    } file_key;

    bool is_ipc;
    bool is_smb2;
    char* file_name;
    uint16_t file_name_size;
    uint64_t file_name_hash;

    union
    {
        struct
        {
            // If pipe has been set to byte mode via TRANS_SET_NMPIPE_STATE
            bool byte_mode;

            // For Windows 2000
            bool used;

            // For WriteAndX requests that use raw mode flag
            // Windows only
            DCE2_SmbWriteAndXRaw* writex_raw;

            // Connection-oriented DCE/RPC tracker
            DCE2_CoTracker* co_tracker;
        } nmpipe;

        struct
        {
            uint64_t file_size;
            uint64_t file_offset;
            uint64_t bytes_processed;
            DCE2_List* file_chunks;
            uint32_t bytes_queued;
            DCE2_SmbFileDirection file_direction;
            bool sequential_only;
        } file;
    } tracker;

#define fid_v1                file_key.file_id
#define uid_v1                file_key.u_id
#define tid_v1                file_key.tree_id
#define fp_byte_mode   tracker.nmpipe.byte_mode
#define fp_used        tracker.nmpipe.used
#define fp_writex_raw  tracker.nmpipe.writex_raw
#define fp_co_tracker  tracker.nmpipe.co_tracker
#define ff_file_size          tracker.file.file_size
#define ff_file_offset        tracker.file.file_offset
#define ff_bytes_processed    tracker.file.bytes_processed
#define ff_file_direction     tracker.file.file_direction
#define ff_file_chunks        tracker.file.file_chunks
#define ff_bytes_queued       tracker.file.bytes_queued
#define ff_sequential_only    tracker.file.sequential_only
};

struct Smb2Request
{
    uint64_t message_id;   /* identifies a message uniquely on connection */
    uint64_t offset;       /* data offset */
    uint64_t file_id;      /* file id */
    struct Smb2Request* next;
    struct Smb2Request* previous;
};

struct DCE2_SmbTransactionTracker
{
    int smb_type;
    uint8_t subcom;
    bool one_way;
    bool disconnect_tid;
    bool pipe_byte_mode;
    uint32_t tdcnt;
    uint32_t dsent;
    DCE2_Buffer* dbuf;
    uint32_t tpcnt;
    uint32_t psent;
    DCE2_Buffer* pbuf;
    // For Transaction2/Query File Information
    uint16_t info_level;
};

struct DCE2_SmbRequestTracker
{
    int smb_com;

    int mid;   // A signed integer so it can be set to sentinel
    uint16_t uid;
    uint16_t tid;
    uint16_t pid;

    // For WriteRaw
    bool writeraw_writethrough;
    uint32_t writeraw_remaining;

    // For Transaction/Transaction2/NtTransact
    DCE2_SmbTransactionTracker ttracker;

    // Client can chain a write to an open.  Need to write data, but also
    // need to associate tracker with fid returned from server
    DCE2_Queue* ft_queue;

    // This is a reference to an existing file tracker
    DCE2_SmbFileTracker* ftracker;

    // Used for requests to cache data that will ultimately end up in
    // the file tracker upon response.
    char* file_name;
    uint16_t file_name_size;
    uint64_t file_size;
    uint64_t file_offset;
    bool sequential_only;

    // For TreeConnect to know whether it's to IPC
    bool is_ipc;
};

struct DCE2_SmbSsnData
{
    DCE2_SsnData sd;  // This member must be first
    DCE2_Policy policy;

    int dialect_index;
    int ssn_state_flags;

    DCE2_SmbDataState cli_data_state;
    DCE2_SmbDataState srv_data_state;

    Dce2SmbPduState pdu_state;

    int uid;   // A signed integer so it can be set to sentinel
    int tid;   // A signed integer so it can be set to sentinel
    DCE2_List* uids;
    DCE2_List* tids;

    // For tracking files and named pipes
    DCE2_SmbFileTracker ftracker;
    DCE2_List* ftrackers;  // List of DCE2_SmbFileTracker

    // For tracking requests / responses
    DCE2_SmbRequestTracker rtracker;
    DCE2_Queue* rtrackers;
    uint16_t max_outstanding_requests;
    uint16_t outstanding_requests;

    // The current pid/mid node for this request/response
    DCE2_SmbRequestTracker* cur_rtracker;

    // Used for TCP segmentation to get full PDU
    DCE2_Buffer* cli_seg;
    DCE2_Buffer* srv_seg;

    // These are used for commands we don't need to process
    uint32_t cli_ignore_bytes;
    uint32_t srv_ignore_bytes;

    // The file API supports one concurrent upload/download per session.
    // This is a reference to a file tracker so shouldn't be freed.
    DCE2_SmbFileTracker* fapi_ftracker;

    DCE2_SmbFileTracker* fb_ftracker;
    bool block_pdus;

    // Maximum file depth as returned from file API
    int64_t max_file_depth;
};

struct DCE2_SmbFsm
{
    char input;
    int next_state;
    int fail_state;
};

// Used for reassembled packets
#define DCE2_MOCK_HDR_LEN__SMB_CLI \
    ((unsigned)(sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq)))
#define DCE2_MOCK_HDR_LEN__SMB_SRV \
    ((unsigned)(sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp)))

DCE2_SsnData* get_dce2_session_data(snort::Flow*);

const char* get_smb_com_string(uint8_t);

class Dce2Smb1SessionData : public Dce2SmbSessionData
{
public:
    Dce2Smb1SessionData() = delete;
    Dce2Smb1SessionData(const snort::Packet*, const dce2SmbProtoConf* proto);
    ~Dce2Smb1SessionData() override;
    void process() override;
    void handle_retransmit(FilePosition, FileVerdict) override { }
    void set_reassembled_data(uint8_t*, uint16_t) override;

private:
    DCE2_SmbSsnData ssd;
};

#endif

