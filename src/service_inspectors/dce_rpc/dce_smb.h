//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB_H
#define DCE_SMB_H

#include "framework/counts.h"
#include "protocols/packet.h"
#include "profiler/profiler_defs.h"

#include "dce_co.h"
#include "smb_common.h"
#include "smb_message.h"

#define DCE2_SMB_NAME "dce_smb"
#define DCE2_SMB_HELP "dce over smb inspection"
#define DCE2_SMB_RPKT_TYPE_MAX 4
#define DCE2_SMB_RPKT_TYPE_START 1

#define DCE2_SMB_BAD_NBSS_TYPE 2
#define DCE2_SMB_BAD_TYPE 3
#define DCE2_SMB_BAD_ID 4
#define DCE2_SMB_BAD_WCT 5
#define DCE2_SMB_BAD_BCC 6
#define DCE2_SMB_BAD_FORM 7
#define DCE2_SMB_BAD_OFF 8
#define DCE2_SMB_TDCNT_ZE 9
#define DCE2_SMB_NB_LT_SMBHDR 10
#define DCE2_SMB_NB_LT_COM 11
#define DCE2_SMB_NB_LT_BCC 12
#define DCE2_SMB_NB_LT_DSIZE 13
#define DCE2_SMB_TDCNT_LT_DSIZE 14
#define DCE2_SMB_DSENT_GT_TDCNT 15
#define DCE2_SMB_BCC_LT_DSIZE 16
#define DCE2_SMB_INVALID_DSIZE 17
#define DCE2_SMB_EXCESSIVE_TREE_CONNECTS 18
#define DCE2_SMB_EXCESSIVE_READS 19
#define DCE2_SMB_EXCESSIVE_CHAINING 20
#define DCE2_SMB_MULT_CHAIN_SS 21
#define DCE2_SMB_MULT_CHAIN_TC 22
#define DCE2_SMB_CHAIN_SS_LOGOFF 23
#define DCE2_SMB_CHAIN_TC_TDIS 24
#define DCE2_SMB_CHAIN_OPEN_CLOSE 25
#define DCE2_SMB_INVALID_SHARE 26

#define DCE2_SMB_V1 44
#define DCE2_SMB_V2 45
#define DCE2_SMB_INVALID_BINDING 46
#define DCE2_SMB2_EXCESSIVE_COMPOUNDING 47
#define DCE2_SMB_DCNT_ZERO 48
#define DCE2_SMB_DCNT_MISMATCH 49
#define DCE2_SMB_MAX_REQS_EXCEEDED 50
#define DCE2_SMB_REQS_SAME_MID 51
#define DCE2_SMB_DEPR_DIALECT_NEGOTIATED 52
#define DCE2_SMB_DEPR_COMMAND_USED 53
#define DCE2_SMB_UNUSUAL_COMMAND_USED 54
#define DCE2_SMB_INVALID_SETUP_COUNT 55
#define DCE2_SMB_MULTIPLE_NEGOTIATIONS 56
#define DCE2_SMB_EVASIVE_FILE_ATTRS 57
#define DCE2_SMB_INVALID_FILE_OFFSET 58
#define DCE2_SMB_BAD_NEXT_COMMAND_OFFSET 59

#define DCE2_SMB_BAD_NBSS_TYPE_STR "SMB - bad NetBIOS session service session type"
#define DCE2_SMB_BAD_TYPE_STR  "SMB - bad SMB message type"
#define DCE2_SMB_BAD_ID_STR "SMB - bad SMB Id (not \\xffSMB for SMB1 or not \\xfeSMB for SMB2)"
#define DCE2_SMB_BAD_WCT_STR "SMB - bad word count or structure size"
#define DCE2_SMB_BAD_BCC_STR  "SMB - bad byte count"
#define DCE2_SMB_BAD_FORM_STR  "SMB - bad format type"
#define DCE2_SMB_BAD_OFF_STR  "SMB - bad offset"
#define DCE2_SMB_TDCNT_ZE_STR  "SMB - zero total data count"
#define DCE2_SMB_NB_LT_SMBHDR_STR "SMB - NetBIOS data length less than SMB header length"
#define DCE2_SMB_NB_LT_COM_STR   "SMB - remaining NetBIOS data length less than command length"
#define DCE2_SMB_NB_LT_BCC_STR  "SMB - remaining NetBIOS data length less than command byte count"
#define DCE2_SMB_NB_LT_DSIZE_STR \
    "SMB - remaining NetBIOS data length less than command data size"
#define DCE2_SMB_TDCNT_LT_DSIZE_STR \
    "SMB - remaining total data count less than this command data size"
#define DCE2_SMB_DSENT_GT_TDCNT_STR \
    "SMB - total data sent (STDu64) greater than command total data expected"
#define DCE2_SMB_BCC_LT_DSIZE_STR   "SMB - byte count less than command data size (STDu64)"
#define DCE2_SMB_INVALID_DSIZE_STR  "SMB - invalid command data size for byte count"
#define DCE2_SMB_EXCESSIVE_TREE_CONNECTS_STR \
    "SMB - excessive tree connect requests with pending tree connect responses"
#define DCE2_SMB_EXCESSIVE_READS_STR  "SMB - excessive read requests with pending read responses"
#define DCE2_SMB_EXCESSIVE_CHAINING_STR  "SMB - excessive command chaining"
#define DCE2_SMB_MULT_CHAIN_SS_STR   "SMB - multiple chained tree connect requests"
#define DCE2_SMB_MULT_CHAIN_TC_STR   "SMB - multiple chained tree connect requests"
#define DCE2_SMB_CHAIN_SS_LOGOFF_STR   "SMB - chained/compounded login followed by logoff"
#define DCE2_SMB_CHAIN_TC_TDIS_STR \
    "SMB - chained/compounded tree connect followed by tree disconnect"
#define DCE2_SMB_CHAIN_OPEN_CLOSE_STR \
    "SMB - chained/compounded open pipe followed by close pipe"
#define DCE2_SMB_INVALID_SHARE_STR   "SMB - invalid share access"

#define DCE2_SMB_V1_STR  "SMB - invalid SMB version 1 seen"
#define DCE2_SMB_V2_STR  "SMB - invalid SMB version 2 seen"
#define DCE2_SMB_INVALID_BINDING_STR "SMB - invalid user, tree connect, file binding"
#define DCE2_SMB2_EXCESSIVE_COMPOUNDING_STR  "SMB - excessive command compounding"
#define DCE2_SMB_DCNT_ZERO_STR   "SMB - zero data count"
#define DCE2_SMB_DCNT_MISMATCH_STR "SMB - data count mismatch in command and format"
#define DCE2_SMB_MAX_REQS_EXCEEDED_STR  "SMB - maximum number of outstanding requests exceeded"
#define DCE2_SMB_REQS_SAME_MID_STR "SMB - outstanding requests with same MID"
#define DCE2_SMB_DEPR_DIALECT_NEGOTIATED_STR  "SMB - deprecated dialect negotiated"
#define DCE2_SMB_DEPR_COMMAND_USED_STR   "SMB - deprecated command used"
#define DCE2_SMB_UNUSUAL_COMMAND_USED_STR "SMB - unusual command used"
#define DCE2_SMB_INVALID_SETUP_COUNT_STR  "SMB - invalid setup count for command"
#define DCE2_SMB_MULTIPLE_NEGOTIATIONS_STR \
    "SMB - client attempted multiple dialect negotiations on session"
#define DCE2_SMB_EVASIVE_FILE_ATTRS_STR \
    "SMB - client attempted to create or set a file's attributes to readonly/hidden/system"
#define DCE2_SMB_INVALID_FILE_OFFSET_STR \
    "SMB - file offset provided is greater than file size specified"
#define DCE2_SMB_BAD_NEXT_COMMAND_OFFSET_STR \
    "SMB - next command specified in SMB2 header is beyond payload boundary"

struct dce2SmbStats
{
    PegCount events;

    PegCount co_pdus;
    PegCount co_bind;
    PegCount co_bind_ack;
    PegCount co_alter_ctx;
    PegCount co_alter_ctx_resp;
    PegCount co_bind_nack;
    PegCount co_request;
    PegCount co_response;
    PegCount co_cancel;
    PegCount co_orphaned;
    PegCount co_fault;
    PegCount co_auth3;
    PegCount co_shutdown;
    PegCount co_reject;
    PegCount co_ms_pdu;
    PegCount co_other_req;
    PegCount co_other_resp;
    PegCount co_req_fragments;
    PegCount co_resp_fragments;
    PegCount co_cli_max_frag_size;
    PegCount co_cli_min_frag_size;
    PegCount co_cli_seg_reassembled;
    PegCount co_cli_frag_reassembled;
    PegCount co_srv_max_frag_size;
    PegCount co_srv_min_frag_size;
    PegCount co_srv_seg_reassembled;
    PegCount co_srv_frag_reassembled;

    PegCount smb_sessions;
    PegCount smb_pkts;
    PegCount smb_ignored_bytes;
    PegCount smb_cli_seg_reassembled;
    PegCount smb_srv_seg_reassembled;
    PegCount smb_max_outstanding_requests;
    //  FIXIT-M more peg count foo
    /*uint64_t smb_com_stats[2][SMB_MAX_NUM_COMS];
    uint64_t smb_chained_stats[2][SMB_ANDX_COM__MAX][SMB_MAX_NUM_COMS];
    // The +1 is for codes beyond the range of the highest valid subcommand code
    // Indicates a bogus subcommand
    uint64_t smb_trans_subcom_stats[2][TRANS_SUBCOM_MAX+1];
    uint64_t smb_trans2_subcom_stats[2][TRANS2_SUBCOM_MAX+1];
    uint64_t smb_nt_transact_subcom_stats[2][NT_TRANSACT_SUBCOM_MAX+1];
    */
    PegCount smb_files_processed;
    /* SMB2 stats */
    PegCount smb2_create;
    PegCount smb2_write;
    PegCount smb2_read;
    PegCount smb2_set_info;
    PegCount smb2_tree_connect;
    PegCount smb2_tree_disconnect;
    PegCount smb2_close;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

extern THREAD_LOCAL dce2SmbStats dce2_smb_stats;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_main;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_session;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_new_session;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_detect;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_log;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_co_seg;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_co_frag;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_co_reass;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_co_ctx;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_seg;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_req;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_uid;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_tid;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_fid;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_file;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_file_detect;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_file_api;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_fingerprint;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_smb_negotiate;

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

enum DCE2_SmbPduState
{
    DCE2_SMB_PDU_STATE__COMMAND,
    DCE2_SMB_PDU_STATE__RAW_DATA
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

enum DCE2_SmbVersion
{
    DCE2_SMB_VERISON_NULL,
    DCE2_SMB_VERISON_1,
    DCE2_SMB_VERISON_2
};

struct DCE2_SmbFileTracker
{
    union
    {
        struct
        {
            int file_id;   // A signed integer so it can be set to sentinel
            uint16_t u_id;
            uint16_t tree_id;
        } id_smb1;

        struct
        {
            uint64_t file_id;
        } id_smb2;
    } file_key;

    bool is_ipc;
    bool is_smb2;
    char* file_name;
    uint16_t file_name_size;

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

#define fid_v1                file_key.id_smb1.file_id
#define uid_v1                file_key.id_smb1.u_id
#define tid_v1                file_key.id_smb1.tree_id
#define fid_v2                file_key.id_smb2.file_id
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

    DCE2_SmbPduState pdu_state;

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

    Smb2Request* smb2_requests;

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

class Dce2SmbFlowData : public snort::FlowData
{
public:
    Dce2SmbFlowData();
    ~Dce2SmbFlowData() override;

    static void init()
    {
        inspector_id = snort::FlowData::create_flow_data_id();
    }

public:
    static unsigned inspector_id;
    DCE2_SmbSsnData dce2_smb_session;
};

// Used for reassembled packets
#define DCE2_MOCK_HDR_LEN__SMB_CLI \
    (sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq))
#define DCE2_MOCK_HDR_LEN__SMB_SRV \
    (sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp))

DCE2_SmbSsnData* get_dce2_smb_session_data(snort::Flow*);

const char* get_smb_com_string(uint8_t);
#endif

