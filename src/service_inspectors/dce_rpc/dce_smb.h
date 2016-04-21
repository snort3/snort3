//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

//dce_smb.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB_H
#define DCE_SMB_H

#include "dce_common.h"
#include "dce_co.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "framework/counts.h"

#define DCE2_SMB_NAME "dce_smb"
#define DCE2_SMB_HELP "dce over smb inspection"
#define DCE2_SMB_RPKT_TYPE_MAX 4

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

#define DCE2_SMB_BAD_NBSS_TYPE_STR "SMB - Bad NetBIOS Session Service session type."
#define DCE2_SMB_BAD_TYPE_STR  "SMB - Bad SMB message type."
#define DCE2_SMB_BAD_ID_STR "SMB - Bad SMB Id (not \\xffSMB for SMB1 or not \\xfeSMB for SMB2)."
#define DCE2_SMB_BAD_WCT_STR "SMB - Bad word count or structure size."
#define DCE2_SMB_BAD_BCC_STR  "SMB - Bad byte count."
#define DCE2_SMB_BAD_FORM_STR  "SMB - Bad format type."
#define DCE2_SMB_BAD_OFF_STR  "SMB - Bad offset."
#define DCE2_SMB_TDCNT_ZE_STR  "SMB - Zero total data count."
#define DCE2_SMB_NB_LT_SMBHDR_STR "SMB - NetBIOS data length less than SMB header length."
#define DCE2_SMB_NB_LT_COM_STR   "SMB - Remaining NetBIOS data length less than command length."
#define DCE2_SMB_NB_LT_BCC_STR  "SMB - Remaining NetBIOS data length less than command byte count."
#define DCE2_SMB_NB_LT_DSIZE_STR \
    "SMB - Remaining NetBIOS data length less than command data size."
#define DCE2_SMB_TDCNT_LT_DSIZE_STR \
    "SMB - Remaining total data count less than this command data size."
#define DCE2_SMB_DSENT_GT_TDCNT_STR \
    "SMB - Total data sent (STDu64) greater than command total data expected."
#define DCE2_SMB_BCC_LT_DSIZE_STR   "SMB - Byte count less than command data size (STDu64)"
#define DCE2_SMB_INVALID_DSIZE_STR  "SMB - Invalid command data size for byte count."
#define DCE2_SMB_EXCESSIVE_TREE_CONNECTS_STR \
    "SMB - Excessive Tree Connect requests with pending Tree Connect responses."
#define DCE2_SMB_EXCESSIVE_READS_STR  "SMB - Excessive Read requests with pending Read responses."
#define DCE2_SMB_EXCESSIVE_CHAINING_STR  "SMB - Excessive command chaining."
#define DCE2_SMB_MULT_CHAIN_SS_STR   "SMB - Multiple chained tree connect requests."
#define DCE2_SMB_MULT_CHAIN_TC_STR   "SMB - Multiple chained tree connect requests."
#define DCE2_SMB_CHAIN_SS_LOGOFF_STR   "SMB - Chained/Compounded login followed by logoff."
#define DCE2_SMB_CHAIN_TC_TDIS_STR \
    "SMB - Chained/Compounded tree connect followed by tree disconnect."
#define DCE2_SMB_CHAIN_OPEN_CLOSE_STR \
    "SMB - Chained/Compounded open pipe followed by close pipe."
#define DCE2_SMB_INVALID_SHARE_STR   "SMB - Invalid share access."

#define DCE2_SMB_V1_STR  "SMB - Invalid SMB version 1 seen."
#define DCE2_SMB_V2_STR  "SMB - Invalid SMB version 2 seen."
#define DCE2_SMB_INVALID_BINDING_STR "SMB - Invalid user, tree connect, file binding."
#define DCE2_SMB2_EXCESSIVE_COMPOUNDING_STR  "SMB - Excessive command compounding."
#define DCE2_SMB_DCNT_ZERO_STR   "SMB - Zero data count."
#define DCE2_SMB_DCNT_MISMATCH_STR "SMB - Data count mismatch in command and format"
#define DCE2_SMB_MAX_REQS_EXCEEDED_STR  "SMB - Maximum number of outstanding requests exceeded."
#define DCE2_SMB_REQS_SAME_MID_STR "SMB - Outstanding requests with same MID."
#define DCE2_SMB_DEPR_DIALECT_NEGOTIATED_STR  "SMB - Deprecated dialect negotiated."
#define DCE2_SMB_DEPR_COMMAND_USED_STR   "SMB - Deprecated command used."
#define DCE2_SMB_UNUSUAL_COMMAND_USED_STR "SMB - Unusual command used."
#define DCE2_SMB_INVALID_SETUP_COUNT_STR  "SMB - Invalid setup count for command."
#define DCE2_SMB_MULTIPLE_NEGOTIATIONS_STR \
    "SMB - Client attempted multiple dialect negotiations on session."
#define DCE2_SMB_EVASIVE_FILE_ATTRS_STR \
    "SMB - Client attempted to create or set a file's attributes to readonly/hidden/system."

#define SMB_MAX_NUM_COMS   256

struct dce2SmbStats
{
/*  FIXIT-M
    PegCount sessions_autodetected;
#ifdef DEBUG
    PegCount autoports[65535][DCE2_TRANS_TYPE__MAX];
#endif
*/
    PegCount events;
    PegCount sessions_aborted;
    PegCount bad_autodetects;

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
    //  FIXIT-M
    /*uint64_t smb_com_stats[2][SMB_MAX_NUM_COMS];
    uint64_t smb_chained_stats[2][SMB_ANDX_COM__MAX][SMB_MAX_NUM_COMS];
    // The +1 is for codes beyond the range of the highest valid subcommand code
    // Indicates a bogus subcommand
    uint64_t smb_trans_subcom_stats[2][TRANS_SUBCOM_MAX+1];
    uint64_t smb_trans2_subcom_stats[2][TRANS2_SUBCOM_MAX+1];
    uint64_t smb_nt_transact_subcom_stats[2][NT_TRANSACT_SUBCOM_MAX+1];
    */
    PegCount smb_files_processed;
};

extern THREAD_LOCAL dce2SmbStats dce2_smb_stats;
extern THREAD_LOCAL Packet* dce2_smb_rpkt[DCE2_SMB_RPKT_TYPE_MAX];
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_main;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_session;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_new_session;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_detect;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_log;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_co_seg;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_co_frag;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_co_reass;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_co_ctx;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_seg;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_req;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_uid;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_tid;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_fid;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file_detect;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_file_api;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_fingerprint;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_smb_negotiate;

#define NBSS_SESSION_TYPE__MESSAGE            0x00
#define NBSS_SESSION_TYPE__REQUEST            0x81
#define NBSS_SESSION_TYPE__POS_RESPONSE       0x82
#define NBSS_SESSION_TYPE__NEG_RESPONSE       0x83
#define NBSS_SESSION_TYPE__RETARGET_RESPONSE  0x84
#define NBSS_SESSION_TYPE__KEEP_ALIVE         0x85

#define DCE2_SMB_ID   0xff534d42  /* \xffSMB */
#define DCE2_SMB2_ID  0xfe534d42  /* \xfeSMB */

/* SMB command codes */
#define SMB_COM_CREATE_DIRECTORY 0x00
#define SMB_COM_DELETE_DIRECTORY 0x01
#define SMB_COM_OPEN 0x02
#define SMB_COM_CREATE 0x03
#define SMB_COM_CLOSE 0x04
#define SMB_COM_FLUSH 0x05
#define SMB_COM_DELETE 0x06
#define SMB_COM_RENAME 0x07
#define SMB_COM_QUERY_INFORMATION 0x08
#define SMB_COM_SET_INFORMATION 0x09
#define SMB_COM_READ 0x0A
#define SMB_COM_WRITE 0x0B
#define SMB_COM_LOCK_BYTE_RANGE 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D
#define SMB_COM_CREATE_TEMPORARY 0x0E
#define SMB_COM_CREATE_NEW 0x0F
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1A
#define SMB_COM_READ_MPX 0x1B
#define SMB_COM_READ_MPX_SECONDARY 0x1C
#define SMB_COM_WRITE_RAW 0x1D
#define SMB_COM_WRITE_MPX 0x1E
#define SMB_COM_WRITE_MPX_SECONDARY 0x1F
#define SMB_COM_WRITE_COMPLETE 0x20
#define SMB_COM_QUERY_SERVER 0x21
#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25
#define SMB_COM_TRANSACTION_SECONDARY 0x26
#define SMB_COM_IOCTL 0x27
#define SMB_COM_IOCTL_SECONDARY 0x28
#define SMB_COM_COPY 0x29
#define SMB_COM_MOVE 0x2A
#define SMB_COM_ECHO 0x2B
#define SMB_COM_WRITE_AND_CLOSE 0x2C
#define SMB_COM_OPEN_ANDX 0x2D
#define SMB_COM_READ_ANDX 0x2E
#define SMB_COM_WRITE_ANDX 0x2F
#define SMB_COM_NEW_FILE_SIZE 0x30
#define SMB_COM_CLOSE_AND_TREE_DISC 0x31
#define SMB_COM_TRANSACTION2 0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_FIND_CLOSE2 0x34
#define SMB_COM_FIND_NOTIFY_CLOSE 0x35
#define SMB_COM_TREE_CONNECT 0x70
#define SMB_COM_TREE_DISCONNECT 0x71
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73
#define SMB_COM_LOGOFF_ANDX 0x74
#define SMB_COM_TREE_CONNECT_ANDX 0x75
#define SMB_COM_SECURITY_PACKAGE_ANDX 0x7E
#define SMB_COM_QUERY_INFORMATION_DISK 0x80
#define SMB_COM_SEARCH 0x81
#define SMB_COM_FIND 0x82
#define SMB_COM_FIND_UNIQUE 0x83
#define SMB_COM_FIND_CLOSE 0x84
#define SMB_COM_NT_TRANSACT 0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_NT_CREATE_ANDX 0xA2
#define SMB_COM_NT_CANCEL 0xA4
#define SMB_COM_NT_RENAME 0xA5
#define SMB_COM_OPEN_PRINT_FILE 0xC0
#define SMB_COM_WRITE_PRINT_FILE 0xC1
#define SMB_COM_CLOSE_PRINT_FILE 0xC2
#define SMB_COM_GET_PRINT_QUEUE 0xC3
#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA
#define SMB_COM_INVALID 0xFE
#define SMB_COM_NO_ANDX_COMMAND 0xFF

/* Size of word count field + Word count * 2 bytes + Size of byte count field */
#define SMB_COM_SIZE(wct)  (sizeof(uint8_t) + ((wct) * sizeof(uint16_t)) + sizeof(uint16_t))

#define SMB_FLG__TYPE  0x80
#define SMB_TYPE__REQUEST   0
#define SMB_TYPE__RESPONSE  1

#define SMB_FLG2__UNICODE      0x8000
#define SMB_FLG2__NT_CODES     0x4000

#define SMB_NT_STATUS_SEVERITY__SUCCESS        0
#define SMB_NT_STATUS_SEVERITY__INFORMATIONAL  1
#define SMB_NT_STATUS_SEVERITY__WARNING        2
#define SMB_NT_STATUS_SEVERITY__ERROR          3

#define SMB_NT_STATUS__SUCCESS                0x00000000
#define SMB_NT_STATUS__INVALID_DEVICE_REQUEST 0xc0000010
#define SMB_NT_STATUS__RANGE_NOT_LOCKED       0xc000007e
#define SMB_NT_STATUS__PIPE_BROKEN            0xc000014b
#define SMB_NT_STATUS__PIPE_DISCONNECTED      0xc00000b0

#define SMB_ERROR_CLASS__SUCCESS  0x00
#define SMB_ERROR_CLASS__ERRDOS   0x01
#define SMB_ERROR_CLASS__ERRSRV   0x02
#define SMB_ERROR_CLASS__ERRHRD   0x03
#define SMB_ERROR_CLASS__ERRXOS   0x04
#define SMB_ERROR_CLASS__ERRMX1   0xe1
#define SMB_ERROR_CLASS__ERRMX2   0xe2
#define SMB_ERROR_CLASS__ERRMX3   0xe3
#define SMB_ERROR_CLASS__ERRCMD   0xff

#define SMB_ERRSRV__INVALID_DEVICE      0x0007
#define SMB_ERRDOS__NOT_LOCKED          0x009e
#define SMB_ERRDOS__BAD_PIPE            0x00e6
#define SMB_ERRDOS__PIPE_NOT_CONNECTED  0x00e9
#define SMB_ERRDOS__MORE_DATA           0x00ea

#pragma pack(1)

/********************************************************************
 * NetBIOS Session Service header
 ********************************************************************/
struct NbssHdr
{
    uint8_t type;
    uint8_t flags;   /* Treat flags as the upper byte to length */
    uint16_t length;
};

struct SmbNtHdr
{
    uint8_t smb_idf[4];             /* contains 0xFF, 'SMB' */
    uint8_t smb_com;                /* command code */
    union
    {
        struct
        {
            uint8_t smb_class;      /* dos error class */
            uint8_t smb_res;        /* reserved for future */
            uint16_t smb_code;      /* dos error code */
        } smb_status;
        uint32_t nt_status;         /* nt status */
    } smb_status;
    uint8_t smb_flg;                /* flags */
    uint16_t smb_flg2;              /* flags */
    uint16_t smb_pid_high;
    uint64_t smb_signature;
    uint16_t smb_res;               /* reserved for future */
    uint16_t smb_tid;               /* tree id */
    uint16_t smb_pid;               /* caller's process id */
    uint16_t smb_uid;               /* authenticated user id */
    uint16_t smb_mid;               /* multiplex id */
};

struct SmbWriteAndXReq   /* smb_wct = 12 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin write */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_wmode;      /* write mode:
                                bit0 - complete write before return (write through)
                                bit1 - return smb_remaining (pipes/devices only)
                                bit2 - use WriteRawNamedPipe (pipes only)
                                bit3 - this is the start of a message (pipes only) */
    uint16_t smb_countleft;  /* bytes remaining to write to satisfy user’s request */
    uint16_t smb_dsize_high; /* high bytes of data size */
    uint16_t smb_dsize;      /* number of data bytes in buffer (min value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
};

struct SmbReadAndXResp    /* smb_wct = 12 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint32_t smb_rsvd;       /* reserved */
    uint16_t smb_dsize;      /* number of data bytes (minimum value = 0) */
    uint16_t smb_doff;       /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_dsize_high; /* high bytes of data size */
    uint32_t smb_rsvd1;      /* reserved */
    uint32_t smb_rsvd2;      /* reserved */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
};

/* For server empty respones indicating client error or interim response */
struct SmbEmptyCom
{
    uint8_t smb_wct;     /* value = 0 */
    uint16_t smb_bcc;    /* value = 0 */
};

#pragma pack()
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

struct DCE2_SmbFileTracker
{
    int fid;   // A signed integer so it can be set to sentinel
    uint16_t uid;
    uint16_t tid;
    bool is_ipc;
    char* file_name;

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

#ifdef ACTIVE_RESPONSE
    DCE2_SmbFileTracker* fb_ftracker;
    bool block_pdus;
#endif

    // Maximum file depth as returned from file API
    int64_t max_file_depth;
};

/********************************************************************
 * Common fields to all commands
 ********************************************************************/
struct SmbCommon
{
    uint8_t smb_wct;
};

inline uint8_t SmbWct(const SmbCommon* hdr)
{
    return hdr->smb_wct;
}

/* Common fields to all AndX commands */
struct SmbAndXCommon
{
    uint8_t smb_wct;
    uint8_t smb_com2;      /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;      /* reserved (must be zero) */
    uint16_t smb_off2;     /* offset (from SMB hdr start) to next cmd (@smb_wct) */
};

inline uint32_t NbssLen(const NbssHdr* nb)
{
    /* Treat first bit of flags as the upper byte to length */
    return ((nb->flags & 0x01) << 16) | ntohs(nb->length);
}

inline uint8_t NbssType(const NbssHdr* nb)
{
    return nb->type;
}

inline uint32_t SmbId(const SmbNtHdr* hdr)
{
    uint8_t* idf = (uint8_t*)hdr->smb_idf;
    return *idf << 24 | *(idf + 1) << 16 | *(idf + 2) << 8 | *(idf + 3);
}

inline uint8_t SmbEmptyComWct(const SmbEmptyCom* ec)
{
    return ec->smb_wct;
}

inline uint16_t SmbBcc(const uint8_t* ptr, uint16_t com_size)
{
    /* com_size must be at least the size of the command encasing */
    if (com_size < sizeof(SmbEmptyCom))
        return 0;

    return extract_16bits(ptr + com_size - sizeof(uint16_t));
}

inline uint16_t SmbEmptyComBcc(const SmbEmptyCom* ec)
{
    return ntohs(ec->smb_bcc);
}

inline int SmbType(const SmbNtHdr* hdr)
{
    if (hdr->smb_flg & SMB_FLG__TYPE)
        return SMB_TYPE__RESPONSE;

    return SMB_TYPE__REQUEST;
}

class Dce2SmbFlowData : public FlowData
{
public:
    Dce2SmbFlowData();
    ~Dce2SmbFlowData();

    static void init()
    {
        flow_id = FlowData::get_flow_id();
    }

public:
    static unsigned flow_id;
    DCE2_SmbSsnData dce2_smb_session;
};

// Used for reassembled packets
#define DCE2_MOCK_HDR_LEN__SMB_CLI \
    (sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbWriteAndXReq))
#define DCE2_MOCK_HDR_LEN__SMB_SRV \
    (sizeof(NbssHdr) + sizeof(SmbNtHdr) + sizeof(SmbReadAndXResp))

DCE2_SmbSsnData* get_dce2_smb_session_data(Flow*);

#endif

