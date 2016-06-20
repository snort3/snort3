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

#define SMB_FILE_TYPE_DISK               0x0000
#define SMB_FILE_TYPE_BYTE_MODE_PIPE     0x0001
#define SMB_FILE_TYPE_MESSAGE_MODE_PIPE  0x0002
#define SMB_FILE_TYPE_PRINTER            0x0003
#define SMB_FILE_TYPE_COMMON_DEVICE      0x0004

#define SMB_FILE_ATTRIBUTE_NORMAL       0x0000
#define SMB_FILE_ATTRIBUTE_READONLY     0x0001
#define SMB_FILE_ATTRIBUTE_HIDDEN       0x0002
#define SMB_FILE_ATTRIBUTE_SYSTEM       0x0004
#define SMB_FILE_ATTRIBUTE_VOLUME       0x0008
#define SMB_FILE_ATTRIBUTE_DIRECTORY    0x0010
#define SMB_FILE_ATTRIBUTE_ARCHIVE      0x0020
#define SMB_SEARCH_ATTRIBUTE_READONLY   0x0100
#define SMB_SEARCH_ATTRIBUTE_HIDDEN     0x0200
#define SMB_SEARCH_ATTRIBUTE_SYSTEM     0x0400
#define SMB_SEARCH_ATTRIBUTE_DIRECTORY  0x1000
#define SMB_SEARCH_ATTRIBUTE_ARCHIVE    0x2000
#define SMB_FILE_ATTRIBUTE_OTHER        0xC8C0   // Reserved

#define SMB_EXT_FILE_ATTR_READONLY    0x00000001
#define SMB_EXT_FILE_ATTR_HIDDEN      0x00000002
#define SMB_EXT_FILE_ATTR_SYSTEM      0x00000004
#define SMB_EXT_FILE_ATTR_DIRECTORY   0x00000010
#define SMB_EXT_FILE_ATTR_ARCHIVE     0x00000020
#define SMB_EXT_FILE_ATTR_NORMAL      0x00000080
#define SMB_EXT_FILE_ATTR_TEMPORARY   0x00000100
#define SMB_EXT_FILE_ATTR_COMPRESSED  0x00000800
#define SMB_EXT_FILE_POSIX_SEMANTICS  0x01000000
#define SMB_EXT_FILE_BACKUP_SEMANTICS 0x02000000
#define SMB_EXT_FILE_DELETE_ON_CLOSE  0x04000000
#define SMB_EXT_FILE_SEQUENTIAL_SCAN  0x08000000
#define SMB_EXT_FILE_RANDOM_ACCESS    0x10000000
#define SMB_EXT_FILE_NO_BUFFERING     0x20000000
#define SMB_EXT_FILE_WRITE_THROUGH    0x80000000

struct dce2SmbStats
{
/*  FIXIT-M add array based peg counts
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

// MS-FSCC Section 2.1.5 - Pathname
#define DCE2_SMB_MAX_PATH_LEN  32760
#define DCE2_SMB_MAX_COMP_LEN    255

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

/* For server empty respones indicating client error or interim response */
struct SmbEmptyCom
{
    uint8_t smb_wct;     /* value = 0 */
    uint16_t smb_bcc;    /* value = 0 */
};

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

enum SmbTransactionSubcommand
{
    TRANS_UNKNOWN_0000             = 0x0000,
    TRANS_SET_NMPIPE_STATE         = 0x0001,
    TRANS_UNKNOWN_0002             = 0x0002,
    TRANS_UNKNOWN_0003             = 0x0003,
    TRANS_UNKNOWN_0004             = 0x0004,
    TRANS_UNKNOWN_0005             = 0x0005,
    TRANS_UNKNOWN_0006             = 0x0006,
    TRANS_UNKNOWN_0007             = 0x0007,
    TRANS_UNKNOWN_0008             = 0x0008,
    TRANS_UNKNOWN_0009             = 0x0009,
    TRANS_UNKNOWN_000A             = 0x000A,
    TRANS_UNKNOWN_000B             = 0x000B,
    TRANS_UNKNOWN_000C             = 0x000C,
    TRANS_UNKNOWN_000D             = 0x000D,
    TRANS_UNKNOWN_000E             = 0x000E,
    TRANS_UNKNOWN_000F             = 0x000F,
    TRANS_UNKNOWN_0010             = 0x0010,
    TRANS_RAW_READ_NMPIPE          = 0x0011,
    TRANS_UNKNOWN_0012             = 0x0012,
    TRANS_UNKNOWN_0013             = 0x0013,
    TRANS_UNKNOWN_0014             = 0x0014,
    TRANS_UNKNOWN_0015             = 0x0015,
    TRANS_UNKNOWN_0016             = 0x0016,
    TRANS_UNKNOWN_0017             = 0x0017,
    TRANS_UNKNOWN_0018             = 0x0018,
    TRANS_UNKNOWN_0019             = 0x0019,
    TRANS_UNKNOWN_001A             = 0x001A,
    TRANS_UNKNOWN_001B             = 0x001B,
    TRANS_UNKNOWN_001C             = 0x001C,
    TRANS_UNKNOWN_001D             = 0x001D,
    TRANS_UNKNOWN_001E             = 0x001E,
    TRANS_UNKNOWN_001F             = 0x001F,
    TRANS_UNKNOWN_0020             = 0x0020,
    TRANS_QUERY_NMPIPE_STATE       = 0x0021,
    TRANS_QUERY_NMPIPE_INFO        = 0x0022,
    TRANS_PEEK_NMPIPE              = 0x0023,
    TRANS_UNKNOWN_0024             = 0x0024,
    TRANS_UNKNOWN_0025             = 0x0025,
    TRANS_TRANSACT_NMPIPE          = 0x0026,
    TRANS_UNKNOWN_0027             = 0x0027,
    TRANS_UNKNOWN_0028             = 0x0028,
    TRANS_UNKNOWN_0029             = 0x0029,
    TRANS_UNKNOWN_002A             = 0x002A,
    TRANS_UNKNOWN_002B             = 0x002B,
    TRANS_UNKNOWN_002C             = 0x002C,
    TRANS_UNKNOWN_002D             = 0x002D,
    TRANS_UNKNOWN_002E             = 0x002E,
    TRANS_UNKNOWN_002F             = 0x002F,
    TRANS_UNKNOWN_0030             = 0x0030,
    TRANS_RAW_WRITE_NMPIPE         = 0x0031,
    TRANS_UNKNOWN_0032             = 0x0032,
    TRANS_UNKNOWN_0033             = 0x0033,
    TRANS_UNKNOWN_0034             = 0x0034,
    TRANS_UNKNOWN_0035             = 0x0035,
    TRANS_READ_NMPIPE              = 0x0036,
    TRANS_WRITE_NMPIPE             = 0x0037,
    TRANS_UNKNOWN_0038             = 0x0038,
    TRANS_UNKNOWN_0039             = 0x0039,
    TRANS_UNKNOWN_003A             = 0x003A,
    TRANS_UNKNOWN_003B             = 0x003B,
    TRANS_UNKNOWN_003C             = 0x003C,
    TRANS_UNKNOWN_003D             = 0x003D,
    TRANS_UNKNOWN_003E             = 0x003E,
    TRANS_UNKNOWN_003F             = 0x003F,
    TRANS_UNKNOWN_0040             = 0x0040,
    TRANS_UNKNOWN_0041             = 0x0041,
    TRANS_UNKNOWN_0042             = 0x0042,
    TRANS_UNKNOWN_0043             = 0x0043,
    TRANS_UNKNOWN_0044             = 0x0044,
    TRANS_UNKNOWN_0045             = 0x0045,
    TRANS_UNKNOWN_0046             = 0x0046,
    TRANS_UNKNOWN_0047             = 0x0047,
    TRANS_UNKNOWN_0048             = 0x0048,
    TRANS_UNKNOWN_0049             = 0x0049,
    TRANS_UNKNOWN_004A             = 0x004A,
    TRANS_UNKNOWN_004B             = 0x004B,
    TRANS_UNKNOWN_004C             = 0x004C,
    TRANS_UNKNOWN_004D             = 0x004D,
    TRANS_UNKNOWN_004E             = 0x004E,
    TRANS_UNKNOWN_004F             = 0x004F,
    TRANS_UNKNOWN_0050             = 0x0050,
    TRANS_UNKNOWN_0051             = 0x0051,
    TRANS_UNKNOWN_0052             = 0x0052,
    TRANS_WAIT_NMPIPE              = 0x0053,
    TRANS_CALL_NMPIPE              = 0x0054,
    TRANS_SUBCOM_MAX               = 0x0055
};

enum SmbTransaction2Subcommand
{
    TRANS2_OPEN2                        = 0x0000,
    TRANS2_FIND_FIRST2                  = 0x0001,
    TRANS2_FIND_NEXT2                   = 0x0002,
    TRANS2_QUERY_FS_INFORMATION         = 0x0003,
    TRANS2_SET_FS_INFORMATION           = 0x0004,
    TRANS2_QUERY_PATH_INFORMATION       = 0x0005,
    TRANS2_SET_PATH_INFORMATION         = 0x0006,
    TRANS2_QUERY_FILE_INFORMATION       = 0x0007,
    TRANS2_SET_FILE_INFORMATION         = 0x0008,
    TRANS2_FSCTL                        = 0x0009,
    TRANS2_IOCTL2                       = 0x000A,
    TRANS2_FIND_NOTIFY_FIRST            = 0x000B,
    TRANS2_FIND_NOTIFY_NEXT             = 0x000C,
    TRANS2_CREATE_DIRECTORY             = 0x000D,
    TRANS2_SESSION_SETUP                = 0x000E,
    TRANS2_UNKNOWN_000F                 = 0x000F,
    TRANS2_GET_DFS_REFERRAL             = 0x0010,
    TRANS2_REPORT_DFS_INCONSISTENCY     = 0x0011,
    TRANS2_SUBCOM_MAX                   = 0x0012
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

#pragma pack()

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
 * Structures and inline accessor functions
 ********************************************************************/
/* Pack the structs since we'll be laying them on top of packet data */
#pragma pack(1)

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

    return alignedNtohs((uint16_t*)(ptr + com_size - sizeof(uint16_t)));
}

inline uint16_t SmbEmptyComBcc(const SmbEmptyCom* ec)
{
    return alignedNtohs(&ec->smb_bcc);
}

inline int SmbType(const SmbNtHdr* hdr)
{
    if (hdr->smb_flg & SMB_FLG__TYPE)
        return SMB_TYPE__RESPONSE;

    return SMB_TYPE__REQUEST;
}

inline uint8_t SmbAndXCom2(const SmbAndXCommon* andx)
{
    return andx->smb_com2;
}

inline uint16_t SmbAndXOff2(const SmbAndXCommon* andx)
{
    return alignedNtohs(&andx->smb_off2);
}

/* SMB formats (smb_fmt) Dialect, Pathname and ASCII are all
 * NULL terminated ASCII strings unless Unicode is specified
 * in the NT LM 1.0 SMB header in which case they are NULL
 * terminated unicode strings
 */
#define SMB_FMT__DATA_BLOCK  1
#define SMB_FMT__DIALECT     2
#define SMB_FMT__ASCII       4

inline bool SmbFmtDataBlock(const uint8_t fmt)
{
    return fmt == SMB_FMT__DATA_BLOCK ? true : false;
}

inline bool SmbFmtDialect(const uint8_t fmt)
{
    return fmt == SMB_FMT__DIALECT ? true : false;
}

inline bool SmbFmtAscii(const uint8_t fmt)
{
    return fmt == SMB_FMT__ASCII ? true : false;
}

/********************************************************************
 * SMB_COM_OPEN
 ********************************************************************/
struct SmbOpenReq   /* smb_wct = 2 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_mode;    /* r/w/share */
    uint16_t smb_attr;    /* attribute */
    uint16_t smb_bcc;     /* min = 2 */
};

struct SmbOpenResp   /* smb_wct = 7 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_attr;    /* attribute */
    uint32_t smb_time;    /* time1 low */
    uint32_t smb_file_size;   /* file size low */
    uint16_t smb_access;  /* access allowed */
    uint16_t smb_bcc;     /* must be 0 */
};

#define SMB_OPEN_ACCESS_MODE__READ        0x0000
#define SMB_OPEN_ACCESS_MODE__WRITE       0x0001
#define SMB_OPEN_ACCESS_MODE__READ_WRITE  0x0002
#define SMB_OPEN_ACCESS_MODE__EXECUTE     0x0003

inline uint16_t SmbOpenRespFid(const SmbOpenResp* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

inline uint32_t SmbOpenRespFileSize(const SmbOpenResp* resp)
{
    return extract_32bits((uint8_t*)&resp->smb_file_size);
}

inline uint16_t SmbOpenRespFileAttrs(const SmbOpenResp* resp)
{
    return alignedNtohs(&resp->smb_attr);
}

inline bool SmbFileAttrsDirectory(const uint16_t file_attrs)
{
    if (file_attrs & SMB_FILE_ATTRIBUTE_DIRECTORY)
        return true;
    return false;
}

inline uint16_t SmbOpenRespAccessMode(const SmbOpenResp* resp)
{
    return alignedNtohs(&resp->smb_access);
}

inline bool SmbOpenForWriting(const uint16_t access_mode)
{
    return access_mode == SMB_OPEN_ACCESS_MODE__WRITE;
}

/********************************************************************
 * SMB_COM_CREATE
 ********************************************************************/
struct SmbCreateReq   /* smb_wct = 3 */
{
    uint8_t smb_wct;
    uint16_t smb_file_attrs;
    uint32_t smb_creation_time;
    uint16_t smb_bcc;
};

struct SmbCreateResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;
    uint16_t smb_fid;
    uint16_t smb_bcc;
};

inline uint16_t SmbCreateReqFileAttrs(const SmbCreateReq* req)
{
    return alignedNtohs(&req->smb_file_attrs);
}

inline bool SmbAttrDirectory(const uint16_t file_attrs)
{
    if (file_attrs & SMB_FILE_ATTRIBUTE_DIRECTORY)
        return true;
    return false;
}

inline uint16_t SmbCreateRespFid(const SmbCreateResp* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_CLOSE
 ********************************************************************/
struct SmbCloseReq   /* smb_wct = 3 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_tlow;    /* time low */
    uint16_t smb_thigh;   /* time high */
    uint16_t smb_bcc;     /* must be 0 */
};

struct SmbCloseResp   /* smb_wct = 0 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbCloseReqFid(const SmbCloseReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

/********************************************************************
 * SMB_COM_READ
 ********************************************************************/
struct SmbReadReq   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_cnt;     /* count of bytes */
    uint32_t smb_off;     /* offset */
    uint16_t smb_left;    /* count left */
    uint16_t smb_bcc;     /* must be 0 */
};

struct SmbReadResp   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_res[4];  /* reserved (MBZ) */
    uint16_t smb_bcc;     /* length of data + 3 */
};

inline uint16_t SmbReadReqFid(const SmbReadReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

inline uint32_t SmbReadReqOffset(const SmbReadReq* req)
{
    return alignedNtohl(&req->smb_off);
}

inline uint16_t SmbReadRespCount(const SmbReadResp* resp)
{
    return alignedNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_WRITE
 ********************************************************************/
struct SmbWriteReq   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;     /* file handle */
    uint16_t smb_cnt;     /* count of bytes */
    uint32_t smb_offset;  /* file offset in bytes */
    uint16_t smb_left;    /* count left */
    uint16_t smb_bcc;     /* length of data + 3 */
};

struct SmbWriteResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbWriteReqFid(const SmbWriteReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteReqCount(const SmbWriteReq* req)
{
    return alignedNtohs(&req->smb_cnt);
}

inline uint32_t SmbWriteReqOffset(const SmbWriteReq* req)
{
    return alignedNtohl(&req->smb_offset);
}

inline uint16_t SmbWriteRespCount(const SmbWriteResp* resp)
{
    return alignedNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_CREATE_NEW
 ********************************************************************/
struct SmbCreateNewReq   /* smb_wct = 3 */
{
    uint8_t smb_wct;
    uint16_t smb_file_attrs;
    uint32_t smb_creation_time;
    uint16_t smb_bcc;
};

struct SmbCreateNewResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;
    uint16_t smb_fid;
    uint16_t smb_bcc;
};

inline uint16_t SmbCreateNewReqFileAttrs(const SmbCreateNewReq* req)
{
    return alignedNtohs(&req->smb_file_attrs);
}

inline uint16_t SmbCreateNewRespFid(const SmbCreateNewResp* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

/********************************************************************
 * SMB_COM_LOCK_AND_READ
 ********************************************************************/
struct SmbLockAndReadReq   /* smb_wct = 5 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_fid;
    uint16_t smb_cnt;
    uint32_t smb_read_offset;
    uint16_t smb_remaining;
    uint16_t smb_bcc;     /* must be 0 */
};

struct SmbLockAndReadResp   /* smb_wct = 5 */
{
    uint8_t smb_wct;
    uint16_t smb_cnt;
    uint16_t reserved[4];
    uint16_t smb_bcc;
};

inline uint16_t SmbLockAndReadReqFid(const SmbLockAndReadReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

inline uint32_t SmbLockAndReadReqOffset(const SmbLockAndReadReq* req)
{
    return alignedNtohl(&req->smb_read_offset);
}

inline uint16_t SmbLockAndReadRespCount(const SmbLockAndReadResp* resp)
{
    return alignedNtohs(&resp->smb_cnt);
}

/********************************************************************
 * SMB_COM_WRITE_AND_UNLOCK
 ********************************************************************/
struct SmbWriteAndUnlockReq
{
    uint8_t smb_wct;
    uint16_t smb_fid;
    uint16_t smb_cnt;
    uint32_t smb_write_offset;
    uint16_t smb_estimate_of_remaining;
    uint16_t smb_bcc;
};

struct SmbWriteAndUnlockResp   /* smb_wct = 1 */
{
    uint8_t smb_wct;      /* count of 16-bit words that follow */
    uint16_t smb_cnt;     /* count */
    uint16_t smb_bcc;     /* must be 0 */
};

inline uint16_t SmbWriteAndUnlockReqFid(const SmbWriteAndUnlockReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteAndUnlockReqCount(const SmbWriteAndUnlockReq* req)
{
    return alignedNtohs(&req->smb_cnt);
}

inline uint32_t SmbWriteAndUnlockReqOffset(const SmbWriteAndUnlockReq* req)
{
    return alignedNtohl(&req->smb_write_offset);
}

/********************************************************************
 * SMB_COM_OPEN_ANDX
 ********************************************************************/
struct SmbOpenAndXReq   /* smb_wct = 15 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_flags;      /* additional information:
                                bit 0 - if set, return additional information
                                bit 1 - if set, set single user total file lock (if only access)
                                bit 2 - if set, the server should notify the consumer on any
                                        action which can modify the file (delete, setattrib,
                                        rename, etc.). if not set, the server need only notify
                                        the consumer on another open request. This bit only has
                                        meaning if bit 1 is set. */
    uint16_t smb_mode;       /* file open mode */
    uint16_t smb_sattr;      /* search attributes */
    uint16_t smb_attr;       /* file attributes (for create) */
    uint32_t smb_time;       /* create time */
    uint16_t smb_ofun;       /* open function */
    uint32_t smb_size;       /* bytes to reserve on "create" or "truncate" */
    uint32_t smb_timeout;    /* max milliseconds to wait for resource to open */
    uint32_t smb_rsvd;       /* reserved (must be zero) */
    uint16_t smb_bcc;        /* minimum value = 1 */
};

struct SmbOpenAndXResp   /* smb_wct = 15 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint16_t smb_attribute;  /* attributes of file or device */
    uint32_t smb_time;       /* last modification time */
    uint32_t smb_size;       /* current file size */
    uint16_t smb_access;     /* access permissions actually allowed */
    uint16_t smb_type;       /* file type */
    uint16_t smb_state;      /* state of IPC device (e.g. pipe) */
    uint16_t smb_action;     /* action taken */
    uint32_t smb_fileid;     /* server unique file id */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */
};

inline uint32_t SmbOpenAndXReqAllocSize(const SmbOpenAndXReq* req)
{
    return alignedNtohl(&req->smb_size);
}

inline uint16_t SmbOpenAndXReqFileAttrs(const SmbOpenAndXReq* req)
{
    return alignedNtohs(&req->smb_attr);
}

inline uint16_t SmbOpenAndXRespFid(const SmbOpenAndXResp* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

inline uint16_t SmbOpenAndXRespFileAttrs(const SmbOpenAndXResp* resp)
{
    return alignedNtohs(&resp->smb_attribute);
}

inline uint32_t SmbOpenAndXRespFileSize(const SmbOpenAndXResp* resp)
{
    return alignedNtohl(&resp->smb_size);
}

inline uint16_t SmbOpenAndXRespResourceType(const SmbOpenAndXResp* resp)
{
    return alignedNtohs(&resp->smb_type);
}

#define SMB_OPEN_RESULT__EXISTED    0x0001
#define SMB_OPEN_RESULT__CREATED    0x0002
#define SMB_OPEN_RESULT__TRUNCATED  0x0003

inline uint16_t SmbOpenAndXRespOpenResults(const SmbOpenAndXResp* resp)
{
    return alignedNtohs(&resp->smb_action);
}

inline bool SmbOpenResultRead(const uint16_t open_results)
{
    return ((open_results & 0x00FF) == SMB_OPEN_RESULT__EXISTED);
}

inline bool SmbResourceTypeDisk(const uint16_t resource_type)
{
    return resource_type == SMB_FILE_TYPE_DISK;
}

/********************************************************************
 * SMB_COM_READ_ANDX
 ********************************************************************/
struct SmbReadAndXReq   /* smb_wct = 10 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return */
    uint16_t smb_mincnt;     /* min number of bytes to return */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_countleft;  /* bytes remaining to satisfy user’s request */
    uint16_t smb_bcc;        /* value = 0 */
};

struct SmbReadAndXExtReq   /* smb_wct = 12 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* low offset in file to begin read */
    uint16_t smb_maxcnt;     /* max number of bytes to return */
    uint16_t smb_mincnt;     /* min number of bytes to return */
    uint32_t smb_timeout;    /* number of milliseconds to wait for completion */
    uint16_t smb_countleft;  /* bytes remaining to satisfy user’s request */
    uint32_t smb_off_high;   /* high offset in file to begin read */
    uint16_t smb_bcc;        /* value = 0 */
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

inline uint16_t SmbReadAndXReqFid(const SmbReadAndXReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

inline uint64_t SmbReadAndXReqOffset(const SmbReadAndXExtReq* req)
{
    if (req->smb_wct == 10)
        return (uint64_t)alignedNtohl(&req->smb_offset);
    return (uint64_t)alignedNtohl(&req->smb_off_high) << 32 | (uint64_t)alignedNtohl(
        &req->smb_offset);
}

inline uint16_t SmbReadAndXRespDataOff(const SmbReadAndXResp* req)
{
    return alignedNtohs(&req->smb_doff);
}

inline uint32_t SmbReadAndXRespDataCnt(const SmbReadAndXResp* resp)
{
    return (uint32_t)alignedNtohs(&resp->smb_dsize_high) << 16 | (uint32_t)alignedNtohs(
        &resp->smb_dsize);
}

/********************************************************************
 * SMB_COM_WRITE_ANDX
 ********************************************************************/
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

struct SmbWriteAndXExtReq   /* smb_wct = 14 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_fid;        /* file handle */
    uint32_t smb_offset;     /* low offset in file to begin write */
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
    uint32_t smb_off_high;   /* high offset in file to begin write */
    uint16_t smb_bcc;        /* total bytes (including pad bytes) following */
};

struct SmbWriteAndXResp   /* smb_wct = 6 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;        /* reserved (pad to word) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_count;      /* number of bytes written */
    uint16_t smb_remaining;  /* bytes remaining to be read (pipes/devices only) */
    uint16_t smb_count_high; /* high order bytes of data count */
    uint16_t smb_rsvd;       /* reserved */
    uint16_t smb_bcc;        /* value = 0 */
};

inline uint16_t SmbWriteAndXReqFid(const SmbWriteAndXReq* req)
{
    return alignedNtohs(&req->smb_fid);
}

inline uint16_t SmbWriteAndXReqDataOff(const SmbWriteAndXReq* req)
{
    return alignedNtohs(&req->smb_doff);
}

inline uint16_t SmbWriteAndXReqRemaining(const SmbWriteAndXReq* req)
{
    return alignedNtohs(&req->smb_countleft);
}

inline uint64_t SmbWriteAndXReqOffset(const SmbWriteAndXExtReq* req)
{
    if (req->smb_wct == 12)
        return (uint64_t)alignedNtohl(&req->smb_offset);
    return (uint64_t)alignedNtohl(&req->smb_off_high) << 32 | (uint64_t)alignedNtohl(
        &req->smb_offset);
}

inline uint32_t SmbWriteAndXReqDataCnt(const SmbWriteAndXReq* req)
{
    return (uint32_t)alignedNtohs(&req->smb_dsize_high) << 16 | (uint32_t)alignedNtohs(
        &req->smb_dsize);
}

inline uint16_t SmbWriteAndXReqWriteMode(const SmbWriteAndXReq* req)
{
    return alignedNtohs(&req->smb_wmode);
}

inline bool SmbWriteAndXReqStartRaw(const SmbWriteAndXReq* req)
{
    return ((alignedNtohs(&req->smb_wmode) & 0x000c) == 0x000c) ? true : false;
}

inline bool SmbWriteAndXReqRaw(const SmbWriteAndXReq* req)
{
    return ((alignedNtohs(&req->smb_wmode) & 0x000c) == 0x0004) ? true : false;
}

inline uint16_t SmbWriteAndXRespCnt(const SmbWriteAndXResp* resp)
{
    return alignedNtohs(&resp->smb_count);
}

/********************************************************************
 * SMB_COM_SESSION_SETUP_ANDX
 ********************************************************************/
struct SmbLm10_SessionSetupAndXReq   /* smb_wct = 10 */
{
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint8_t smb_com2;      /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;      /* reserved (must be zero) */
    uint16_t smb_off2;     /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_bufsize;  /* the consumers max buffer size */
    uint16_t smb_mpxmax;   /* actual maximum multiplexed pending requests */
    uint16_t smb_vc_num;   /* 0 = first (only), non zero - additional VC number */
    uint32_t smb_sesskey;  /* Session Key (valid only if smb_vc_num != 0) */
    uint16_t smb_apasslen; /* size of account password (smb_apasswd) */
    uint32_t smb_rsvd;     /* reserved */
    uint16_t smb_bcc;      /* minimum value = 0 */
};

inline uint16_t SmbSessionSetupAndXReqMaxMultiplex(const SmbLm10_SessionSetupAndXReq* req)
{
    return alignedNtohs(&req->smb_mpxmax);
}

/********************************************************************
 * SMB_COM_NEGOTIATE
 ********************************************************************/
/* This is the Lanman response */
struct SmbLm10_NegotiateProtocolResp   /* smb_wct = 13 */
{
    uint8_t smb_wct;        /* count of 16-bit words that follow */
    uint16_t smb_index;     /* index identifying dialect selected */
    uint16_t smb_secmode;   /* security mode:
                               bit 0, 1 = User level, 0 = Share level
                               bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxxmt;    /* max transmit buffer size server supports, 1K min */
    uint16_t smb_maxmux;    /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;    /* max VCs per server/consumer session supported */
    uint16_t smb_blkmode;   /* block read/write mode support:
                               bit 0, Read Block Raw supported (65535 bytes max)
                               bit 1, Write Block Raw supported (65535 bytes max) */
    uint32_t smb_sesskey;   /* Session Key (unique token identifying session) */
    uint16_t smb_srv_time;  /* server's current time (hhhhh mmmmmm xxxxx) */
    uint16_t smb_srv_tzone; /* server's current data (yyyyyyy mmmm ddddd) */
    uint32_t smb_rsvd;      /* reserved */
    uint16_t smb_bcc;       /* value = (size of smb_cryptkey) */
};

/* This is the NT response */
struct SmbNt_NegotiateProtocolResp     /* smb_wct = 17 */
{
    uint8_t smb_wct;            /* count of 16-bit words that follow */
    uint16_t smb_index;         /* index identifying dialect selected */
    uint8_t smb_secmode;        /* security mode:
                                   bit 0, 1 = User level, 0 = Share level
                                   bit 1, 1 = encrypt passwords, 0 = do not encrypt passwords */
    uint16_t smb_maxmux;        /* max pending multiplexed requests server supports */
    uint16_t smb_maxvcs;        /* max VCs per server/consumer session supported */
    uint32_t smb_maxbuf;        /* maximum buffer size supported */
    uint32_t smb_maxraw;        /* maximum raw buffer size supported */
    uint32_t smb_sesskey;       /* Session Key (unique token identifying session) */
    uint32_t smb_cap;           /* capabilities */
    struct
    {
        uint32_t low_time;
        int32_t high_time;
    } smb_srv_time;             /* server time */
    uint16_t smb_srv_tzone;     /* server's current data (yyyyyyy mmmm ddddd) */
    uint8_t smb_challenge_len;  /* Challenge length */
    uint16_t smb_bcc;           /* value = (size of smb_cryptkey) */
};

inline uint16_t SmbLm_NegotiateRespMaxMultiplex(const SmbLm10_NegotiateProtocolResp* resp)
{
    return alignedNtohs(&resp->smb_maxmux);
}

inline uint16_t SmbNt_NegotiateRespMaxMultiplex(const SmbNt_NegotiateProtocolResp* resp)
{
    return alignedNtohs(&resp->smb_maxmux);
}

/*********************************************************************
 * SMB_COM_TREE_CONNECT_ANDX
 *********************************************************************/
struct SmbTreeConnectAndXReq   /* smb_wct = 4 */
{
    uint8_t smb_wct;         /* count of 16-bit words that follow */
    uint8_t smb_com2;        /* secondary (X) command, 0xFF = none */
    uint8_t smb_reh2;        /* reserved (must be zero) */
    uint16_t smb_off2;       /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint16_t smb_flags;      /* additional information:
                                bit 0 - if set, disconnect TID in current smb_tid */
    uint16_t smb_spasslen;   /* length of smb_spasswd */
    uint16_t smb_bcc;        /* minimum value = 3 */
};

inline uint16_t SmbTreeConnectAndXReqPassLen(const SmbTreeConnectAndXReq* req)
{
    return alignedNtohs(&req->smb_spasslen);
}

/********************************************************************
 * SMB_COM_NT_TRANSACT
 ********************************************************************/
#define SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY     0x00000004

/********************************************************************
 * SMB_COM_NT_CREATE_ANDX
 ********************************************************************/
#define SMB_CREATE_DISPOSITSION__FILE_SUPERCEDE      0x00000000
#define SMB_CREATE_DISPOSITSION__FILE_OPEN           0x00000001
#define SMB_CREATE_DISPOSITSION__FILE_CREATE         0x00000002
#define SMB_CREATE_DISPOSITSION__FILE_OPEN_IF        0x00000003
#define SMB_CREATE_DISPOSITSION__FILE_OVERWRITE      0x00000004
#define SMB_CREATE_DISPOSITSION__FILE_OVERWRITE_IF   0x00000005

struct SmbNtCreateAndXReq   /* smb_wct = 24 */
{
    uint8_t smb_wct;            /* count of 16-bit words that follow */
    uint8_t smb_com2;           /* secondary (X) command, 0xFF = none */
    uint8_t smb_res2;           /* reserved (pad to word) */
    uint16_t smb_off2;          /* offset (from SMB hdr start) to next cmd (@smb_wct) */
    uint8_t smb_res;            /* reserved */
    uint16_t smb_name_len;      /* length of name of file */
    uint32_t smb_flags;         /* flags */
    uint32_t smb_root_fid;      /* fid for previously opened directory */
    uint32_t smb_access;        /* specifies the type of file access */
    uint64_t smb_alloc_size;    /* initial allocation size of the file */
    uint32_t smb_file_attrs;    /* specifies the file attributes for the file */
    uint32_t smb_share_access;  /* the type of share access */
    uint32_t smb_create_disp;   /* actions to take if file does or does not exist */
    uint32_t smb_create_opts;   /* options used when creating or opening file */
    uint32_t smb_impersonation_level;  /* security impersonation level */
    uint8_t smb_security_flags;   /* security flags */
    uint16_t smb_bcc;           /* byte count */
};

struct SmbNtCreateAndXResp    /* smb_wct = 34 */
{
    uint8_t smb_wct;
    uint8_t smb_com2;
    uint8_t smb_res2;
    uint16_t smb_off2;
    uint8_t smb_oplock_level;
    uint16_t smb_fid;
    uint32_t smb_create_disposition;
    uint64_t smb_creation_time;
    uint64_t smb_last_access_time;
    uint64_t smb_last_write_time;
    uint64_t smb_change_time;
    uint32_t smb_file_attrs;
    uint64_t smb_alloc_size;
    uint64_t smb_eof;
    uint16_t smb_resource_type;
    uint16_t smb_nm_pipe_state;
    uint8_t smb_directory;
    uint16_t smb_bcc;
};

// Word count is always set to 42 though there are actually 50 words
struct SmbNtCreateAndXExtResp    /* smb_wct = 42 */
{
    uint8_t smb_wct;
    uint8_t smb_com2;
    uint8_t smb_res2;
    uint16_t smb_off2;
    uint8_t smb_oplock_level;
    uint16_t smb_fid;
    uint32_t smb_create_disposition;
    uint64_t smb_creation_time;
    uint64_t smb_last_access_time;
    uint64_t smb_last_write_time;
    uint64_t smb_change_time;
    uint32_t smb_file_attrs;
    uint64_t smb_alloc_size;
    uint64_t smb_eof;
    uint16_t smb_resource_type;
    uint16_t smb_nm_pipe_state;
    uint8_t smb_directory;
    uint8_t smb_volume_guid[16];
    uint64_t smb_fileid;
    uint32_t smb_max_access_rights;
    uint32_t smb_guest_access_rights;
    uint16_t smb_bcc;
};

inline uint16_t SmbNtCreateAndXReqFileNameLen(const SmbNtCreateAndXReq* req)
{
    return alignedNtohs(&req->smb_name_len);
}

inline uint32_t SmbNtCreateAndXReqCreateDisposition(const SmbNtCreateAndXReq* req)
{
    return alignedNtohl(&req->smb_create_disp);
}

inline bool SmbCreateDispositionRead(const uint32_t create_disposition)
{
    return (create_disposition == SMB_CREATE_DISPOSITSION__FILE_OPEN)
           || (create_disposition > SMB_CREATE_DISPOSITSION__FILE_OVERWRITE_IF);
}

inline uint64_t SmbNtCreateAndXReqAllocSize(const SmbNtCreateAndXReq* req)
{
    return alignedNtohq(&req->smb_alloc_size);
}

inline bool SmbNtCreateAndXReqSequentialOnly(const SmbNtCreateAndXReq* req)
{
    return (alignedNtohl(&req->smb_create_opts) & SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY);
}

inline uint32_t SmbNtCreateAndXReqFileAttrs(const SmbNtCreateAndXReq* req)
{
    return alignedNtohl(&req->smb_file_attrs);
}

inline uint16_t SmbNtCreateAndXRespFid(const SmbNtCreateAndXResp* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

inline uint32_t SmbNtCreateAndXRespCreateDisposition(const SmbNtCreateAndXResp* resp)
{
    return alignedNtohl(&resp->smb_create_disposition);
}

inline bool SmbNtCreateAndXRespDirectory(const SmbNtCreateAndXResp* resp)
{
    return (resp->smb_directory ? true : false);
}

inline uint16_t SmbNtCreateAndXRespResourceType(const SmbNtCreateAndXResp* resp)
{
    return alignedNtohs(&resp->smb_resource_type);
}

inline uint64_t SmbNtCreateAndXRespEndOfFile(const SmbNtCreateAndXResp* resp)
{
    return alignedNtohq(&resp->smb_eof);
}

/********************************************************************
 * SMB_COM_TRANSACTION
 ********************************************************************/
struct SmbTransactionReq   /* smb_wct = 14 + value of smb_suwcnt */
{
    /* Note all subcommands use a setup count of 2 */
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_tpscnt;   /* total number of parameter bytes being sent */
    uint16_t smb_tdscnt;   /* total number of data bytes being sent */
    uint16_t smb_mprcnt;   /* max number of parameter bytes to return */
    uint16_t smb_mdrcnt;   /* max number of data bytes to return */
    uint8_t smb_msrcnt;    /* max number of setup words to return */
    uint8_t smb_rsvd;      /* reserved (pad above to word) */
    uint16_t smb_flags;    /* additional information:
                              bit 0 - if set, also disconnect TID in smb_tid
                              bit 1 - if set, transaction is one way (no final response) */
    uint32_t smb_timeout;  /* number of milliseconds to wait for completion */
    uint16_t smb_rsvd1;    /* reserved */
    uint16_t smb_pscnt;    /* number of parameter bytes being sent this buffer */
    uint16_t smb_psoff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_dscnt;    /* number of data bytes being sent this buffer */
    uint16_t smb_dsoff;    /* offset (from start of SMB hdr) to data bytes */
    uint8_t smb_suwcnt;    /* set up word count */
    uint8_t smb_rsvd2;     /* reserved (pad above to word) */
    uint16_t smb_setup1;   /* function (see below)
                                TRANS_SET_NM_PIPE_STATE   = 0x0001
                                TRANS_RAW_READ_NMPIPE     = 0x0011
                                TRANS_QUERY_NMPIPE_STATE  = 0x0021
                                TRANS_QUERY_NMPIPE_INFO   = 0x0022
                                TRANS_PEEK_NMPIPE         = 0x0023
                                TRANS_TRANSACT_NMPIPE     = 0x0026
                                TRANS_RAW_WRITE_NMPIPE    = 0x0031
                                TRANS_READ_NMPIPE         = 0x0036
                                TRANS_WRITE_NMPIPE        = 0x0037
                                TRANS_WAIT_NMPIPE         = 0x0053
                                TRANS_CALL_NMPIPE         = 0x0054  */
    uint16_t smb_setup2;   /* FID (handle) of pipe (if needed), or priority */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

struct SmbTransactionInterimResp    /* smb_wct = 0 */
{
    uint8_t smb_wct;        /* count of 16-bit words that follow */
    uint16_t smb_bcc;       /* must be 0 */
};

struct SmbTransactionResp   /* smb_wct = 10 + value of smb_suwcnt */
{
    /* Note all subcommands use a setup count of 0 */
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_tprcnt;   /* total number of parameter bytes being returned */
    uint16_t smb_tdrcnt;   /* total number of data bytes being returned */
    uint16_t smb_rsvd;     /* reserved */
    uint16_t smb_prcnt;    /* number of parameter bytes being returned this buf */
    uint16_t smb_proff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_prdisp;   /* byte displacement for these parameter bytes */
    uint16_t smb_drcnt;    /* number of data bytes being returned this buffer */
    uint16_t smb_droff;    /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_drdisp;   /* byte displacement for these data bytes */
    uint8_t smb_suwcnt;    /* set up return word count */
    uint8_t smb_rsvd1;     /* reserved (pad above to word) */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

inline uint16_t SmbTransactionReqSubCom(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_setup1);
}

inline uint16_t SmbTransactionReqFid(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_setup2);
}

inline bool SmbTransactionReqDisconnectTid(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_flags) & 0x0001 ? true : false;
}

inline bool SmbTransactionReqOneWay(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_flags) & 0x0002 ? true : false;
}

inline uint8_t SmbTransactionReqSetupCnt(const SmbTransactionReq* req)
{
    return req->smb_suwcnt;
}

inline uint16_t SmbTransactionReqTotalDataCnt(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_tdscnt);
}

inline uint16_t SmbTransactionReqDataCnt(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_dscnt);
}

inline uint16_t SmbTransactionReqDataOff(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_dsoff);
}

inline uint16_t SmbTransactionReqTotalParamCnt(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_tpscnt);
}

inline uint16_t SmbTransactionReqParamCnt(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_pscnt);
}

inline uint16_t SmbTransactionReqParamOff(const SmbTransactionReq* req)
{
    return alignedNtohs(&req->smb_psoff);
}

inline uint16_t SmbTransactionRespTotalDataCnt(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_tdrcnt);
}

inline uint16_t SmbTransactionRespDataCnt(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_drcnt);
}

inline uint16_t SmbTransactionRespDataOff(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_droff);
}

inline uint16_t SmbTransactionRespDataDisp(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_drdisp);
}

inline uint16_t SmbTransactionRespTotalParamCnt(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_tprcnt);
}

inline uint16_t SmbTransactionRespParamCnt(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_prcnt);
}

inline uint16_t SmbTransactionRespParamOff(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_proff);
}

inline uint16_t SmbTransactionRespParamDisp(const SmbTransactionResp* resp)
{
    return alignedNtohs(&resp->smb_prdisp);
}

// Flags for TRANS_SET_NMPIPE_STATE parameters
#define PIPE_STATE_NON_BLOCKING  0x8000
#define PIPE_STATE_MESSAGE_MODE  0x0100

/********************************************************************
 * SMB_COM_TRANSACTION2
 ********************************************************************/
struct SmbTransaction2Req
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_max_param_count;
    uint16_t smb_max_data_count;
    uint8_t smb_max_setup_count;
    uint8_t smb_res;
    uint16_t smb_flags;
    uint32_t smb_timeout;
    uint16_t smb_res2;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint8_t smb_setup_count;    /* Should be 1 for all subcommands */
    uint8_t smb_res3;
    uint16_t smb_setup;  /* This is the subcommand */
    uint16_t smb_bcc;
};

struct SmbTransaction2InterimResp
{
    uint8_t smb_wct;
    uint16_t smb_bcc;
};

struct SmbTransaction2Resp
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 or 1 word */
    uint8_t smb_res2;
};

inline uint16_t SmbTransaction2ReqSubCom(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_setup);
}

inline uint16_t SmbTransaction2ReqTotalParamCnt(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_total_param_count);
}

inline uint16_t SmbTransaction2ReqParamCnt(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_param_count);
}

inline uint16_t SmbTransaction2ReqParamOff(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_param_offset);
}

inline uint16_t SmbTransaction2ReqTotalDataCnt(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_total_data_count);
}

inline uint16_t SmbTransaction2ReqDataCnt(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_data_count);
}

inline uint16_t SmbTransaction2ReqDataOff(const SmbTransaction2Req* req)
{
    return alignedNtohs(&req->smb_data_offset);
}

inline uint8_t SmbTransaction2ReqSetupCnt(const SmbTransaction2Req* req)
{
    return req->smb_setup_count;
}

inline uint16_t SmbTransaction2RespTotalParamCnt(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_total_param_count);
}

inline uint16_t SmbTransaction2RespParamCnt(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_param_count);
}

inline uint16_t SmbTransaction2RespParamOff(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_param_offset);
}

inline uint16_t SmbTransaction2RespParamDisp(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_param_disp);
}

inline uint16_t SmbTransaction2RespTotalDataCnt(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_total_data_count);
}

inline uint16_t SmbTransaction2RespDataCnt(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_data_count);
}

inline uint16_t SmbTransaction2RespDataOff(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_data_offset);
}

inline uint16_t SmbTransaction2RespDataDisp(const SmbTransaction2Resp* resp)
{
    return alignedNtohs(&resp->smb_data_disp);
}

struct SmbTrans2Open2ReqParams
{
    uint16_t Flags;
    uint16_t AccessMode;
    uint16_t Reserved1;
    uint16_t FileAttributes;
    uint32_t CreationTime;
    uint16_t OpenMode;
    uint32_t AllocationSize;
    uint16_t Reserved[5];
};

typedef SmbTransaction2Req SmbTrans2Open2Req;

inline uint16_t SmbTrans2Open2ReqAccessMode(const SmbTrans2Open2ReqParams* req)
{
    return alignedNtohs(&req->AccessMode);
}

inline uint16_t SmbTrans2Open2ReqFileAttrs(const SmbTrans2Open2ReqParams* req)
{
    return alignedNtohs(&req->FileAttributes);
}

inline uint16_t SmbTrans2Open2ReqOpenMode(const SmbTrans2Open2ReqParams* req)
{
    return alignedNtohs(&req->OpenMode);
}

inline uint32_t SmbTrans2Open2ReqAllocSize(const SmbTrans2Open2ReqParams* req)
{
    return alignedNtohl(&req->AllocationSize);
}

struct SmbTrans2Open2RespParams
{
    uint16_t smb_fid;
    uint16_t file_attributes;
    uint32_t creation_time;
    uint32_t file_data_size;
    uint16_t access_mode;
    uint16_t resource_type;
    uint16_t nm_pipe_status;
    uint16_t action_taken;
    uint32_t reserved;
    uint16_t extended_attribute_error_offset;
    uint32_t extended_attribute_length;
};

inline uint16_t SmbTrans2Open2RespFid(const SmbTrans2Open2RespParams* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

inline uint16_t SmbTrans2Open2RespFileAttrs(const SmbTrans2Open2RespParams* resp)
{
    return alignedNtohs(&resp->file_attributes);
}

inline uint32_t SmbTrans2Open2RespFileDataSize(const SmbTrans2Open2RespParams* resp)
{
    return alignedNtohl(&resp->file_data_size);
}

inline uint16_t SmbTrans2Open2RespResourceType(const SmbTrans2Open2RespParams* resp)
{
    return alignedNtohs(&resp->resource_type);
}

inline uint16_t SmbTrans2Open2RespActionTaken(const SmbTrans2Open2RespParams* resp)
{
    return alignedNtohs(&resp->action_taken);
}

struct SmbTrans2Open2Resp
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 */
    uint8_t smb_res2;
    uint16_t smb_bcc;
};

// See MS-CIFS Section 2.2.2.3.3
#define SMB_INFO_STANDARD               0x0001
#define SMB_INFO_QUERY_EA_SIZE          0x0002
#define SMB_INFO_QUERY_EAS_FROM_LIST    0x0003
#define SMB_INFO_QUERY_ALL_EAS          0x0004
#define SMB_INFO_IS_NAME_VALID          0x0006
#define SMB_QUERY_FILE_BASIC_INFO       0x0101
#define SMB_QUERY_FILE_STANDARD_INFO    0x0102
#define SMB_QUERY_FILE_EA_INFO          0x0103
#define SMB_QUERY_FILE_NAME_INFO        0x0104
#define SMB_QUERY_FILE_ALL_INFO         0x0107
#define SMB_QUERY_FILE_ALT_NAME_INFO    0x0108
#define SMB_QUERY_FILE_STREAM_INFO      0x0109
#define SMB_QUERY_FILE_COMPRESSION_INFO 0x010b

// See MS-SMB Section 2.2.2.3.5
// For added value, see below from MS-FSCC
#define SMB_INFO_PASSTHROUGH  0x03e8
#define SMB_INFO_PT_FILE_STANDARD_INFO  SMB_INFO_PASSTHROUGH+5
#define SMB_INFO_PT_FILE_ALL_INFO       SMB_INFO_PASSTHROUGH+18
#define SMB_INFO_PT_FILE_STREAM_INFO    SMB_INFO_PASSTHROUGH+22
#define SMB_INFO_PT_NETWORK_OPEN_INFO   SMB_INFO_PASSTHROUGH+34

struct SmbTrans2QueryFileInfoReqParams
{
    uint16_t fid;
    uint16_t information_level;
};

inline uint16_t SmbTrans2QueryFileInfoReqFid(const SmbTrans2QueryFileInfoReqParams* req)
{
    return alignedNtohs(&req->fid);
}

inline uint16_t SmbTrans2QueryFileInfoReqInfoLevel(const SmbTrans2QueryFileInfoReqParams* req)
{
    return alignedNtohs(&req->information_level);
}

struct SmbQueryInfoStandard
{
    uint16_t CreationDate;
    uint16_t CreationTime;
    uint16_t LastAccessDate;
    uint16_t LastAccessTime;
    uint16_t LastWriteDate;
    uint16_t LastWriteTime;
    uint32_t FileDataSize;
    uint32_t AllocationSize;
    uint16_t Attributes;
};

inline uint32_t SmbQueryInfoStandardFileDataSize(const SmbQueryInfoStandard* q)
{
    return alignedNtohl(&q->FileDataSize);
}

struct SmbQueryInfoQueryEaSize
{
    uint16_t CreationDate;
    uint16_t CreationTime;
    uint16_t LastAccessDate;
    uint16_t LastAccessTime;
    uint16_t LastWriteDate;
    uint16_t LastWriteTime;
    uint32_t FileDataSize;
    uint32_t AllocationSize;
    uint16_t Attributes;
    uint32_t EaSize;
};

inline uint32_t SmbQueryInfoQueryEaSizeFileDataSize(const SmbQueryInfoQueryEaSize* q)
{
    return alignedNtohl(&q->FileDataSize);
}

struct SmbQueryFileStandardInfo
{
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint16_t Reserved;
};

inline uint64_t SmbQueryFileStandardInfoEndOfFile(const SmbQueryFileStandardInfo* q)
{
    return alignedNtohq(&q->EndOfFile);
}

struct SmbQueryFileAllInfo
{
    // Basic Info
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint32_t ExtFileAttributes;
    uint32_t Reserved1;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint16_t Reserved2;
    uint32_t EaSize;
    uint32_t FileNameLength;
};

inline uint64_t SmbQueryFileAllInfoEndOfFile(const SmbQueryFileAllInfo* q)
{
    return alignedNtohq(&q->EndOfFile);
}

struct SmbQueryPTFileAllInfo
{
    // Basic Info
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint32_t ExtFileAttributes;
    uint32_t Reserved1;

    // Standard Info
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t DeletePending;
    uint8_t Directory;
    uint16_t Reserved2;

    // Internal Info
    uint64_t IndexNumber;

    // EA Info
    uint32_t EaSize;

    // Access Info
    uint32_t AccessFlags;

    // Position Info
    uint64_t CurrentByteOffset;

    // Mode Info
    uint32_t Mode;

    // Alignment Info
    uint32_t AlignmentRequirement;

    // Name Info
    uint32_t FileNameLength;
};

inline uint64_t SmbQueryPTFileAllInfoEndOfFile(const SmbQueryPTFileAllInfo* q)
{
    return alignedNtohq(&q->EndOfFile);
}

struct SmbQueryPTNetworkOpenInfo
{
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
    uint32_t Reserved;
};

inline uint64_t SmbQueryPTNetworkOpenInfoEndOfFile(const SmbQueryPTNetworkOpenInfo* q)
{
    return alignedNtohq(&q->EndOfFile);
}

struct SmbQueryPTFileStreamInfo
{
    uint32_t NextEntryOffset;
    uint32_t StreamNameLength;
    uint64_t StreamSize;
    uint64_t StreamAllocationSize;
};

inline uint64_t SmbQueryPTFileStreamInfoStreamSize(const SmbQueryPTFileStreamInfo* q)
{
    return alignedNtohq(&q->StreamSize);
}

struct SmbTrans2QueryFileInformationResp
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_res;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_setup_count;  /* 0 */
    uint8_t smb_res2;
    uint16_t smb_bcc;
};

#define SMB_INFO_SET_EAS               0x0002
#define SMB_SET_FILE_BASIC_INFO        0x0101
#define SMB_SET_FILE_DISPOSITION_INFO  0x0102
#define SMB_SET_FILE_ALLOCATION_INFO   0x0103
#define SMB_SET_FILE_END_OF_FILE_INFO  0x0104

// For added value, see above File Information Classes
#define SMB_INFO_PT_SET_FILE_BASIC_FILE_INFO   SMB_INFO_PASSTHROUGH+4
#define SMB_INFO_PT_SET_FILE_END_OF_FILE_INFO  SMB_INFO_PASSTHROUGH+20

struct SmbTrans2SetFileInfoReqParams
{
    uint16_t fid;
    uint16_t information_level;
    uint16_t reserved;
};

inline uint16_t SmbTrans2SetFileInfoReqFid(const SmbTrans2SetFileInfoReqParams* req)
{
    return alignedNtohs(&req->fid);
}

inline uint16_t SmbTrans2SetFileInfoReqInfoLevel(const SmbTrans2SetFileInfoReqParams* req)
{
    return alignedNtohs(&req->information_level);
}

inline bool SmbSetFileInfoEndOfFile(const uint16_t info_level)
{
    return ((info_level == SMB_SET_FILE_END_OF_FILE_INFO)
           || (info_level == SMB_INFO_PT_SET_FILE_END_OF_FILE_INFO));
}

struct SmbSetFileBasicInfo
{
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint32_t ExtFileAttributes;
    uint32_t Reserved;
};

inline uint32_t SmbSetFileInfoExtFileAttrs(const SmbSetFileBasicInfo* info)
{
    return alignedNtohl(&info->ExtFileAttributes);
}

inline bool SmbSetFileInfoSetFileBasicInfo(const uint16_t info_level)
{
    return ((info_level == SMB_SET_FILE_BASIC_INFO)
           || (info_level == SMB_INFO_PT_SET_FILE_BASIC_FILE_INFO));
}

/********************************************************************
 * SMB_COM_NT_TRANSACT
 ********************************************************************/
#define SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY     0x00000004

struct SmbNtTransactReq
{
    uint8_t smb_wct;
    uint8_t smb_max_setup_count;
    uint16_t smb_res;
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_max_param_count;
    uint32_t smb_max_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint8_t smb_setup_count;
    uint16_t smb_function;
};

struct SmbNtTransactInterimResp
{
    uint8_t smb_wct;
    uint16_t smb_bcc;
};

struct SmbNtTransactResp
{
    uint8_t smb_wct;
    uint8_t smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t smb_setup_count;
};

inline uint16_t SmbNtTransactReqSubCom(const SmbNtTransactReq* req)
{
    return alignedNtohs(&req->smb_function);
}

inline uint8_t SmbNtTransactReqSetupCnt(const SmbNtTransactReq* req)
{
    return req->smb_setup_count;
}

inline uint32_t SmbNtTransactReqTotalParamCnt(const SmbNtTransactReq* req)
{
    return alignedNtohl(&req->smb_total_param_count);
}

inline uint32_t SmbNtTransactReqParamCnt(const SmbNtTransactReq* req)
{
    return alignedNtohl(&req->smb_param_count);
}

inline uint32_t SmbNtTransactReqParamOff(const SmbNtTransactReq* req)
{
    return alignedNtohl(&req->smb_param_offset);
}

inline uint32_t SmbNtTransactReqTotalDataCnt(const SmbNtTransactReq* req)
{
    return alignedNtohl(&req->smb_total_data_count);
}

inline uint32_t SmbNtTransactReqDataCnt(const SmbNtTransactReq* req)
{
    return alignedNtohl(&req->smb_data_count);
}

inline uint32_t SmbNtTransactReqDataOff(const SmbNtTransactReq* req)
{
    return alignedNtohl(&req->smb_data_offset);
}

inline uint32_t SmbNtTransactRespTotalParamCnt(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_total_param_count);
}

inline uint32_t SmbNtTransactRespParamCnt(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_param_count);
}

inline uint32_t SmbNtTransactRespParamOff(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_param_offset);
}

inline uint32_t SmbNtTransactRespParamDisp(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_param_disp);
}

inline uint32_t SmbNtTransactRespTotalDataCnt(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_total_data_count);
}

inline uint32_t SmbNtTransactRespDataCnt(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_data_count);
}

inline uint32_t SmbNtTransactRespDataOff(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_data_offset);
}

inline uint32_t SmbNtTransactRespDataDisp(const SmbNtTransactResp* resp)
{
    return alignedNtohl(&resp->smb_data_disp);
}

struct SmbNtTransactCreateReqParams
{
    uint32_t flags;
    uint32_t root_dir_fid;
    uint32_t desired_access;
    uint64_t allocation_size;
    uint32_t ext_file_attributes;
    uint32_t share_access;
    uint32_t create_disposition;
    uint32_t create_options;
    uint32_t security_descriptor_length;
    uint32_t ea_length;
    uint32_t name_length;
    uint32_t impersonation_level;
    uint8_t security_flags;
};

inline uint64_t SmbNtTransactCreateReqAllocSize(const SmbNtTransactCreateReqParams* req)
{
    return alignedNtohq(&req->allocation_size);
}

inline uint32_t SmbNtTransactCreateReqFileNameLength(const SmbNtTransactCreateReqParams* req)
{
    return alignedNtohl(&req->name_length);
}

inline uint32_t SmbNtTransactCreateReqFileAttrs(const SmbNtTransactCreateReqParams* req)
{
    return alignedNtohl(&req->ext_file_attributes);
}

inline bool SmbNtTransactCreateReqSequentialOnly(const SmbNtTransactCreateReqParams* req)
{
    return (alignedNtohl(&req->create_options) & SMB_CREATE_OPTIONS__FILE_SEQUENTIAL_ONLY);
}

struct SmbNtTransactCreateReq
{
    uint8_t smb_wct;
    uint8_t smb_max_setup_count;
    uint16_t smb_res;
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_max_param_count;
    uint32_t smb_max_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint8_t smb_setup_count;    /* Must be 0x00 */
    uint16_t smb_function;      /* NT_TRANSACT_CREATE */
    uint16_t smb_bcc;
};

struct SmbNtTransactCreateRespParams
{
    uint8_t op_lock_level;
    uint8_t reserved;
    uint16_t smb_fid;
    uint32_t create_action;
    uint32_t ea_error_offset;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t last_change_time;
    uint32_t ext_file_attributes;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint16_t resource_type;
    uint16_t nm_pipe_status;
    uint8_t directory;
};

inline uint16_t SmbNtTransactCreateRespFid(const SmbNtTransactCreateRespParams* resp)
{
    return alignedNtohs(&resp->smb_fid);
}

inline uint32_t SmbNtTransactCreateRespCreateAction(const SmbNtTransactCreateRespParams* resp)
{
    return alignedNtohl(&resp->create_action);
}

inline uint64_t SmbNtTransactCreateRespEndOfFile(const SmbNtTransactCreateRespParams* resp)
{
    return alignedNtohq(&resp->end_of_file);
}

inline uint16_t SmbNtTransactCreateRespResourceType(const SmbNtTransactCreateRespParams* resp)
{
    return alignedNtohs(&resp->resource_type);
}

inline bool SmbNtTransactCreateRespDirectory(const SmbNtTransactCreateRespParams* resp)
{
    return (resp->directory ? true : false);
}

struct SmbNtTransactCreateResp
{
    uint8_t smb_wct;
    uint8_t smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t smb_setup_count;    /* 0x00 */
    uint16_t smb_bcc;
};

/********************************************************************
 * SMB_COM_TRANSACTION_SECONDARY
 *  Continuation command for SMB_COM_TRANSACTION requests if all
 *  data wasn't sent.
 ********************************************************************/
struct SmbTransactionSecondaryReq   /* smb_wct = 8 */
{
    uint8_t smb_wct;       /* count of 16-bit words that follow */
    uint16_t smb_tpscnt;   /* total number of parameter bytes being sent */
    uint16_t smb_tdscnt;   /* total number of data bytes being sent */
    uint16_t smb_pscnt;    /* number of parameter bytes being sent this buffer */
    uint16_t smb_psoff;    /* offset (from start of SMB hdr) to parameter bytes */
    uint16_t smb_psdisp;   /* byte displacement for these parameter bytes */
    uint16_t smb_dscnt;    /* number of data bytes being sent this buffer */
    uint16_t smb_dsoff;    /* offset (from start of SMB hdr) to data bytes */
    uint16_t smb_dsdisp;   /* byte displacement for these data bytes */
    uint16_t smb_bcc;      /* total bytes (including pad bytes) following */
};

inline uint16_t SmbTransactionSecondaryReqTotalDataCnt(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_tdscnt);
}

inline uint16_t SmbTransactionSecondaryReqDataCnt(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_dscnt);
}

inline uint16_t SmbTransactionSecondaryReqDataOff(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_dsoff);
}

inline uint16_t SmbTransactionSecondaryReqDataDisp(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_dsdisp);
}

inline uint16_t SmbTransactionSecondaryReqTotalParamCnt(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_tpscnt);
}

inline uint16_t SmbTransactionSecondaryReqParamCnt(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_pscnt);
}

inline uint16_t SmbTransactionSecondaryReqParamOff(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_psoff);
}

inline uint16_t SmbTransactionSecondaryReqParamDisp(const SmbTransactionSecondaryReq* req)
{
    return alignedNtohs(&req->smb_psdisp);
}

/********************************************************************
 * SMB_COM_TRANSACTION2_SECONDARY
 *  Continuation command for SMB_COM_TRANSACTION2 requests if all
 *  data wasn't sent.
 ********************************************************************/
struct SmbTransaction2SecondaryReq
{
    uint8_t smb_wct;
    uint16_t smb_total_param_count;
    uint16_t smb_total_data_count;
    uint16_t smb_param_count;
    uint16_t smb_param_offset;
    uint16_t smb_param_disp;
    uint16_t smb_data_count;
    uint16_t smb_data_offset;
    uint16_t smb_data_disp;
    uint16_t smb_fid;
    uint16_t smb_bcc;
};

inline uint16_t SmbTransaction2SecondaryReqTotalParamCnt(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_total_param_count);
}

inline uint16_t SmbTransaction2SecondaryReqParamCnt(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_param_count);
}

inline uint16_t SmbTransaction2SecondaryReqParamOff(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_param_offset);
}

inline uint16_t SmbTransaction2SecondaryReqParamDisp(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_param_disp);
}

inline uint16_t SmbTransaction2SecondaryReqTotalDataCnt(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_total_data_count);
}

inline uint16_t SmbTransaction2SecondaryReqDataCnt(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_data_count);
}

inline uint16_t SmbTransaction2SecondaryReqDataOff(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_data_offset);
}

inline uint16_t SmbTransaction2SecondaryReqDataDisp(const SmbTransaction2SecondaryReq* req)
{
    return alignedNtohs(&req->smb_data_disp);
}

/********************************************************************
 * SMB_COM_NT_TRANSACT_SECONDARY
 ********************************************************************/
struct SmbNtTransactSecondaryReq
{
    uint8_t smb_wct;
    uint8_t smb_res[3];
    uint32_t smb_total_param_count;
    uint32_t smb_total_data_count;
    uint32_t smb_param_count;
    uint32_t smb_param_offset;
    uint32_t smb_param_disp;
    uint32_t smb_data_count;
    uint32_t smb_data_offset;
    uint32_t smb_data_disp;
    uint8_t smb_res2;
};

inline uint32_t SmbNtTransactSecondaryReqTotalParamCnt(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_total_param_count);
}

inline uint32_t SmbNtTransactSecondaryReqParamCnt(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_param_count);
}

inline uint32_t SmbNtTransactSecondaryReqParamOff(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_param_offset);
}

inline uint32_t SmbNtTransactSecondaryReqParamDisp(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_param_disp);
}

inline uint32_t SmbNtTransactSecondaryReqTotalDataCnt(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_total_data_count);
}

inline uint32_t SmbNtTransactSecondaryReqDataCnt(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_data_count);
}

inline uint32_t SmbNtTransactSecondaryReqDataOff(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_data_offset);
}

inline uint32_t SmbNtTransactSecondaryReqDataDisp(const SmbNtTransactSecondaryReq* req)
{
    return alignedNtohl(&req->smb_data_disp);
}

#pragma pack()

struct DCE2_SmbFsm
{
    char input;
    int next_state;
    int fail_state;
};

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

