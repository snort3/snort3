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

//dce2_smb.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE2_SMB_H
#define DCE2_SMB_H

#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "framework/counts.h"

#define DCE2_SMB_NAME "dce_smb"
#define DCE2_SMB_HELP "dce over smb inspection"

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

    PegCount smb_sessions;
    PegCount smb_pkts;

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

extern THREAD_LOCAL ProfileStats dce2_smb_pstat_main;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_session;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_new_session;
extern THREAD_LOCAL ProfileStats dce2_smb_pstat_session_state;
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
#endif

