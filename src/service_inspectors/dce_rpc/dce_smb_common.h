//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb_common.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB_COMMON_H
#define DCE_SMB_COMMON_H

// This provides SMB flow data and base class for SMB session data
// Also provides common functions used by both versions

#include "file_api/file_api.h"
#include "protocols/packet.h"
#include "profiler/profiler_defs.h"
#include "trace/trace_api.h"

#include "dce_common.h"
#include "dce_smb_module.h"
#include "smb_common.h"

#define DCE2_SMB_NAME "dce_smb"
#define DCE2_SMB_HELP "dce over smb inspection"

#define SMB_DEBUG(module_name, module_id, log_level, p, ...) \
    trace_logf(log_level, module_name , module_id, p, __VA_ARGS__)

#define DCE2_SMB_ID   0xff534d42  /* \xffSMB */
#define DCE2_SMB2_ID  0xfe534d42  /* \xfeSMB */
#define DCE2_SMB_ID_SIZE 4

#define SMB_DEFAULT_MAX_CREDIT        8192
#define SMB_DEFAULT_MEMCAP            8388608
#define SMB_DEFAULT_MAX_COMPOUND_REQ  3

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
    PegCount v2_setup;
    PegCount v2_setup_err_resp;
    PegCount v2_setup_inv_str_sz;
    PegCount v2_setup_resp_hdr_err;
    PegCount v2_tree_cnct;
    PegCount v2_tree_cnct_err_resp;
    PegCount v2_tree_cnct_ignored;
    PegCount v2_tree_cnct_inv_str_sz;
    PegCount v2_tree_cnct_resp_hdr_err;
    PegCount v2_crt;
    PegCount v2_crt_err_resp;
    PegCount v2_crt_inv_file_data;
    PegCount v2_crt_inv_str_sz;
    PegCount v2_crt_resp_hdr_err;
    PegCount v2_crt_req_hdr_err;
    PegCount v2_crt_rtrkr_misng;
    PegCount v2_crt_req_ipc;
    PegCount v2_crt_tree_trkr_misng;
    PegCount v2_wrt;
    PegCount v2_wrt_err_resp;
    PegCount v2_wrt_inv_str_sz;
    PegCount v2_wrt_req_hdr_err;
    PegCount v2_wrt_resp_hdr_err;
    PegCount v2_read;
    PegCount v2_read_err_resp;
    PegCount v2_read_inv_str_sz;
    PegCount v2_read_rtrkr_misng;
    PegCount v2_read_resp_hdr_err;
    PegCount v2_read_req_hdr_err;
    PegCount v2_setinfo;
    PegCount v2_stinf_err_resp;
    PegCount v2_stinf_inv_str_sz;
    PegCount v2_stinf_req_ftrkr_misng;
    PegCount v2_stinf_req_hdr_err;
    PegCount v2_cls;
    PegCount v2_cls_err_resp;
    PegCount v2_cls_inv_str_sz;
    PegCount v2_cls_req_ftrkr_misng;
    PegCount v2_cls_req_hdr_err;
    PegCount v2_tree_discn;
    PegCount v2_tree_discn_ignored;
    PegCount v2_tree_discn_inv_str_sz;
    PegCount v2_tree_discn_req_hdr_err;
    PegCount v2_logoff;
    PegCount v2_logoff_inv_str_sz;
    PegCount v2_hdr_err;
    PegCount v2_bad_next_cmd_offset;
    PegCount v2_inv_file_ctx_err;
    PegCount v2_msgs_uninspected;
    PegCount v2_cmpnd_req_lt_crossed;
    PegCount v2_tree_ignored;
    PegCount v2_session_ignored;
    PegCount v2_ioctl;
    PegCount v2_ioctl_err_resp;
    PegCount v2_ioctl_inv_str_sz;
    PegCount v2_ioctl_req_hdr_err;
    PegCount v2_ioctl_resp_hdr_err;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    PegCount total_smb1_sessions;
    PegCount total_smb2_sessions;
    PegCount total_encrypted_sessions;
    PegCount total_mc_sessions;
    PegCount ignore_dup_sessions;
};

enum DCE2_SmbVersion
{
    DCE2_SMB_VERSION_NULL,
    DCE2_SMB_VERSION_1,
    DCE2_SMB_VERSION_2
};

enum Dce2SmbPduState
{
    DCE2_SMB_PDU_STATE__COMMAND,
    DCE2_SMB_PDU_STATE__RAW_DATA
};

extern THREAD_LOCAL dce2SmbStats dce2_smb_stats;
extern THREAD_LOCAL snort::ProfileStats dce2_smb_pstat_main;
extern bool smb_module_is_up;
extern SnortProtocolId snort_protocol_id_smb;

class Dce2SmbSessionData
{
public:
    Dce2SmbSessionData() = delete;
    Dce2SmbSessionData(const snort::Packet*, const dce2SmbProtoConf*);
    virtual ~Dce2SmbSessionData() { }

    virtual void process() = 0;
    virtual void handle_retransmit(FilePosition, FileVerdict) = 0;
    virtual void set_reassembled_data(uint8_t*, uint16_t) = 0;

    DCE2_SsnData* get_dce2_session_data()
    { return &sd; }

    snort::Flow* get_tcp_flow()
    { return tcp_flow; }

    int64_t get_max_file_depth()
    { return max_file_depth; }

    uint16_t get_max_outstanding_requests()
    {
        return sd.config ? ((dce2SmbProtoConf*)sd.config)->smb_max_credit :
               SMB_DEFAULT_MAX_CREDIT;
    }

    int64_t get_smb_file_depth()
    {
        return ((dce2SmbProtoConf*)sd.config)->smb_file_depth;
    }

    uint16_t get_smb_max_compound()
    {
        return sd.config ? ((dce2SmbProtoConf*)sd.config)->smb_max_compound :
               SMB_DEFAULT_MAX_COMPOUND_REQ;
    }

protected:
    DCE2_SsnData sd;
    DCE2_Policy policy;
    int64_t max_file_depth;
    int dialect_index;
    snort::Flow* tcp_flow;
};

class Dce2SmbFlowData : public snort::FlowData
{
public:
    Dce2SmbFlowData(Dce2SmbSessionData*);
    Dce2SmbFlowData() : snort::FlowData(inspector_id)
    {
        dce2_smb_stats.concurrent_sessions++;
        if (dce2_smb_stats.max_concurrent_sessions < dce2_smb_stats.concurrent_sessions)
            dce2_smb_stats.max_concurrent_sessions = dce2_smb_stats.concurrent_sessions;
        ssd = nullptr;
    }

    ~Dce2SmbFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

    Dce2SmbSessionData* get_smb_session_data()
    { return ssd; }

    Dce2SmbSessionData* upgrade(const snort::Packet*);
    void update_smb_session_data(Dce2SmbSessionData* ssd_v)
    { 
        if (ssd) delete ssd;
        ssd = ssd_v;
    }
    void handle_retransmit(snort::Packet*) override;

public:
    static unsigned inspector_id;

private:
    Dce2SmbSessionData* ssd;
};

Dce2SmbFlowData* create_expected_smb_flow_data(const snort::Packet*);
Dce2SmbSessionData* create_new_smb_session(const snort::Packet*, dce2SmbProtoConf*);
Dce2SmbSessionData* create_smb_session_data(Dce2SmbFlowData*, const snort::Packet*,
    dce2SmbProtoConf*);
DCE2_SsnData* get_dce2_session_data(snort::Flow*);
snort::FileContext* get_smb_file_context(const snort::Packet*);
snort::FileContext* get_smb_file_context(snort::Flow*, uint64_t, uint64_t, bool);
char* get_smb_file_name(const uint8_t*, uint32_t, bool, uint16_t*);
void set_smb_reassembled_data(uint8_t*, uint16_t);

#endif

