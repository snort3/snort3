//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb_module.cc author Rashmi Pitre <rrp@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_module.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "trace/trace.h"
#include "utils/util.h"

#include "dce_smb_common.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* dce_smb_trace = nullptr;

static const PegInfo dce2_smb_pegs[] =
{
    { CountType::SUM, "events", "total events" },
    { CountType::SUM, "pdus", "total connection-oriented PDUs" },
    { CountType::SUM, "binds", "total connection-oriented binds" },
    { CountType::SUM, "bind_acks", "total connection-oriented binds acks" },
    { CountType::SUM, "alter_contexts", "total connection-oriented alter contexts" },
    { CountType::SUM, "alter_context_responses",
        "total connection-oriented alter context responses" },
    { CountType::SUM, "bind_naks", "total connection-oriented bind naks" },
    { CountType::SUM, "requests", "total connection-oriented requests" },
    { CountType::SUM, "responses", "total connection-oriented responses" },
    { CountType::SUM, "cancels", "total connection-oriented cancels" },
    { CountType::SUM, "orphaned", "total connection-oriented orphaned" },
    { CountType::SUM, "faults", "total connection-oriented faults" },
    { CountType::SUM, "auth3s", "total connection-oriented auth3s" },
    { CountType::SUM, "shutdowns", "total connection-oriented shutdowns" },
    { CountType::SUM, "rejects", "total connection-oriented rejects" },
    { CountType::SUM, "ms_rpc_http_pdus",
        "total connection-oriented MS requests to send RPC over HTTP" },
    { CountType::SUM, "other_requests", "total connection-oriented other requests" },
    { CountType::SUM, "other_responses", "total connection-oriented other responses" },
    { CountType::SUM, "request_fragments", "total connection-oriented request fragments" },
    { CountType::SUM, "response_fragments", "total connection-oriented response fragments" },
    { CountType::SUM, "client_max_fragment_size",
        "connection-oriented client maximum fragment size" },
    { CountType::SUM, "client_min_fragment_size",
        "connection-oriented client minimum fragment size" },
    { CountType::SUM, "client_segs_reassembled",
        "total connection-oriented client segments reassembled" },
    { CountType::SUM, "client_frags_reassembled",
        "total connection-oriented client fragments reassembled" },
    { CountType::SUM, "server_max_fragment_size",
        "connection-oriented server maximum fragment size" },
    { CountType::SUM, "server_min_fragment_size",
        "connection-oriented server minimum fragment size" },
    { CountType::SUM, "server_segs_reassembled",
        "total connection-oriented server segments reassembled" },
    { CountType::SUM, "server_frags_reassembled",
        "total connection-oriented server fragments reassembled" },
    { CountType::SUM, "sessions", "total smb sessions" },
    { CountType::SUM, "packets", "total smb packets" },
    { CountType::SUM, "ignored_bytes", "total ignored bytes" },
    { CountType::SUM, "smb_client_segs_reassembled", "total smb client segments reassembled" },
    { CountType::SUM, "smb_server_segs_reassembled", "total smb server segments reassembled" },
    { CountType::MAX, "max_outstanding_requests", "maximum outstanding requests" },
    { CountType::SUM, "files_processed", "total smb files processed" },
    { CountType::SUM, "v2_setup", "total number of SMBv2 setup packets seen" },
    { CountType::SUM, "v2_setup_err_resp",
        "total number of SMBv2 setup error response packets seen" },
    { CountType::SUM, "v2_setup_inv_str_sz",
        "total number of SMBv2 setup packets seen with invalid structure size" },
    { CountType::SUM, "v2_setup_resp_hdr_err",
        "total number of SMBv2 setup response packets ignored due to corrupted header" },
    { CountType::SUM, "v2_tree_cnct", "total number of SMBv2 tree connect packets seen" },
    { CountType::SUM, "v2_tree_cnct_err_resp",
        "total number of SMBv2 tree connect error response packets seen" },
    { CountType::SUM, "v2_tree_cnct_ignored",
        "total number of SMBv2 setup response packets ignored due to failure in creating tree tracker" },
    { CountType::SUM, "v2_tree_cnct_inv_str_sz",
        "total number of SMBv2 tree connect packets seen with invalid structure size" },
    { CountType::SUM, "v2_tree_cnct_resp_hdr_err",
        "total number of SMBv2 tree connect response packets ignored due to corrupted header" },
    { CountType::SUM, "v2_crt", "total number of SMBv2 create packets seen" },
    { CountType::SUM, "v2_crt_err_resp",
        "total number of SMBv2 create error response packets seen" },
    { CountType::SUM, "v2_crt_inv_file_data",
        "total number of SMBv2 create request packets ignored due to error in getting file name" },
    { CountType::SUM, "v2_crt_inv_str_sz",
        "total number of SMBv2 create packets seen with invalid structure size" },
    { CountType::SUM, "v2_crt_resp_hdr_err",
         "total number of SMBv2 create response packets ignored due to corrupted header" },
    { CountType::SUM, "v2_crt_req_hdr_err",
         "total number of SMBv2 create request packets ignored due to corrupted header" },
    { CountType::SUM, "v2_crt_rtrkr_misng",
        "total number of SMBv2 create response packets ignored due to missing create request tracker" },
    { CountType::SUM, "v2_crt_req_ipc",
        "total number of SMBv2 create request packets ignored as share type is IPC" },
    { CountType::SUM, "v2_crt_tree_trkr_misng",
        "total number of SMBv2 create response packets ignored due to missing tree tracker" },
    { CountType::SUM, "v2_wrt", "total number of SMBv2 write packets seen" },
    { CountType::SUM, "v2_wrt_err_resp",
        "total number of SMBv2 write error response packets seen" },
    { CountType::SUM, "v2_wrt_inv_str_sz",
        "total number of SMBv2 write packets seen with invalid structure size" },
    { CountType::SUM, "v2_wrt_req_hdr_err",
        "total number of SMBv2 write request packets ignored due to corrupted header" },
    { CountType::SUM, "v2_wrt_resp_hdr_err",
        "total number of SMBv2 write response packets ignored due to corrupted header" },
    { CountType::SUM, "v2_read", "total number of SMBv2 read packets seen" },
    { CountType::SUM, "v2_read_err_resp",
        "total number of SMBv2 read error response packets seen" },
    { CountType::SUM, "v2_read_inv_str_sz",
        "total number of SMBv2 read packets seen with invalid structure size" },
    { CountType::SUM, "v2_read_rtrkr_misng",
        "total number of SMBv2 read response packets ignored due to missing read request tracker" },
    { CountType::SUM, "v2_read_resp_hdr_err",
        "total number of SMBv2 read response packets ignored due to corrupted header" },
    { CountType::SUM, "v2_read_req_hdr_err",
        "total number of SMBv2 read request packets ignored due to corrupted header" },
    { CountType::SUM, "v2_setinfo", "total number of SMBv2 set info packets seen" },
    { CountType::SUM, "v2_stinf_err_resp",
        "total number of SMBv2 set info error response packets seen" },
    { CountType::SUM, "v2_stinf_inv_str_sz",
        "total number of SMBv2 set info packets seen with invalid structure size" },
    { CountType::SUM, "v2_stinf_req_ftrkr_misng",
        "total number of SMBv2 set info request packets ignored due to missing file tracker" },
    { CountType::SUM, "v2_stinf_req_hdr_err",
        "total number of SMBv2 set info request packets ignored due to corrupted header" },
    { CountType::SUM, "v2_cls", "total number of SMBv2 close packets seen" },
    { CountType::SUM, "v2_cls_err_resp",
        "total number of SMBv2 close error response packets seen" },
    { CountType::SUM, "v2_cls_inv_str_sz",
        "total number of SMBv2 close packets seen with invalid structure size" },
    { CountType::SUM, "v2_cls_req_ftrkr_misng",
        "total number of SMBv2 close request packets ignored due to missing file tracker" },
    { CountType::SUM, "v2_cls_req_hdr_err",
        "total number of SMBv2 close request packets ignored due to corrupted header" },
    { CountType::SUM, "v2_tree_discn",
        "total number of SMBv2 tree disconnect packets seen" },
    { CountType::SUM, "v2_tree_discn_ignored",
        "total number of SMBv2 tree disconnect packets ignored due to missing trackers or invalid share type" },
    { CountType::SUM, "v2_tree_discn_inv_str_sz",
        "total number of SMBv2 tree disconnect packets seen with invalid structure size" },
    { CountType::SUM, "v2_tree_discn_req_hdr_err",
        "total number of SMBv2 tree disconnect request packets ignored due to corrupted header" },
    { CountType::SUM, "v2_logoff", "total number of SMBv2 logoff" },
    { CountType::SUM, "v2_logoff_inv_str_sz",
        "total number of SMBv2 logoff packets seen with invalid structure size" },
    { CountType::SUM, "v2_hdr_err", "total number of SMBv2 packets seen with corrupted hdr" },
    { CountType::SUM, "v2_bad_next_cmd_offset",
        "total number of SMBv2 packets seen with invalid next command offset" },
    { CountType::SUM, "v2_inv_file_ctx_err",
        "total number of times null file context are seen resulting in not being able to set file size" },
    { CountType::SUM, "v2_msgs_uninspected",
        "total number of SMBv2 packets seen where command is not being inspected" },
    { CountType::SUM, "v2_cmpnd_req_lt_crossed",
        "total number of SMBv2 packets seen where compound requests exceed the smb_max_compound limit" },
    { CountType::SUM, "v2_tree_ignored",
        "total number of packets ignored due to missing tree tracker" },
    { CountType::SUM, "v2_session_ignored",
        "total number of packets ignored due to missing session tracker" },
    { CountType::SUM, "v2_ioctl",
        "total number of ioctl calls" },
    { CountType::SUM, "v2_ioctl_err_resp",
        "total number of ioctl errors responses" },
    { CountType::SUM, "v2_ioctl_inv_str_sz",
        "total number of ioctl invalid structure size" },
    { CountType::SUM, "v2_ioctl_req_hdr_err",
        "total number of ioctl request header errors" },
    { CountType::SUM, "v2_ioctl_resp_hdr_err",
        "total number of ioctl response header errors" },
    { CountType::NOW, "concurrent_sessions", "total concurrent sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent sessions" },
    { CountType::SUM, "total_smb1_sessions", "total smb1 sessions" },
    { CountType::SUM, "total_smb2_sessions", "total smb2 sessions" },
    { CountType::SUM, "total_encrypted_sessions", "total encrypted sessions" },
    { CountType::SUM, "total_mc_sessions", "total multichannel sessions" },
    { CountType::SUM, "ignore_dup_sessions", "total smb req/resp dropped because of dup msg id" },
    { CountType::END, nullptr, nullptr }
};

static const char* dce2SmbFingerprintPolicyStrings[] =
{ "disabled", "client", "server", "client and server" };

static const Parameter s_params[] =
{
    { "limit_alerts", Parameter::PT_BOOL, nullptr, "true",
      "limit DCE alert to at most one per signature per flow" },

    { "disable_defrag", Parameter::PT_BOOL, nullptr, "false",
      "disable DCE/RPC defragmentation" },

    { "max_frag_len", Parameter::PT_INT, "1514:65535", "65535",
      "maximum fragment size for defragmentation" },

    { "reassemble_threshold", Parameter::PT_INT, "0:65535", "0",
      "minimum bytes received before performing reassembly" },

    { "smb_fingerprint_policy", Parameter::PT_ENUM, "none | client |  server | both ", "none",
      "target based SMB policy to use" },

    { "policy", Parameter::PT_ENUM,
      "Win2000 |  WinXP | WinVista | Win2003 | Win2008 | Win7 | Samba | Samba-3.0.37 | "
      "Samba-3.0.22 | Samba-3.0.20", "WinXP",
      "target based policy to use" },

    { "smb_max_chain", Parameter::PT_INT, "0:255", "3",
      "SMB max chain size" },

    { "smb_max_compound", Parameter::PT_INT, "0:255", "3",
      "SMB max compound size" },

    { "valid_smb_versions", Parameter::PT_MULTI, "v1 | v2 | all", "all",
      "valid SMB versions" },

    { "smb_file_inspection", Parameter::PT_ENUM, "off | on | only", nullptr,
      "deprecated (not used): file inspection controlled by smb_file_depth" },

    { "smb_file_depth", Parameter::PT_INT, "-1:32767", "16384",
      "SMB file depth for file data (-1 = disabled, 0 = unlimited)" },

    { "smb_invalid_shares", Parameter::PT_STRING, nullptr, nullptr,
      "SMB shares to alert on " },

    { "smb_legacy_mode", Parameter::PT_BOOL, nullptr, "false",
      "inspect only SMBv1" },

    { "smb_max_credit", Parameter::PT_INT, "1:65535", "8192",
      "Maximum number of outstanding request" },

    { "memcap", Parameter::PT_INT, "512:maxSZ", "8388608",
      "Memory utilization limit on smb" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dce2_smb_rules[] =
{
    { DCE2_SMB_BAD_NBSS_TYPE, DCE2_SMB_BAD_NBSS_TYPE_STR },
    { DCE2_SMB_BAD_TYPE, DCE2_SMB_BAD_TYPE_STR },
    { DCE2_SMB_BAD_ID, DCE2_SMB_BAD_ID_STR },
    { DCE2_SMB_BAD_WCT, DCE2_SMB_BAD_WCT_STR },
    { DCE2_SMB_BAD_BCC, DCE2_SMB_BAD_BCC_STR },
    { DCE2_SMB_BAD_FORM, DCE2_SMB_BAD_FORM_STR },
    { DCE2_SMB_BAD_OFF, DCE2_SMB_BAD_OFF_STR },
    { DCE2_SMB_TDCNT_ZE, DCE2_SMB_TDCNT_ZE_STR },
    { DCE2_SMB_NB_LT_SMBHDR, DCE2_SMB_NB_LT_SMBHDR_STR },
    { DCE2_SMB_NB_LT_COM, DCE2_SMB_NB_LT_COM_STR },
    { DCE2_SMB_NB_LT_BCC, DCE2_SMB_NB_LT_BCC_STR },
    { DCE2_SMB_NB_LT_DSIZE, DCE2_SMB_NB_LT_DSIZE_STR },
    { DCE2_SMB_TDCNT_LT_DSIZE, DCE2_SMB_TDCNT_LT_DSIZE_STR },
    { DCE2_SMB_DSENT_GT_TDCNT, DCE2_SMB_DSENT_GT_TDCNT_STR },
    { DCE2_SMB_BCC_LT_DSIZE, DCE2_SMB_BCC_LT_DSIZE_STR },
    { DCE2_SMB_INVALID_DSIZE, DCE2_SMB_INVALID_DSIZE_STR },
    { DCE2_SMB_EXCESSIVE_TREE_CONNECTS, DCE2_SMB_EXCESSIVE_TREE_CONNECTS_STR },
    { DCE2_SMB_EXCESSIVE_READS, DCE2_SMB_EXCESSIVE_READS_STR },
    { DCE2_SMB_EXCESSIVE_CHAINING, DCE2_SMB_EXCESSIVE_CHAINING_STR },
    { DCE2_SMB_MULT_CHAIN_SS, DCE2_SMB_MULT_CHAIN_SS_STR },
    { DCE2_SMB_MULT_CHAIN_TC, DCE2_SMB_MULT_CHAIN_TC_STR },
    { DCE2_SMB_CHAIN_SS_LOGOFF, DCE2_SMB_CHAIN_SS_LOGOFF_STR },
    { DCE2_SMB_CHAIN_TC_TDIS, DCE2_SMB_CHAIN_TC_TDIS_STR },
    { DCE2_SMB_CHAIN_OPEN_CLOSE, DCE2_SMB_CHAIN_OPEN_CLOSE_STR },
    { DCE2_SMB_INVALID_SHARE, DCE2_SMB_INVALID_SHARE_STR },

    { DCE2_SMB_V1, DCE2_SMB_V1_STR },
    { DCE2_SMB_V2, DCE2_SMB_V2_STR },
    { DCE2_SMB_INVALID_BINDING, DCE2_SMB_INVALID_BINDING_STR },
    { DCE2_SMB2_EXCESSIVE_COMPOUNDING, DCE2_SMB2_EXCESSIVE_COMPOUNDING_STR },
    { DCE2_SMB_DCNT_ZERO, DCE2_SMB_DCNT_ZERO_STR },
    { DCE2_SMB_MAX_REQS_EXCEEDED, DCE2_SMB_MAX_REQS_EXCEEDED_STR },
    { DCE2_SMB_REQS_SAME_MID, DCE2_SMB_REQS_SAME_MID_STR },
    { DCE2_SMB_DEPR_DIALECT_NEGOTIATED, DCE2_SMB_DEPR_DIALECT_NEGOTIATED_STR },
    { DCE2_SMB_DEPR_COMMAND_USED, DCE2_SMB_DEPR_COMMAND_USED_STR },
    { DCE2_SMB_UNUSUAL_COMMAND_USED, DCE2_SMB_UNUSUAL_COMMAND_USED_STR },
    { DCE2_SMB_INVALID_SETUP_COUNT, DCE2_SMB_INVALID_SETUP_COUNT_STR },
    { DCE2_SMB_MULTIPLE_NEGOTIATIONS, DCE2_SMB_MULTIPLE_NEGOTIATIONS_STR },
    { DCE2_SMB_EVASIVE_FILE_ATTRS, DCE2_SMB_EVASIVE_FILE_ATTRS_STR },
    { DCE2_SMB_INVALID_FILE_OFFSET, DCE2_SMB_INVALID_FILE_OFFSET_STR },
    { DCE2_SMB_BAD_NEXT_COMMAND_OFFSET, DCE2_SMB_BAD_NEXT_COMMAND_OFFSET_STR },
    { 0, nullptr }
};

static std::string get_shares(DCE2_List* shares)
{
    std::string cmds;

    if ( shares )
    {
        for (dce2SmbShare* share = (dce2SmbShare*)DCE2_ListFirst(shares);
            share;
            share = (dce2SmbShare*)DCE2_ListNext(shares))
        {
            cmds += share->ascii_str;
            cmds += " ";
        }
    }

    if ( !cmds.empty() )
        cmds.pop_back();
    else
        cmds += "none";

    return cmds;
}

Dce2SmbModule::Dce2SmbModule() : Module(DCE2_SMB_NAME, DCE2_SMB_HELP, s_params)
{
    memset(&config, 0, sizeof(config));
}

Dce2SmbModule::~Dce2SmbModule()
{
    if (config.smb_invalid_shares)
    {
        DCE2_ListDestroy(config.smb_invalid_shares);
    }
}

void Dce2SmbModule::set_trace(const Trace* trace) const
{ dce_smb_trace = trace; }

const TraceOption* Dce2SmbModule::get_trace_options() const
{
    static const TraceOption dce_smb_trace_options(nullptr, 0, nullptr);
    return &dce_smb_trace_options;
}

const RuleMap* Dce2SmbModule::get_rules() const
{
    return dce2_smb_rules;
}

const PegInfo* Dce2SmbModule::get_pegs() const
{
    return dce2_smb_pegs;
}

PegCount* Dce2SmbModule::get_counts() const
{
    return (PegCount*)&dce2_smb_stats;
}

ProfileStats* Dce2SmbModule::get_profile() const
{
    return &dce2_smb_pstat_main;
}

static int smb_invalid_share_compare(const void* a, const void* b)
{
    const dce2SmbShare* ashare = (const dce2SmbShare*)a;
    const dce2SmbShare* bshare = (const dce2SmbShare*)b;

    if ((ashare == nullptr) || (bshare == nullptr))
        return -1;

    /* Just check the ascii string */
    if (ashare->ascii_str_len != bshare->ascii_str_len)
        return -1;

    if (memcmp(ashare->ascii_str, bshare->ascii_str, ashare->ascii_str_len) == 0)
        return 0;

    /* Only care about equality for dups */
    return -1;
}

static void smb_invalid_share_free(void* data)
{
    dce2SmbShare* smb_share = (dce2SmbShare*)data;

    if (smb_share == nullptr)
        return;

    snort_free(smb_share->unicode_str);
    snort_free(smb_share->ascii_str);
    snort_free(smb_share);
}

static void set_smb_versions_mask(dce2SmbProtoConf& config, const char* s)
{
    config.smb_valid_versions_mask = 0;

    if ( strstr(s, "v1") )
    {
        config.smb_valid_versions_mask |= DCE2_VALID_SMB_VERSION_FLAG_V1;
    }
    if ( strstr(s, "v2") )
    {
        config.smb_valid_versions_mask |= DCE2_VALID_SMB_VERSION_FLAG_V2;
    }
    if ( strstr(s, "all") )
    {
        config.smb_valid_versions_mask = DCE2_VALID_SMB_VERSION_FLAG_V1;
        config.smb_valid_versions_mask |= DCE2_VALID_SMB_VERSION_FLAG_V2;
    }
}

static const char* get_smb_versions(uint16_t mask)
{
    switch (mask)
    {
    case DCE2_VALID_SMB_VERSION_FLAG_V1:
        return "v1";
    case DCE2_VALID_SMB_VERSION_FLAG_V2:
        return "v2";
    default:
        return "all";
    }
}

static bool set_smb_invalid_shares(dce2SmbProtoConf& config, Value& v)
{
    string tok;
    bool error = false;

    config.smb_invalid_shares =
        DCE2_ListNew(DCE2_LIST_TYPE__NORMAL, smb_invalid_share_compare,
        smb_invalid_share_free, smb_invalid_share_free,
        DCE2_LIST_FLAG__NO_DUPS | DCE2_LIST_FLAG__INS_TAIL);

    v.set_first_token();

    while ( v.get_next_token(tok) )
    {
        dce2SmbShare* smb_share;
        dce2SmbShare* smb_share_key;
        int i, j;
        DCE2_Ret status;
        const char* share  = tok.c_str();
        int share_len= strlen(share);

        smb_share = (dce2SmbShare*)snort_calloc(sizeof(dce2SmbShare));
        smb_share_key = (dce2SmbShare*)snort_calloc(sizeof(dce2SmbShare));

        smb_share->unicode_str_len = (share_len * 2) + 2;
        smb_share->unicode_str = (char*)snort_calloc(smb_share->unicode_str_len);

        smb_share->ascii_str_len = share_len + 1;
        smb_share->ascii_str = (char*)snort_calloc(smb_share->ascii_str_len);

        for (i = 0, j = 0; i < share_len; i++, j += 2)
        {
            smb_share->unicode_str[j] = toupper(share[i]);
            smb_share->ascii_str[i] =  toupper(share[i]);
        }

        /* Just use ascii share as the key */
        smb_share_key->ascii_str_len = smb_share->ascii_str_len;
        smb_share_key->ascii_str = (char*)snort_calloc(smb_share_key->ascii_str_len);

        memcpy(smb_share_key->ascii_str, smb_share->ascii_str, smb_share_key->ascii_str_len);

        status = DCE2_ListInsert(config.smb_invalid_shares, (void*)smb_share_key,
            (void*)smb_share);
        if (status == DCE2_RET__DUPLICATE)
        {
            /* Just free this share and move on */
            smb_invalid_share_free((void*)smb_share);
            smb_invalid_share_free((void*)smb_share_key);
        }
        else if (status != DCE2_RET__SUCCESS)
        {
            ErrorMessage("DCE2 - Failed to insert invalid share into list\n");
            error = true;
            break;
        }
    }
    if (error)
    {
        DCE2_ListDestroy(config.smb_invalid_shares);
        config.smb_invalid_shares = nullptr;
        return error;
    }

    return(true);
}

bool Dce2SmbModule::set(const char*, Value& v, SnortConfig*)
{
    if (dce2_set_co_config(v,config.common))
        return true;

    else if ( v.is("smb_fingerprint_policy") )
        config.smb_fingerprint_policy = (dce2SmbFingerprintPolicy)v.get_uint8();

    else if ( v.is("smb_max_chain") )
        config.smb_max_chain = v.get_uint8();

    else if ( v.is("smb_max_compound") )
        config.smb_max_compound = v.get_uint8();

    else if ( v.is("valid_smb_versions") )
        set_smb_versions_mask(config,v.get_string());

    else if ( v.is("smb_file_inspection") )
        ParseWarning(WARN_CONF, "smb_file_inspection is deprecated (not used): use smb_file_depth");

    else if ( v.is("smb_file_depth") )
        config.smb_file_depth = v.get_int16();

    else if ( v.is("smb_invalid_shares") )
        return(set_smb_invalid_shares(config,v));

    else if ( v.is("smb_legacy_mode"))
        config.legacy_mode = v.get_bool();

    else if ( v.is("smb_max_credit") )
        config.smb_max_credit = v.get_uint16();

    else if ( v.is("memcap") )
        config.memcap = v.get_size();

    return true;
}

void Dce2SmbModule::get_data(dce2SmbProtoConf& dce2_smb_config)
{
    dce2_smb_config = config; // includes pointer copy so set to null
    config.smb_invalid_shares = nullptr;
}

void print_dce2_smb_conf(const dce2SmbProtoConf& config)
{
    print_dce2_co_config(config.common);

    ConfigLogger::log_value("smb_fingerprint_policy",
        dce2SmbFingerprintPolicyStrings[config.smb_fingerprint_policy]);
    ConfigLogger::log_limit("smb_max_chain", config.smb_max_chain, 0, 1);
    ConfigLogger::log_limit("smb_max_compound", config.smb_max_compound, 0, 1);
    ConfigLogger::log_value("valid_smb_versions",
        get_smb_versions(config.smb_valid_versions_mask));
    ConfigLogger::log_limit("smb_file_depth", config.smb_file_depth, 0, -1);
    ConfigLogger::log_list("smb_invalid_shares",
        get_shares(config.smb_invalid_shares).c_str());
    ConfigLogger::log_flag("smb_legacy_mode", config.legacy_mode);
    ConfigLogger::log_limit("smb_max_credit", config.smb_max_credit, 0, 1);
}

