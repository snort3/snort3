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

// dce_smb_module.cc author Rashmi Pitre <rrp@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_module.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "utils/util.h"

#include "dce_smb.h"

using namespace snort;
using namespace std;

Trace TRACE_NAME(dce_smb);

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
    { CountType::SUM, "max_outstanding_requests", "total smb maximum outstanding requests" },
    { CountType::SUM, "files_processed", "total smb files processed" },
    { CountType::SUM, "smbv2_create", "total number of SMBv2 create packets seen" },
    { CountType::SUM, "smbv2_write", "total number of SMBv2 write packets seen" },
    { CountType::SUM, "smbv2_read", "total number of SMBv2 read packets seen" },
    { CountType::SUM, "smbv2_set_info", "total number of SMBv2 set info packets seen" },
    { CountType::SUM, "smbv2_tree_connect", "total number of SMBv2 tree connect packets seen" },
    { CountType::SUM, "smbv2_tree_disconnect",
        "total number of SMBv2 tree disconnect packets seen" },
    { CountType::SUM, "smbv2_close", "total number of SMBv2 close packets seen" },
    { CountType::NOW, "concurrent_sessions", "total concurrent sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent sessions" },
    { CountType::END, nullptr, nullptr }
};

static const char* dce2SmbFingerprintPolicyStrings[] =
{ "Disabled", "Client","Server", "Client and Server" };

static const Parameter s_params[] =
{
    { "disable_defrag", Parameter::PT_BOOL, nullptr, "false",
      " Disable DCE/RPC defragmentation" },
    { "max_frag_len", Parameter::PT_INT, "1514:65535", "65535",
      " Maximum fragment size for defragmentation" },
    { "reassemble_threshold", Parameter::PT_INT, "0:65535", "0",
      " Minimum bytes received before performing reassembly" },
    { "smb_fingerprint_policy", Parameter::PT_ENUM,
      "none | client |  server | both ", "none",
      " Target based SMB policy to use" },
    { "policy", Parameter::PT_ENUM,
      "Win2000 |  WinXP | WinVista | Win2003 | Win2008 | Win7 | Samba | Samba-3.0.37 | Samba-3.0.22 | Samba-3.0.20",
      "WinXP",
      " Target based policy to use" },
    { "smb_max_chain", Parameter::PT_INT, "0:255", "3",
      " SMB max chain size" },
    { "smb_max_compound", Parameter::PT_INT, "0:255", "3",
      " SMB max compound size" },
    { "valid_smb_versions", Parameter::PT_MULTI,
      "v1 | v2 | all", "all",
      " Valid SMB versions" },
    { "smb_file_inspection", Parameter::PT_ENUM,
      "off | on | only", "off",
      " SMB file inspection" },
    { "smb_file_depth", Parameter::PT_INT, "-1:", "16384",
      " SMB file depth for file data" },
    { "smb_invalid_shares", Parameter::PT_STRING, nullptr, nullptr,
      "SMB shares to alert on " },
    { "smb_legacy_mode", Parameter::PT_BOOL, nullptr, "false",
      "inspect only SMBv1" },
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

Dce2SmbModule::Dce2SmbModule() : Module(DCE2_SMB_NAME, DCE2_SMB_HELP, s_params, false, &TRACE_NAME(dce_smb))
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

ProfileStats* Dce2SmbModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "dce_smb_main";
        parent = nullptr;
        return &dce2_smb_pstat_main;

    case 1:
        name = "dce_smb_session";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_session;

    case 2:
        name = "dce_smb_new_session";
        parent = "dce_smb_session";

        return &dce2_smb_pstat_new_session;

    case 3:
        name = "dce_smb_detect";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_detect;

    case 4:
        name = "dce_smb_log";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_log;

    case 5:
        name = "dce_smb_co_segment";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_co_seg;

    case 6:
        name = "dce_smb_co_fragment";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_co_frag;

    case 7:
        name = "dce_smb_co_reassembly";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_co_reass;

    case 8:
        name = "dce_smb_co_context";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_co_ctx;

    case 9:
        name = "dce_smb_segment";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_seg;

    case 10:
        name = "dce_smb_request";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_req;

    case 11:
        name = "dce_smb_uid";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_uid;

    case 12:
        name = "dce_smb_tid";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_tid;

    case 13:
        name = "dce_smb_fid";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_fid;

    case 14:
        name = "dce_smb_file";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_file;

    case 15:
        name = "dce_smb_file_detect";
        parent = "dce_smb_file";
        return &dce2_smb_pstat_smb_file_detect;

    case 16:
        name = "dce_smb_file_api";
        parent = "dce_smb_file";
        return &dce2_smb_pstat_smb_file_api;

    case 17:
        name = "dce_smb_fingerprint";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_fingerprint;

    case 18:
        name = "dce_smb_negotiate";
        parent = "dce_smb_main";
        return &dce2_smb_pstat_smb_negotiate;
    }
    return nullptr;
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

bool Dce2SmbModule::set(const char* fqn, snort::Value& v, snort::SnortConfig* c)
{
    if (dce2_set_co_config(v,config.common))
        return true;
    else if ( v.is("smb_fingerprint_policy") )
        config.smb_fingerprint_policy = (dce2SmbFingerprintPolicy)v.get_long();
    else if ( v.is("smb_max_chain") )
        config.smb_max_chain = v.get_long();
    else if ( v.is("smb_max_compound") )
        config.smb_max_compound = v.get_long();
    else if ( v.is("valid_smb_versions") )
        set_smb_versions_mask(config,v.get_string());
    else if ( v.is("smb_file_inspection") )
        config.smb_file_inspection = (dce2SmbFileInspection)v.get_long();
    else if ( v.is("smb_file_depth") )
        config.smb_file_depth = v.get_long();
    else if ( v.is("smb_invalid_shares") )
        return(set_smb_invalid_shares(config,v));
    else if ( v.is("smb_legacy_mode"))
        config.legacy_mode = v.get_bool();
    else
        return Module::set(fqn, v, c);
    return true;
}

void Dce2SmbModule::get_data(dce2SmbProtoConf& dce2_smb_config)
{
    dce2_smb_config = config; // includes pointer copy so set to NULL
    config.smb_invalid_shares = nullptr;
}

void print_dce2_smb_conf(dce2SmbProtoConf& config)
{
    LogMessage("DCE SMB config: \n");

    print_dce2_co_config(config.common);
    LogMessage("    SMB fingerprint policy : %s\n",
        dce2SmbFingerprintPolicyStrings[config.smb_fingerprint_policy]);

    if (config.smb_max_chain == 0)
        LogMessage("    Maximum SMB command chaining: Unlimited\n");
    else if (config.smb_max_chain == 1)
        LogMessage("    Maximum SMB command chaining: No chaining allowed\n");
    else
        LogMessage("    Maximum SMB command chaining: %u\n", config.smb_max_chain);

    if (config.smb_max_compound == 0)
        LogMessage("    Maximum SMB compounded requests: Unlimited\n");
    else if (config.smb_max_compound == 1)
        LogMessage("    Maximum SMB compounded requests: No compounding allowed\n");
    else
        LogMessage("    Maximum SMB compounded requests: %u\n", config.smb_max_compound);

    if (config.smb_file_inspection == DCE2_SMB_FILE_INSPECTION_OFF)
    {
        LogMessage("    SMB file inspection: Disabled\n");
    }
    else
    {
        if (config.smb_file_inspection == DCE2_SMB_FILE_INSPECTION_ONLY)
            LogMessage("    SMB file inspection: Only\n");
        else
            LogMessage("    SMB file inspection: Enabled\n");

        if (config.smb_file_depth == -1)
            LogMessage("    SMB file depth: Disabled\n");
        else if (config.smb_file_depth == 0)
            LogMessage("    SMB file depth: Unlimited\n");
        else
            LogMessage("    SMB file depth: %d\n",config.smb_file_depth);
    }

    if (config.smb_valid_versions_mask  == DCE2_VALID_SMB_VERSION_FLAG_V1)
    {
        LogMessage("    SMB valid versions : v1\n");
    }
    else if (config.smb_valid_versions_mask  == DCE2_VALID_SMB_VERSION_FLAG_V2)
    {
        LogMessage("    SMB valid versions : v2\n");
    }
    else
    {
        LogMessage("    SMB valid versions : all\n");
    }
    if (config.smb_invalid_shares != nullptr)
    {
        dce2SmbShare* share;

        LogMessage("    Invalid SMB shares:\n");

        for (share = (dce2SmbShare*)DCE2_ListFirst(config.smb_invalid_shares);
            share != nullptr;
            share = (dce2SmbShare*)DCE2_ListNext(config.smb_invalid_shares))
        {
            LogMessage("    %s\n",share->ascii_str);
        }
    }
    if (config.legacy_mode)
        LogMessage("    SMB legacy mode enabled\n");
}

