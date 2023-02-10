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
//
// dce_smb_module.h author Rashmi Pitre <rrp@cisco.com>

#ifndef DCE_SMB_MODULE_H
#define DCE_SMB_MODULE_H

#include "framework/module.h"

#include "dce_common.h"
#include "dce_list.h"

namespace snort
{
class Trace;
struct SnortConfig;
}

extern THREAD_LOCAL const snort::Trace* dce_smb_trace;

#define DCE2_VALID_SMB_VERSION_FLAG_V1 1
#define DCE2_VALID_SMB_VERSION_FLAG_V2 2

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
#define DCE2_SMB_MULT_CHAIN_SS_STR   "SMB - Multiple chained login requests"
#define DCE2_SMB_MULT_CHAIN_TC_STR   "SMB - Multiple chained tree connect requests"
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

enum dce2SmbFingerprintPolicy
{
    DCE2_SMB_FINGERPRINT_POLICY_NONE = 0,
    DCE2_SMB_FINGERPRINT_POLICY_CLIENT,
    DCE2_SMB_FINGERPRINT_POLICY_SERVER,
    DCE2_SMB_FINGERPRINT_POLICY_BOTH,
};

struct dce2SmbShare
{
    char* unicode_str;
    unsigned int unicode_str_len;
    char* ascii_str;
    unsigned int ascii_str_len;
};

struct dce2SmbProtoConf
{
    dce2CoProtoConf common; // This member must be first
    dce2SmbFingerprintPolicy smb_fingerprint_policy;
    uint8_t smb_max_chain;
    uint8_t smb_max_compound;
    uint16_t smb_valid_versions_mask;
    int16_t smb_file_depth;
    DCE2_List* smb_invalid_shares;
    bool legacy_mode;
    uint16_t smb_max_credit;
    size_t memcap;
};

class Dce2SmbModule : public snort::Module
{
public:
    Dce2SmbModule();
    ~Dce2SmbModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_DCE2; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    void get_data(dce2SmbProtoConf&);

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    dce2SmbProtoConf config;
};

void print_dce2_smb_conf(const dce2SmbProtoConf&);

inline int64_t DCE2_ScSmbFileDepth(const dce2SmbProtoConf* sc)
{
    return sc->smb_file_depth;
}

inline uint8_t DCE2_ScSmbMaxChain(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return 0;
    return sc->smb_max_chain;
}

inline DCE2_List* DCE2_ScSmbInvalidShares(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return nullptr;
    return sc->smb_invalid_shares;
}

#define SMB_DEFAULT_MAX_CREDIT        8192
#define SMB_DEFAULT_MEMCAP            8388608
#define SMB_DEFAULT_MAX_COMPOUND_REQ  3

inline uint16_t DCE2_ScSmbMaxCredit(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return SMB_DEFAULT_MAX_CREDIT;
    return sc->smb_max_credit;
}

inline size_t DCE2_ScSmbMemcap(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return SMB_DEFAULT_MEMCAP;
    return sc->memcap;
}

inline uint16_t DCE2_ScSmbMaxCompound(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return SMB_DEFAULT_MAX_COMPOUND_REQ;
    return sc->smb_max_compound;
}

inline bool DCE2_GcSmbFingerprintClient(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return false;
    return (sc->smb_fingerprint_policy
           & DCE2_SMB_FINGERPRINT_POLICY_CLIENT) ? true : false;
}

inline bool DCE2_GcSmbFingerprintServer(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return false;
    return (sc->smb_fingerprint_policy
           & DCE2_SMB_FINGERPRINT_POLICY_SERVER) ? true : false;
}

inline bool DCE2_GcIsLegacyMode(const dce2SmbProtoConf* sc)
{
    if (sc == nullptr)
        return false;
    return sc->legacy_mode;
}

#endif

