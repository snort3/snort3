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

// dce_common.cc author Rashmi Pitre <rrp@cisco.com>

#include "dce_common.h"
#include "framework/base_api.h"
#include "framework/module.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "main/snort_debug.h"

const char* dce2_get_policy_name(DCE2_POLICY policy)
{
    const char* policyStr = nullptr;
    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
        policyStr = DCE2_SARG__POLICY_WIN2000;
        break;
    case DCE2_POLICY__WINXP:
        policyStr = DCE2_SARG__POLICY_WINXP;
        break;
    case DCE2_POLICY__WINVISTA:
        policyStr = DCE2_SARG__POLICY_WINVISTA;
        break;
    case DCE2_POLICY__WIN2003:
        policyStr = DCE2_SARG__POLICY_WIN2003;
        break;
    case DCE2_POLICY__WIN2008:
        policyStr = DCE2_SARG__POLICY_WIN2008;
        break;
    case DCE2_POLICY__WIN7:
        policyStr = DCE2_SARG__POLICY_WIN7;
        break;
    case DCE2_POLICY__SAMBA:
        policyStr = DCE2_SARG__POLICY_SAMBA;
        break;
    case DCE2_POLICY__SAMBA_3_0_37:
        policyStr = DCE2_SARG__POLICY_SAMBA_3_0_37;
        break;
    case DCE2_POLICY__SAMBA_3_0_22:
        policyStr = DCE2_SARG__POLICY_SAMBA_3_0_22;
        break;
    case DCE2_POLICY__SAMBA_3_0_20:
        policyStr = DCE2_SARG__POLICY_SAMBA_3_0_20;
        break;
    default:
        policyStr = "Unknown";
    }
    return policyStr;
}

bool dce2_set_common_config(Value& v, dce2CommonProtoConf& common)
{
    if ( v.is("disable_defrag") )
        common.disable_defrag = v.get_bool();

    else if ( v.is("max_frag_len") )
        common.max_frag_len = v.get_long();

    else if ( v.is("policy") )
        common.policy = (DCE2_POLICY)v.get_long();
    else
        return false;
    return true;
}

void print_dce2_common_config(dce2CommonProtoConf& common)
{
    LogMessage("    Defragmentation: %s\n",
        common.disable_defrag ?
        "DISABLED" : "ENABLED");
    LogMessage("    Max Fragment length: %d\n",
        common.max_frag_len);
    LogMessage("    Policy : %s\n",
        dce2_get_policy_name(common.policy));
}

bool dce2_paf_abort(Flow* flow)
{
    if (flow->get_session_flags() & SSNFLAG_MIDSTREAM)
    {
        DebugMessage(DEBUG_DCE_TCP,
            "Aborting PAF because of midstream pickup.\n");
        return true;
    }
    else if (!(flow->get_session_flags() & SSNFLAG_ESTABLISHED))
    {
        DebugMessage(DEBUG_DCE_TCP,
            "Aborting PAF because of unestablished session.\n");
        return true;
    }
    // FIXIT-M add the remaining checks

    return false;
}

#ifdef BUILDING_SO

extern const BaseApi* ips_dce_iface;
extern const BaseApi* ips_dce_opnum;
extern const BaseApi* ips_dce_stub_data;

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dce2_tcp_api.base,
    &dce2_smb_api.base,
    ips_dce_iface,
    ips_dce_opnum,
    ips_dce_stub_data,
    nullptr
};
#else

const BaseApi* sin_dce_tcp = &dce2_tcp_api.base;
const BaseApi* sin_dce_smb = &dce2_smb_api.base;

#endif

