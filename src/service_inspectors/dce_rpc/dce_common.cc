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
#include "dce_tcp.h"
#include "dce_smb.h"
#include "framework/base_api.h"
#include "framework/module.h"
#include "flow/flow.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "detection/detect.h"
#include "ips_options/extract.h"

THREAD_LOCAL int dce2_detected = 0;

static const char* dce2_get_policy_name(DCE2_Policy policy)
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
        common.policy = (DCE2_Policy)v.get_long();
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

bool dce2_paf_abort(Flow* flow, DCE2_SsnData* sd)
{
    if (flow->get_session_flags() & SSNFLAG_MIDSTREAM)
    {
        DebugMessage(DEBUG_DCE_COMMON,
            "Aborting PAF because of midstream pickup.\n");
        return true;
    }
    else if (!(flow->get_session_flags() & SSNFLAG_ESTABLISHED))
    {
        DebugMessage(DEBUG_DCE_COMMON,
            "Aborting PAF because of unestablished session.\n");
        return true;
    }

    if ((sd != nullptr) && DCE2_SsnNoInspect(sd))
    {
        DebugMessage(DEBUG_DCE_COMMON, "Aborting PAF because of session data check.\n");
        return true;
    }

    return false;
}

static void DCE2_PrintRoptions(DCE2_Roptions* ropts)
{
    DebugFormat(DEBUG_DCE_COMMON,
        "  First frag: %s\n", ropts->first_frag == 1 ? "yes" : (ropts->first_frag == 0 ? "no" :
        "unset"));
    if (ropts->first_frag == DCE2_SENTINEL)
    {
        DebugMessage(DEBUG_DCE_COMMON, "  Iface: unset\n");
        DebugMessage(DEBUG_DCE_COMMON, "  Iface version: unset\n");
    }
    else
    {
        DebugFormat(DEBUG_DCE_COMMON, "  Iface: %s\n", DCE2_UuidToStr(&ropts->iface,
            DCERPC_BO_FLAG__NONE));
        DebugFormat(DEBUG_DCE_COMMON, "  Iface version: %u\n", ropts->iface_vers_maj);
    }
    if (ropts->opnum == DCE2_SENTINEL)
        DebugMessage(DEBUG_DCE_COMMON, "  Opnum: unset\n");
    else
    {
        DebugFormat(DEBUG_DCE_COMMON, "  Opnum: %u\n", ropts->opnum);
    }
    if (ropts->stub_data != nullptr)
        DebugFormat(DEBUG_DCE_COMMON, "  Stub data: %p\n", ropts->stub_data);
    else
    {
        DebugMessage(DEBUG_DCE_COMMON, "  Stub data: NULL\n");
    }
}

static void dce2_protocol_detect(DCE2_SsnData* sd, Packet* pkt)
{
    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_detect);
    }
    else
    {
        Profile profile(dce2_smb_pstat_detect);
    }

    // FIXIT - decide whether eventq push/pop is necessary once packet reassembly is supported
    //SnortEventqPush();
    snort_detect(pkt);
    //SnortEventqPop();

    dce2_detected = 1;
}

void DCE2_Detect(DCE2_SsnData* sd)
{
    Packet* top_pkt = sd->wire_pkt;
    //FIXIT-M  Get packet from stack

    DebugMessage(DEBUG_DCE_COMMON, "Detecting ------------------------------------------------\n");
    DebugMessage(DEBUG_DCE_COMMON, " Rule options:\n");
    DCE2_PrintRoptions(&sd->ropts);
    DebugMessage(DEBUG_DCE_COMMON, "Payload:\n");
    DCE2_PrintPktData(top_pkt->data, top_pkt->dsize);
    if (sd->ropts.stub_data != nullptr)
    {
        DebugMessage(DEBUG_DCE_COMMON,"\nStub data:\n");
        DCE2_PrintPktData(sd->ropts.stub_data,
            top_pkt->dsize - (sd->ropts.stub_data - top_pkt->data));
    }

    dce2_protocol_detect(sd, top_pkt);
    /* Always reset rule option data after detecting */
    DCE2_ResetRopts(&sd->ropts);
    DebugMessage(DEBUG_DCE_COMMON, "----------------------------------------------------------\n");
}

DCE2_SsnData* get_dce2_session_data(Packet* p)
{
    DCE2_SmbSsnData* smb_data = get_dce2_smb_session_data(p->flow);
    DCE2_SsnData* sd = (smb_data != nullptr) ? &(smb_data->sd) : nullptr;
    if ((sd != nullptr) && (sd->trans == DCE2_TRANS_TYPE__SMB))
    {
        return sd;
    }

    DCE2_TcpSsnData* tcp_data = get_dce2_tcp_session_data(p->flow);
    sd = (tcp_data != nullptr) ? &(tcp_data->sd) : nullptr;
    if ((sd != nullptr) && (sd->trans == DCE2_TRANS_TYPE__TCP))
    {
        return sd;
    }

    // FIXIT - add checks for http, udp once ported

    return nullptr;
}

DceEndianness::DceEndianness()
{
    hdr_byte_order = DCE2_SENTINEL;
    data_byte_order = DCE2_SENTINEL;
    stub_data_offset = DCE2_SENTINEL;
}

bool DceEndianness::get_offset_endianness(int32_t offset, int8_t& endian)
{
    int byte_order;

    if ((data_byte_order == DCE2_SENTINEL) ||
        (hdr_byte_order == DCE2_SENTINEL))
    {
        DebugMessage(DEBUG_DCE_COMMON,
            "Data byte order or header byte order not set "
            "in rule options - not evaluating.\n");
        return false;
    }

    if (stub_data_offset == DCE2_SENTINEL)
    {
        DebugMessage(DEBUG_DCE_COMMON, "Stub data is NULL.  "
            "Setting byte order to that of the header.\n");
        byte_order = (DceRpcBoFlag)hdr_byte_order;
    }
    else if (offset < stub_data_offset)
    {
        DebugMessage(DEBUG_DCE_COMMON,
            "Reading data in the header.  Setting byte order "
            "to that of the header.\n");
        byte_order = (DceRpcBoFlag)hdr_byte_order;
    }
    else
    {
        DebugMessage(DEBUG_DCE_COMMON,
            "Reading data in the stub.  Setting byte order "
            "to that of the stub data.\n");
        byte_order = (DceRpcBoFlag)data_byte_order;
    }

    endian = (byte_order == DCERPC_BO_FLAG__BIG_ENDIAN) ? ENDIAN_BIG : ENDIAN_LITTLE;
    DebugFormat(DEBUG_DCE_COMMON, " Byte order: %s\n",
        endian == ENDIAN_LITTLE ? "little endian" : "big endian");
    return true;
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

