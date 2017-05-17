//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_common.h"

#include "detection/detection_engine.h"
#include "ips_options/extract.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/safec.h"

#include "dce_http_proxy_module.h"
#include "dce_http_server_module.h"
#include "dce_smb_utils.h"
#include "dce_tcp.h"
#include "dce_udp.h"

THREAD_LOCAL int dce2_detected = 0;
static THREAD_LOCAL bool using_rpkt = false;

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
    else
        return false;
    return true;
}

bool dce2_set_co_config(Value& v, dce2CoProtoConf& co)
{
    if (dce2_set_common_config(v, co.common))
        return true;
    else if ( v.is("policy") )
        co.policy = (DCE2_Policy)v.get_long();
    else if ( v.is("reassemble_threshold") )
        co.co_reassemble_threshold = v.get_long();
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
}

void print_dce2_co_config(dce2CoProtoConf& co)
{
    print_dce2_common_config(co.common);

    LogMessage("    Policy : %s\n",
        dce2_get_policy_name(co.policy));
    LogMessage("    Reassemble Threshold : %d\n",
        co.co_reassemble_threshold);
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
        DEBUG_WRAP(char uuid_buf[DCE2_UUID_BUF_SIZE];)
        DebugFormat(DEBUG_DCE_COMMON, "  Iface: %s\n",
            DCE2_UuidToStr(&ropts->iface, DCERPC_BO_FLAG__NONE, uuid_buf));
        DebugFormat(DEBUG_DCE_COMMON, "  Iface version: %hu\n", ropts->iface_vers_maj);
    }
    if (ropts->opnum == DCE2_SENTINEL)
        DebugMessage(DEBUG_DCE_COMMON, "  Opnum: unset\n");
    else
    {
        DebugFormat(DEBUG_DCE_COMMON, "  Opnum: %d\n", ropts->opnum);
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
        // FIXIT-M this doesn't look right; profile immediately goes out of scope
        Profile profile(dce2_tcp_pstat_detect);
    }
    else if (sd->trans == DCE2_TRANS_TYPE__SMB)
    {
        Profile profile(dce2_smb_pstat_detect);
    }
    else
    {
        Profile profile(dce2_udp_pstat_detect);
    }

    DetectionEngine::detect(pkt);

    dce2_detected = 1;
}

void DCE2_Detect(DCE2_SsnData* sd)
{
    if ( using_rpkt )
    {
        using_rpkt = false;
        DetectionEngine de;
        DCE2_Detect(sd);
        return;
    }
    Packet* top_pkt = DetectionEngine::get_current_packet();

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

    DCE2_UdpSsnData* udp_data = get_dce2_udp_session_data(p->flow);
    sd = (udp_data != nullptr) ? &(udp_data->sd) : nullptr;
    if ((sd != nullptr) && (sd->trans == DCE2_TRANS_TYPE__UDP))
    {
        return sd;
    }

    return nullptr;
}

DceEndianness::DceEndianness()
{
    hdr_byte_order = DCE2_SENTINEL;
    data_byte_order = DCE2_SENTINEL;
    stub_data_offset = DCE2_SENTINEL;
}

void DceEndianness::reset()
{
    hdr_byte_order = DCE2_SENTINEL;
    data_byte_order = DCE2_SENTINEL;
    stub_data_offset = DCE2_SENTINEL;
}

bool DceEndianness::get_offset_endianness(int32_t offset, uint8_t& endian)
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

uint16_t DCE2_GetRpktMaxData(DCE2_SsnData* sd, DCE2_RpktType rtype)
{
    Packet* p = sd->wire_pkt;
    uint16_t overhead = 0;

    switch (rtype)
    {
    case DCE2_RPKT_TYPE__SMB_SEG:
    case DCE2_RPKT_TYPE__SMB_TRANS:
        break;

    case DCE2_RPKT_TYPE__SMB_CO_SEG:
        if (DCE2_SsnFromClient(p))
            overhead += DCE2_MOCK_HDR_LEN__SMB_CLI;
        else
            overhead += DCE2_MOCK_HDR_LEN__SMB_SRV;
        break;

    case DCE2_RPKT_TYPE__SMB_CO_FRAG:
        if (DCE2_SsnFromClient(p))
            overhead += DCE2_MOCK_HDR_LEN__SMB_CLI + DCE2_MOCK_HDR_LEN__CO_CLI;
        else
            overhead += DCE2_MOCK_HDR_LEN__SMB_SRV + DCE2_MOCK_HDR_LEN__CO_SRV;
        break;

    case DCE2_RPKT_TYPE__TCP_CO_SEG:
        break;
    case DCE2_RPKT_TYPE__TCP_CO_FRAG:
        if (DCE2_SsnFromClient(p))
            overhead += DCE2_MOCK_HDR_LEN__CO_CLI;
        else
            overhead += DCE2_MOCK_HDR_LEN__CO_SRV;
        break;

    default:
        DebugFormat(DEBUG_DCE_COMMON,"Invalid reassembly packet type: %d\n",rtype);
        return 0;
    }
    return (Packet::max_dsize - overhead);
}

static void dce2_fill_rpkt_info(Packet* rpkt, Packet* p)
{
    rpkt->endianness = new DceEndianness();
    rpkt->pkth = p->pkth;
    rpkt->ptrs = p->ptrs;
    rpkt->flow = p->flow;
    rpkt->proto_bits = p->proto_bits;
    rpkt->packet_flags = p->packet_flags;
    rpkt->packet_flags |= PKT_PSEUDO;
    rpkt->user_policy_id = p->user_policy_id;
}

Packet* DCE2_GetRpkt(Packet* p,DCE2_RpktType rpkt_type,
    const uint8_t* data, uint32_t data_len)
{
    Packet* rpkt = DetectionEngine::set_next_packet();
    dce2_fill_rpkt_info(rpkt, p);
    uint16_t data_overhead = 0;

    switch (rpkt_type)
    {
    case DCE2_RPKT_TYPE__SMB_SEG:
        rpkt->pseudo_type = PSEUDO_PKT_SMB_SEG;
        break;

    case DCE2_RPKT_TYPE__SMB_TRANS:
        rpkt->pseudo_type = PSEUDO_PKT_SMB_TRANS;
        if (DCE2_SsnFromClient(p))
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_CLI;
            memset((void*)rpkt->data, 0, data_overhead);
            DCE2_SmbInitRdata((uint8_t*)rpkt->data, PKT_FROM_CLIENT);
        }
        else
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_SRV;
            memset((void*)rpkt->data, 0, data_overhead);
            DCE2_SmbInitRdata((uint8_t*)rpkt->data, PKT_FROM_SERVER);
        }
        break;

    case DCE2_RPKT_TYPE__SMB_CO_SEG:
        rpkt->pseudo_type = PSEUDO_PKT_DCE_SEG;
        if (DCE2_SsnFromClient(p))
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_CLI;
            memset((void*)rpkt->data, 0, data_overhead);
            DCE2_SmbInitRdata((uint8_t*)rpkt->data, PKT_FROM_CLIENT);
        }
        else
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_SRV;
            memset((void*)rpkt->data, 0, data_overhead);
            DCE2_SmbInitRdata((uint8_t*)rpkt->data, PKT_FROM_SERVER);
        }
        break;

    case DCE2_RPKT_TYPE__SMB_CO_FRAG:
        rpkt->pseudo_type = PSEUDO_PKT_DCE_FRAG;
        if (DCE2_SsnFromClient(p))
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_CLI + DCE2_MOCK_HDR_LEN__CO_CLI;
            memset((void*)rpkt->data, 0, data_overhead);
            DCE2_SmbInitRdata((uint8_t*)rpkt->data, PKT_FROM_CLIENT);
            DCE2_CoInitRdata((uint8_t*)rpkt->data +
                DCE2_MOCK_HDR_LEN__SMB_CLI, PKT_FROM_CLIENT);
        }
        else
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_SRV + DCE2_MOCK_HDR_LEN__CO_SRV;
            memset((void*)rpkt->data, 0, data_overhead);
            DCE2_SmbInitRdata((uint8_t*)rpkt->data, PKT_FROM_SERVER);
            DCE2_CoInitRdata((uint8_t*)rpkt->data +
                DCE2_MOCK_HDR_LEN__SMB_SRV, PKT_FROM_SERVER);
        }
        break;

    case DCE2_RPKT_TYPE__UDP_CL_FRAG:
        rpkt->pseudo_type = PSEUDO_PKT_DCE_FRAG;
        data_overhead = DCE2_MOCK_HDR_LEN__CL;
        memset((void*)rpkt->data, 0, data_overhead);
        DCE2_ClInitRdata((uint8_t*)rpkt->data);
        break;

    case DCE2_RPKT_TYPE__TCP_CO_SEG:
    case DCE2_RPKT_TYPE__TCP_CO_FRAG:
        if (rpkt_type == DCE2_RPKT_TYPE__TCP_CO_FRAG)
        {
            rpkt->pseudo_type = PSEUDO_PKT_DCE_FRAG;
            if (DCE2_SsnFromClient(p))
            {
                data_overhead = DCE2_MOCK_HDR_LEN__CO_CLI;
                memset((void*)rpkt->data, 0, data_overhead);
                DCE2_CoInitRdata((uint8_t*)rpkt->data, PKT_FROM_CLIENT);
            }
            else
            {
                data_overhead = DCE2_MOCK_HDR_LEN__CO_SRV;
                memset((void*)rpkt->data, 0, data_overhead);
                DCE2_CoInitRdata((uint8_t*)rpkt->data, PKT_FROM_SERVER);
            }
        }
        else
        {
            rpkt->pseudo_type = PSEUDO_PKT_DCE_SEG;
        }
        break;

    default:
        DebugFormat(DEBUG_DCE_COMMON, "Invalid reassembly packet type: %d\n",rpkt_type);
        assert(false);
        return nullptr;
    }

    if ((data_overhead + data_len) > Packet::max_dsize)
        data_len -= (data_overhead + data_len) - Packet::max_dsize;

    if (data_len > Packet::max_dsize - data_overhead)
    {
        DebugMessage(DEBUG_DCE_COMMON, "Failed to create reassembly packet.\n");
        delete rpkt->endianness;
        rpkt->endianness = nullptr;
        return nullptr;
    }

    memcpy_s((void*)(rpkt->data + data_overhead),
        Packet::max_dsize - data_overhead, data, data_len);

    rpkt->dsize = data_len + data_overhead;
    using_rpkt = true;
    return rpkt;
}

DCE2_Ret DCE2_AddDataToRpkt(Packet* rpkt, const uint8_t* data, uint32_t data_len)
{
    if ((rpkt == nullptr) || (data == nullptr) || (data_len == 0))
        return DCE2_RET__ERROR;

    if (rpkt->data == nullptr)
        return DCE2_RET__ERROR;

    // FIXIT-L PORT_IF_NEEDED packet size and hdr check
    const uint8_t* pkt_data_end = rpkt->data + Packet::max_dsize;
    const uint8_t* payload_end = rpkt->data + rpkt->dsize;

    if ((payload_end + data_len) > pkt_data_end)
        data_len = pkt_data_end - payload_end;

    if (data_len > Packet::max_dsize - rpkt->dsize)
        return DCE2_RET__ERROR;

    memcpy_s((void*)(payload_end), Packet::max_dsize - rpkt->dsize,
        data, data_len);

    rpkt->dsize += (uint16_t)data_len;
    return DCE2_RET__SUCCESS;
}

extern const BaseApi* ips_dce_iface;
extern const BaseApi* ips_dce_opnum;
extern const BaseApi* ips_dce_stub_data;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_dce[] =
#endif
{
    &dce2_tcp_api.base,
    &dce2_smb_api.base,
    &dce2_udp_api.base,
    &dce_http_proxy_api.base,
    &dce_http_server_api.base,
    ips_dce_iface,
    ips_dce_opnum,
    ips_dce_stub_data,
    nullptr
};
