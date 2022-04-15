//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "utils/safec.h"

#include "dce_context_data.h"
#include "dce_http_proxy_module.h"
#include "dce_http_server_module.h"
#include "dce_smb1.h"
#include "dce_smb_common.h"
#include "dce_smb_utils.h"
#include "dce_tcp.h"
#include "dce_udp.h"

using namespace snort;

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

bool dce2_set_common_config(const Value& v, dce2CommonProtoConf& common)
{
    if ( v.is("limit_alerts") )
        common.limit_alerts = v.get_bool();

    else if ( v.is("disable_defrag") )
        common.disable_defrag = v.get_bool();

    else if ( v.is("max_frag_len") )
        common.max_frag_len = v.get_uint16();

    else
        return false;

    return true;
}

bool dce2_set_co_config(const Value& v, dce2CoProtoConf& co)
{
    if (dce2_set_common_config(v, co.common))
        return true;

    else if ( v.is("policy") )
        co.policy = (DCE2_Policy)v.get_uint8();

    else if ( v.is("reassemble_threshold") )
        co.co_reassemble_threshold = v.get_uint16();

    else
        return false;

    return true;
}

void print_dce2_common_config(const dce2CommonProtoConf& common)
{
    ConfigLogger::log_flag("limit_alerts", common.limit_alerts);
    ConfigLogger::log_flag("disable_defrag", common.disable_defrag);
    ConfigLogger::log_value("max_frag_len", common.max_frag_len);
}

void print_dce2_co_config(const dce2CoProtoConf& co)
{
    print_dce2_common_config(co.common);

    ConfigLogger::log_value("policy", dce2_get_policy_name(co.policy));
    ConfigLogger::log_value("reassemble_threshold", co.co_reassemble_threshold);
}

bool dce2_paf_abort(DCE2_SsnData* sd)
{
    if ((sd != nullptr) && DCE2_SsnNoInspect(sd))
        return true;

    return false;
}

void DCE2_Detect(DCE2_SsnData* sd)
{
    if (!sd) return ;
    DceContextData::set_current_ropts(sd);
    if ( using_rpkt )
    {
        using_rpkt = false;
        DetectionEngine de;
        DCE2_Detect(sd);
        return;
    }
    Packet* top_pkt = DetectionEngine::get_current_packet();
    DetectionEngine::detect(top_pkt);
    dce2_detected = 1;
    /* Always reset rule option data after detecting */
    DCE2_ResetRopts(sd, top_pkt);
}

DCE2_TransType get_dce2_trans_type(const Packet* p)
{
    DCE2_SsnData* sd = get_dce2_session_data(p->flow);
    if ((sd != nullptr) && (sd->trans == DCE2_TRANS_TYPE__SMB))
    {
        return DCE2_TRANS_TYPE__SMB;
    }

    DCE2_TcpSsnData* tcp_data = get_dce2_tcp_session_data(p->flow);
    sd = (tcp_data != nullptr) ? &(tcp_data->sd) : nullptr;
    if ((sd != nullptr) && (sd->trans == DCE2_TRANS_TYPE__TCP))
    {
        return DCE2_TRANS_TYPE__TCP;
    }

    DCE2_UdpSsnData* udp_data = get_dce2_udp_session_data(p->flow);
    sd = (udp_data != nullptr) ? &(udp_data->sd) : nullptr;
    if ((sd != nullptr) && (sd->trans == DCE2_TRANS_TYPE__UDP))
    {
        return DCE2_TRANS_TYPE__UDP;
    }

    return DCE2_TRANS_TYPE__NONE;
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
        return false;

    if (stub_data_offset == DCE2_SENTINEL)
    {
        byte_order = (DceRpcBoFlag)hdr_byte_order;
    }
    else if (offset < stub_data_offset)
    {
        byte_order = (DceRpcBoFlag)hdr_byte_order;
    }
    else
    {
        byte_order = (DceRpcBoFlag)data_byte_order;
    }

    endian = (byte_order == DCERPC_BO_FLAG__BIG_ENDIAN) ? ENDIAN_BIG : ENDIAN_LITTLE;

    return true;
}

uint16_t DCE2_GetRpktMaxData(DCE2_RpktType rtype)
{
    Packet* p = DetectionEngine::get_current_packet();
    uint16_t overhead = 0;

    switch (rtype)
    {
    case DCE2_RPKT_TYPE__SMB_SEG:
    case DCE2_RPKT_TYPE__SMB_TRANS:
        break;

    case DCE2_RPKT_TYPE__SMB_CO_SEG:
        if (p->is_from_client())
            overhead += DCE2_MOCK_HDR_LEN__SMB_CLI;
        else
            overhead += DCE2_MOCK_HDR_LEN__SMB_SRV;
        break;

    case DCE2_RPKT_TYPE__SMB_CO_FRAG:
        if (p->is_from_client())
            overhead += DCE2_MOCK_HDR_LEN__SMB_CLI + DCE2_MOCK_HDR_LEN__CO_CLI;
        else
            overhead += DCE2_MOCK_HDR_LEN__SMB_SRV + DCE2_MOCK_HDR_LEN__CO_SRV;
        break;

    case DCE2_RPKT_TYPE__TCP_CO_SEG:
        break;
    case DCE2_RPKT_TYPE__TCP_CO_FRAG:
        if (p->is_from_client())
            overhead += DCE2_MOCK_HDR_LEN__CO_CLI;
        else
            overhead += DCE2_MOCK_HDR_LEN__CO_SRV;
        break;

    default:
        assert(false);
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
    rpkt->user_inspection_policy_id = p->user_inspection_policy_id;
    rpkt->user_ips_policy_id = p->user_ips_policy_id;
    rpkt->user_network_policy_id = p->user_network_policy_id;
}

Packet* DCE2_GetRpkt(Packet* p,DCE2_RpktType rpkt_type,
    const uint8_t* data, uint32_t data_len)
{
    Packet* rpkt = DetectionEngine::set_next_packet(p);
    uint8_t* wrdata = const_cast<uint8_t*>(rpkt->data);
    dce2_fill_rpkt_info(rpkt, p);
    uint16_t data_overhead = 0;

    switch (rpkt_type)
    {
    case DCE2_RPKT_TYPE__SMB_SEG:
        rpkt->pseudo_type = PSEUDO_PKT_SMB_SEG;
        break;

    case DCE2_RPKT_TYPE__SMB_TRANS:
        rpkt->pseudo_type = PSEUDO_PKT_SMB_TRANS;
        if (p->is_from_client())
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_CLI;
            memset(wrdata, 0, data_overhead);
            DCE2_SmbInitRdata(wrdata, PKT_FROM_CLIENT);
        }
        else
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_SRV;
            memset(wrdata, 0, data_overhead);
            DCE2_SmbInitRdata(wrdata, PKT_FROM_SERVER);
        }
        break;

    case DCE2_RPKT_TYPE__SMB_CO_SEG:
        rpkt->pseudo_type = PSEUDO_PKT_DCE_SEG;
        if (p->is_from_client())
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_CLI;
            memset(wrdata, 0, data_overhead);
            DCE2_SmbInitRdata(wrdata, PKT_FROM_CLIENT);
        }
        else
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_SRV;
            memset(wrdata, 0, data_overhead);
            DCE2_SmbInitRdata(wrdata, PKT_FROM_SERVER);
        }
        break;

    case DCE2_RPKT_TYPE__SMB_CO_FRAG:
        rpkt->pseudo_type = PSEUDO_PKT_DCE_FRAG;
        if (p->is_from_client())
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_CLI + DCE2_MOCK_HDR_LEN__CO_CLI;
            memset(wrdata, 0, data_overhead);
            DCE2_SmbInitRdata(wrdata, PKT_FROM_CLIENT);
            DCE2_CoInitRdata(wrdata +
                DCE2_MOCK_HDR_LEN__SMB_CLI, PKT_FROM_CLIENT);
        }
        else
        {
            data_overhead = DCE2_MOCK_HDR_LEN__SMB_SRV + DCE2_MOCK_HDR_LEN__CO_SRV;
            memset(wrdata, 0, data_overhead);
            DCE2_SmbInitRdata(wrdata, PKT_FROM_SERVER);
            DCE2_CoInitRdata(wrdata +
                DCE2_MOCK_HDR_LEN__SMB_SRV, PKT_FROM_SERVER);
        }
        break;

    case DCE2_RPKT_TYPE__UDP_CL_FRAG:
        rpkt->pseudo_type = PSEUDO_PKT_DCE_FRAG;
        data_overhead = DCE2_MOCK_HDR_LEN__CL;
        memset(wrdata, 0, data_overhead);
        DCE2_ClInitRdata(wrdata);
        break;

    case DCE2_RPKT_TYPE__TCP_CO_SEG:
    case DCE2_RPKT_TYPE__TCP_CO_FRAG:
        if (rpkt_type == DCE2_RPKT_TYPE__TCP_CO_FRAG)
        {
            rpkt->pseudo_type = PSEUDO_PKT_DCE_FRAG;
            if (p->is_from_client())
            {
                data_overhead = DCE2_MOCK_HDR_LEN__CO_CLI;
                memset(wrdata, 0, data_overhead);
                DCE2_CoInitRdata(wrdata, PKT_FROM_CLIENT);
            }
            else
            {
                data_overhead = DCE2_MOCK_HDR_LEN__CO_SRV;
                memset(wrdata, 0, data_overhead);
                DCE2_CoInitRdata(wrdata, PKT_FROM_SERVER);
            }
        }
        else
        {
            rpkt->pseudo_type = PSEUDO_PKT_DCE_SEG;
        }
        break;

    default:
        assert(false);
        return nullptr;
    }

    if ((data_overhead + data_len) > Packet::max_dsize)
        data_len -= (data_overhead + data_len) - Packet::max_dsize;

    if (data_len > Packet::max_dsize - data_overhead)
    {
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
