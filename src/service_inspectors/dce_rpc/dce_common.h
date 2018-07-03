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
//-------------------------------------------------------------------------

//dce_common.h author Rashmi Pitre <rrp@cisco.com>

#ifndef DCE_COMMON_H
#define DCE_COMMON_H

#include <cassert>

#include "detection/detection_engine.h"
#include "framework/counts.h"
#include "framework/endianness.h"
#include "framework/value.h"
#include "protocols/packet.h"

#include "dce_list.h"
#include "dce_context_data.h"

extern const snort::InspectApi dce2_smb_api;
extern const snort::InspectApi dce2_tcp_api;
extern const snort::InspectApi dce2_udp_api;
extern const snort::InspectApi dce_http_proxy_api;
extern const snort::InspectApi dce_http_server_api;
extern THREAD_LOCAL int dce2_detected;

#define GID_DCE2 133
#define DCE_RPC_SERVICE_NAME "dcerpc"

enum DCE2_Policy
{
    DCE2_POLICY__WIN2000 = 0,
    DCE2_POLICY__WINXP,
    DCE2_POLICY__WINVISTA,
    DCE2_POLICY__WIN2003,
    DCE2_POLICY__WIN2008,
    DCE2_POLICY__WIN7,
    DCE2_POLICY__SAMBA,
    DCE2_POLICY__SAMBA_3_0_37,
    DCE2_POLICY__SAMBA_3_0_22,
    DCE2_POLICY__SAMBA_3_0_20,
    DCE2_POLICY__MAX
};

struct dce2CommonStats
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
};
#define DCE2_SARG__POLICY_WIN2000       "Win2000"
#define DCE2_SARG__POLICY_WINXP         "WinXP"
#define DCE2_SARG__POLICY_WINVISTA      "WinVista"
#define DCE2_SARG__POLICY_WIN2003       "Win2003"
#define DCE2_SARG__POLICY_WIN2008       "Win2008"
#define DCE2_SARG__POLICY_WIN7          "Win7"
#define DCE2_SARG__POLICY_SAMBA         "Samba"
#define DCE2_SARG__POLICY_SAMBA_3_0_37  "Samba-3.0.37"  /* Samba version 3.0.37 and previous */
#define DCE2_SARG__POLICY_SAMBA_3_0_22  "Samba-3.0.22"  /* Samba version 3.0.22 and previous */
#define DCE2_SARG__POLICY_SAMBA_3_0_20  "Samba-3.0.20"  /* Samba version 3.0.20 and previous */

struct dce2CommonProtoConf
{
    bool disable_defrag;
    int max_frag_len;
};

struct dce2CoProtoConf
{
    dce2CommonProtoConf common;
    DCE2_Policy policy;
    uint16_t co_reassemble_threshold;
};

#define DCE2_DEBUG__PAF_END_MSG    "=========================================================="

enum DceRpcPduType
{
    DCERPC_PDU_TYPE__REQUEST = 0,
    DCERPC_PDU_TYPE__PING,
    DCERPC_PDU_TYPE__RESPONSE,
    DCERPC_PDU_TYPE__FAULT,
    DCERPC_PDU_TYPE__WORKING,
    DCERPC_PDU_TYPE__NOCALL,
    DCERPC_PDU_TYPE__REJECT,
    DCERPC_PDU_TYPE__ACK,
    DCERPC_PDU_TYPE__CL_CANCEL,
    DCERPC_PDU_TYPE__FACK,
    DCERPC_PDU_TYPE__CANCEL_ACK,
    DCERPC_PDU_TYPE__BIND,
    DCERPC_PDU_TYPE__BIND_ACK,
    DCERPC_PDU_TYPE__BIND_NACK,
    DCERPC_PDU_TYPE__ALTER_CONTEXT,
    DCERPC_PDU_TYPE__ALTER_CONTEXT_RESP,
    DCERPC_PDU_TYPE__AUTH3,
    DCERPC_PDU_TYPE__SHUTDOWN,
    DCERPC_PDU_TYPE__CO_CANCEL,
    DCERPC_PDU_TYPE__ORPHANED,
    DCERPC_PDU_TYPE__MICROSOFT_PROPRIETARY_OUTLOOK2003_RPC_OVER_HTTP,
    DCERPC_PDU_TYPE__MAX
};

/* Version 4 is for Connectionless
 * Version 5 is for Connection oriented */
enum DceRpcProtoMajorVers
{
    DCERPC_PROTO_MAJOR_VERS__4 = 4,
    DCERPC_PROTO_MAJOR_VERS__5 = 5
};

enum DceRpcProtoMinorVers
{
    DCERPC_PROTO_MINOR_VERS__0 = 0,
    DCERPC_PROTO_MINOR_VERS__1 = 1
};

enum DCE2_RpktType
{
    DCE2_RPKT_TYPE__NULL = 0,
    DCE2_RPKT_TYPE__SMB_SEG,
    DCE2_RPKT_TYPE__SMB_TRANS,
    DCE2_RPKT_TYPE__SMB_CO_SEG,
    DCE2_RPKT_TYPE__SMB_CO_FRAG,
    DCE2_RPKT_TYPE__TCP_CO_SEG,
    DCE2_RPKT_TYPE__TCP_CO_FRAG,
    DCE2_RPKT_TYPE__UDP_CL_FRAG,
    DCE2_RPKT_TYPE__MAX
};

struct DCE2_Roptions
{
    /* dce_iface */
    int first_frag;    /* Set to sentinel if not applicable */
    Uuid iface;
    /* For connectionless */
    uint32_t iface_vers;        /* For connectionless */

    /* For connection-oriented */
    uint16_t iface_vers_maj;
    uint16_t iface_vers_min;

    /* dce_opnum */
    int opnum;    /* Set to sentinel if not applicable */

    /* dce_stub_data */
    const uint8_t* stub_data;  /* Set to NULL if not applicable */
};

enum DCE2_SsnFlag
{
    DCE2_SSN_FLAG__NONE               = 0x0000,
    DCE2_SSN_FLAG__NO_INSPECT         = 0x0001,
    DCE2_SSN_FLAG__SMB2               = 0x0002,
    DCE2_SSN_FLAG__ALL                = 0xffff
};

struct DCE2_SsnData
{
    DCE2_TransType trans;
    DCE2_Policy server_policy;
    DCE2_Policy client_policy;
    int flags;
    snort::Packet* wire_pkt;
    uint64_t alert_mask;
    DCE2_Roptions ropts;
    void* config;

    uint32_t cli_seq;
    uint32_t cli_nseq;
    uint32_t srv_seq;
    uint32_t srv_nseq;
};

class DceEndianness : public snort::Endianness
{
public:
    int hdr_byte_order;   /* Set to sentinel if not applicable */
    int data_byte_order;  /* Set to sentinel if not applicable */
    int32_t stub_data_offset;  /* Set to sentinel if not applicable */

public:
    DceEndianness();
    bool get_offset_endianness(int32_t offset, uint8_t& endian) override;
    void reset();
};

inline void DCE2_ResetRopts(DCE2_SsnData* sd, snort::Packet* p)
{
    sd->ropts.first_frag = DCE2_SENTINEL;
    sd->ropts.opnum = DCE2_SENTINEL;
    sd->ropts.stub_data = nullptr;
    DceContextData::clear_current_ropts(p, sd->trans);
}

inline void DCE2_SsnSetNoInspect(DCE2_SsnData* sd)
{
    sd->flags |= DCE2_SSN_FLAG__NO_INSPECT;
}

inline int DCE2_SsnNoInspect(DCE2_SsnData* sd)
{
    return sd->flags & DCE2_SSN_FLAG__NO_INSPECT;
}

inline bool DCE2_GcDceDefrag(dce2CommonProtoConf* config)
{
    return (config->disable_defrag ? false : true);
}

inline bool DCE2_GcMaxFrag(dce2CommonProtoConf* config)
{
    if (config->max_frag_len != DCE2_SENTINEL)
        return true;
    return false;
}

inline uint16_t DCE2_GcMaxFragLen(dce2CommonProtoConf* config)
{
    if (DCE2_GcMaxFrag(config))
        return (uint16_t)config->max_frag_len;
    return UINT16_MAX;
}

inline int DCE2_SsnFromServer(snort::Packet* p)
{
    return p->is_from_server();
}

inline int DCE2_SsnFromClient(snort::Packet* p)
{
    return p->is_from_client();
}

inline DCE2_Policy DCE2_SsnGetPolicy(DCE2_SsnData* sd)
{
    assert(sd);

    if (DCE2_SsnFromClient(sd->wire_pkt))
        return sd->server_policy;
    else
        return sd->client_policy;
}

inline void DCE2_SsnSetPolicy(DCE2_SsnData* sd, DCE2_Policy policy)
{
    if (DCE2_SsnFromClient(sd->wire_pkt))
        sd->client_policy = policy;
    else
        sd->server_policy = policy;
}

/********************************************************************
 * Function: DCE2_SsnIsWindowsPolicy()
 *
 * Purpose:
 *  Convenience function to determine if policy traffic is going to
 *  is a Windows one.
 *
 * Arguments:
 *  DCE2_SsnData * - pointer to session data
 *
 * Returns:
 *  bool  -  true if Samba, false if not
 *
 ********************************************************************/
inline bool DCE2_SsnIsWindowsPolicy(DCE2_SsnData* sd)
{
    DCE2_Policy policy = DCE2_SsnGetPolicy(sd);

    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        return true;
    default:
        break;
    }

    return false;
}

/********************************************************************
 * Function: DCE2_SsnIsSambaPolicy()
 *
 * Purpose:
 *  Convenience function to determine if policy traffic is going to
 *  is a Samba one.
 *
 * Arguments:
 *  DCE2_SsnData * - pointer to session data
 *
 * Returns:
 *  bool  -  true if Samba, false if not
 *
 ********************************************************************/
inline bool DCE2_SsnIsSambaPolicy(DCE2_SsnData* sd)
{
    DCE2_Policy policy = DCE2_SsnGetPolicy(sd);

    switch (policy)
    {
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        return true;
    default:
        break;
    }

    return false;
}

inline DCE2_Policy DCE2_SsnGetServerPolicy(DCE2_SsnData* sd)
{
    return sd->server_policy;
}

/********************************************************************
 * Function: DCE2_SsnIsServerSambaPolicy()
 *
 * Purpose:
 *  Convenience function to determine if server policy is a
 *  Samba one.
 *
 * Arguments:
 *  DCE2_SsnData * - pointer to session data
 *
 * Returns:
 *  bool  -  true if Samba, false if not
 *
 ********************************************************************/
inline bool DCE2_SsnIsServerSambaPolicy(DCE2_SsnData* sd)
{
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);

    switch (policy)
    {
    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        return true;
    default:
        break;
    }

    return false;
}

inline void dce_alert(uint32_t gid, uint32_t sid, dce2CommonStats* stats)
{
    snort::DetectionEngine::queue_event(gid,sid);
    stats->events++;
}

bool dce2_set_common_config(snort::Value&, dce2CommonProtoConf&);
void print_dce2_common_config(dce2CommonProtoConf&);
bool dce2_set_co_config(snort::Value&, dce2CoProtoConf&);
void print_dce2_co_config(dce2CoProtoConf&);
bool dce2_paf_abort(snort::Flow*, DCE2_SsnData*);
void DCE2_Detect(DCE2_SsnData*);
snort::Packet* DCE2_GetRpkt(snort::Packet*, DCE2_RpktType, const uint8_t*, uint32_t);
uint16_t DCE2_GetRpktMaxData(DCE2_SsnData*, DCE2_RpktType);
DCE2_Ret DCE2_AddDataToRpkt(snort::Packet*, const uint8_t*, uint32_t);
DCE2_TransType get_dce2_trans_type(const snort::Packet* p);

#endif

