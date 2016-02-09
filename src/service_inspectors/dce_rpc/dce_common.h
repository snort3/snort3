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
//-------------------------------------------------------------------------

//dce_common.h author Rashmi Pitre <rrp@cisco.com>

#ifndef DCE_COMMON_H
#define DCE_COMMON_H

#include "dce_utils.h"
#include "main/snort_types.h"
#include "framework/module.h"
#include "framework/inspector.h"

extern const InspectApi dce2_smb_api;
extern const InspectApi dce2_tcp_api;

#define GID_DCE2 145

enum DCE2_POLICY
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
    uint16_t max_frag_len;
    DCE2_POLICY policy;
};

#define DCE2_DEBUG__PAF_END_MSG    "=========================================================="

/* DCE/RPC byte order flag */
enum DceRpcBoFlag
{
    DCERPC_BO_FLAG__NONE,
    DCERPC_BO_FLAG__BIG_ENDIAN,
    DCERPC_BO_FLAG__LITTLE_ENDIAN
};

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

    /* dce_byte_test */
    int hdr_byte_order;   /* Set to sentinel if not applicable */
    int data_byte_order;  /* Set to sentinel if not applicable */

    /* dce_stub_data */
    const uint8_t* stub_data;  /* Set to NULL if not applicable */
};

struct DCE2_SsnData
{
    DCE2_POLICY server_policy;
    DCE2_POLICY client_policy;
    int flags;
    const Packet* wire_pkt;
    uint64_t alert_mask;
    DCE2_Roptions ropts;
    int autodetect_dir;

    uint32_t cli_seq;
    uint32_t cli_nseq;
    uint32_t srv_seq;
    uint32_t srv_nseq;
};

inline DceRpcBoFlag DceRpcByteOrder(const uint8_t value)
{
    if ((value & 0x10) >> 4)
        return DCERPC_BO_FLAG__LITTLE_ENDIAN;

    return DCERPC_BO_FLAG__BIG_ENDIAN;
}

inline uint16_t DceRpcNtohs(const uint16_t* ptr, const DceRpcBoFlag bo_flag)
{
    uint16_t value;

    if (ptr == NULL)
        return 0;

#ifdef WORDS_MUSTALIGN
    value = *((uint8_t*)ptr) << 8 | *((uint8_t*)ptr + 1);
#else
    value = *ptr;
#endif  /* WORDS_MUSTALIGN */

    if (bo_flag == DCERPC_BO_FLAG__NONE)
        return value;

#ifdef WORDS_BIGENDIAN
    if (bo_flag == DCERPC_BO_FLAG__BIG_ENDIAN)
#else
    if (bo_flag == DCERPC_BO_FLAG__LITTLE_ENDIAN)
#endif  /* WORDS_BIGENDIAN */
        return value;

    return ((value & 0xff00) >> 8) | ((value & 0x00ff) << 8);
}

bool dce2_set_common_config(Value&, dce2CommonProtoConf&);
void print_dce2_common_config(dce2CommonProtoConf&);
bool dce2_paf_abort(Flow*);

#endif

