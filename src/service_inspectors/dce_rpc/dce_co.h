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

// dce_co.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE_CO_H
#define DCE_CO_H

#include "dce_common.h"

#define DCE2_CO_BAD_MAJOR_VERSION           27
#define DCE2_CO_BAD_MINOR_VERSION           28
#define DCE2_CO_BAD_PDU_TYPE                29
#define DCE2_CO_FRAG_LEN_LT_HDR             30
#define DCE2_CO_REM_FRAG_LEN_LT_SIZE        31
#define DCE2_CO_NO_CTX_ITEMS_SPECFD         32
#define DCE2_CO_NO_TFER_SYNTAX_SPECFD       33
#define DCE2_CO_FRAG_LT_MAX_XMIT_FRAG       34
#define DCE2_CO_FRAG_GT_MAX_XMIT_FRAG       35
#define DCE2_CO_ALTER_CHANGE_BYTE_ORDER     36
#define DCE2_CO_FRAG_DIFF_CALL_ID           37
#define DCE2_CO_FRAG_DIFF_OPNUM             38
#define DCE2_CO_FRAG_DIFF_CTX_ID            39

#define DCE2_CO_BAD_MAJOR_VERSION_STR  "Connection oriented DCE/RPC - Invalid major version."
#define DCE2_CO_BAD_MINOR_VERSION_STR  "Connection oriented DCE/RPC - Invalid minor version."
#define DCE2_CO_BAD_PDU_TYPE_STR       "Connection-oriented DCE/RPC - Invalid pdu type."
#define DCE2_CO_FRAG_LEN_LT_HDR_STR \
    "Connection-oriented DCE/RPC - Fragment length less than header size."
#define DCE2_CO_REM_FRAG_LEN_LT_SIZE_STR \
    "Connection-oriented DCE/RPC - Remaining fragment length less than size needed."
#define DCE2_CO_NO_CTX_ITEMS_SPECFD_STR \
    "Connection-oriented DCE/RPC - No context items specified."
#define DCE2_CO_NO_TFER_SYNTAX_SPECFD_STR \
    "Connection-oriented DCE/RPC -No transfer syntaxes specified."
#define DCE2_CO_FRAG_LT_MAX_XMIT_FRAG_STR \
    "Connection-oriented DCE/RPC - Fragment length on non-last fragment less than \
maximum negotiated fragment transmit size for client."
#define DCE2_CO_FRAG_GT_MAX_XMIT_FRAG_STR \
    "Connection-oriented DCE/RPC - Fragment length greater than \
maximum negotiated fragment transmit size."
#define DCE2_CO_ALTER_CHANGE_BYTE_ORDER_STR \
    "Connection-oriented DCE/RPC - Alter Context byte order different from Bind"
#define DCE2_CO_FRAG_DIFF_CALL_ID_STR \
    "Connection-oriented DCE/RPC - Call id of non first/last fragment different \
from call id established for fragmented request."
#define DCE2_CO_FRAG_DIFF_OPNUM_STR \
    "Connection-oriented DCE/RPC - Opnum of non first/last fragment different \
from opnum established for fragmented request."
#define DCE2_CO_FRAG_DIFF_CTX_ID_STR \
    "Connection-oriented DCE/RPC - Context id of non first/last fragment different \
from context id established for fragmented request."

#pragma pack(1)

struct DceRpcCoVersion
{
    uint8_t major;
    uint8_t minor;
};

/* Connection oriented common header */
struct DceRpcCoHdr
{
    DceRpcCoVersion pversion;
    uint8_t ptype;
    uint8_t pfc_flags;
    uint8_t packed_drep[4];
    uint16_t frag_length;
    uint16_t auth_length;
    uint32_t call_id;
};

#pragma pack()

inline uint8_t DceRpcCoVersMaj(const DceRpcCoHdr* co)
{
    return co->pversion.major;
}

inline uint8_t DceRpcCoVersMin(const DceRpcCoHdr* co)
{
    return co->pversion.minor;
}

inline DceRpcPduType DceRpcCoPduType(const DceRpcCoHdr* co)
{
    return (DceRpcPduType)co->ptype;
}

inline DceRpcBoFlag DceRpcCoByteOrder(const DceRpcCoHdr* co)
{
    return DceRpcByteOrder(co->packed_drep[0]);
}

inline uint16_t DceRpcCoFragLen(const DceRpcCoHdr* co)
{
    return DceRpcNtohs(&co->frag_length, DceRpcCoByteOrder(co));
}

#endif

