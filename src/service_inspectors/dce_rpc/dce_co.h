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
#include "dce_list.h"

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

struct DCE2_CoFragTracker
{
    DCE2_Buffer* cli_stub_buf;
    DCE2_Buffer* srv_stub_buf;

    int opnum;    /* Opnum that is ultimatley used for request */
    int ctx_id;   /* Context id that is ultimatley used for request */

    /* These are set on a first fragment received */
    int expected_call_id;  /* Expected call id for fragments */
    int expected_opnum;    /* Expected call id for fragments */
    int expected_ctx_id;   /* Expected call id for fragments */
};

struct DCE2_CoSeg
{
    DCE2_Buffer* buf;

    /* If there is enough data in segmentation buffer for header,
     * this will be set to the frag length in the header */
    uint16_t frag_len;
};

struct DCE2_CoTracker
{
    DCE2_List* ctx_ids;  /* splayed list so most recently used goes to front of list */
    int got_bind;        /* got an accepted bind */

    /* Queue of pending client bind or alter context request context items
     * Since the actual context id number doesn't have to occur sequentially
     * in the context list in the client packet, need to keep track to match
     * up server response since server doesn't reply with actual context id
     * numbers, but in the order they were in the client packet */
    DCE2_Queue* pending_ctx_ids;

    /* Keeps track of fragmentation buffer and frag specfic data */
    DCE2_CoFragTracker frag_tracker;

    int max_xmit_frag;    /* The maximum negotiated size of a client request */
    int data_byte_order;  /* Depending on policy is from bind or request */
    int ctx_id;           /* The current context id of the request */
    int opnum;            /* The current opnum of the request */
    int call_id;          /* The current call id of the request */
    const uint8_t* stub_data;   /* Current pointer to stub data in the request */

    /* For transport segmentation */
    DCE2_CoSeg cli_seg;
    DCE2_CoSeg srv_seg;
};

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

void DCE2_CoInitTracker(DCE2_CoTracker*);

#endif

