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

#define DCE2_CO_BAD_MAJOR_VERSION_STR  "connection oriented DCE/RPC - invalid major version"
#define DCE2_CO_BAD_MINOR_VERSION_STR  "connection oriented DCE/RPC - invalid minor version"
#define DCE2_CO_BAD_PDU_TYPE_STR       "connection-oriented DCE/RPC - invalid PDU type"
#define DCE2_CO_FRAG_LEN_LT_HDR_STR \
    "connection-oriented DCE/RPC - fragment length less than header size"
#define DCE2_CO_REM_FRAG_LEN_LT_SIZE_STR \
    "connection-oriented DCE/RPC - remaining fragment length less than size needed"
#define DCE2_CO_NO_CTX_ITEMS_SPECFD_STR \
    "connection-oriented DCE/RPC - no context items specified"
#define DCE2_CO_NO_TFER_SYNTAX_SPECFD_STR \
    "connection-oriented DCE/RPC -no transfer syntaxes specified"
#define DCE2_CO_FRAG_LT_MAX_XMIT_FRAG_STR \
    "connection-oriented DCE/RPC - fragment length on non-last fragment less than \
maximum negotiated fragment transmit size for client"
#define DCE2_CO_FRAG_GT_MAX_XMIT_FRAG_STR \
    "connection-oriented DCE/RPC - fragment length greater than \
maximum negotiated fragment transmit size"
#define DCE2_CO_ALTER_CHANGE_BYTE_ORDER_STR \
    "connection-oriented DCE/RPC - alter context byte order different from bind"
#define DCE2_CO_FRAG_DIFF_CALL_ID_STR \
    "connection-oriented DCE/RPC - call id of non first/last fragment different \
from call id established for fragmented request"
#define DCE2_CO_FRAG_DIFF_OPNUM_STR \
    "connection-oriented DCE/RPC - opnum of non first/last fragment different \
from opnum established for fragmented request"
#define DCE2_CO_FRAG_DIFF_CTX_ID_STR \
    "connection-oriented DCE/RPC - context id of non first/last fragment different \
from context id established for fragmented request"

#define DCE2_MAX_XMIT_SIZE_FUZZ    500
#define DCE2_MOCK_HDR_LEN__CO_CLI   (sizeof(DceRpcCoHdr) + sizeof(DceRpcCoRequest))
#define DCE2_MOCK_HDR_LEN__CO_SRV   (sizeof(DceRpcCoHdr) + sizeof(DceRpcCoResponse))
#define DCE2_CO__MIN_ALLOC_SIZE     50
#define DCE2_LITTLE_ENDIAN 0x10

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

/* Bind */
struct DceRpcCoBind
{
    uint16_t max_xmit_frag;
    uint16_t max_recv_frag;
    uint32_t assoc_group_id;
    uint8_t n_context_elem;   /* number of context elements */
    uint8_t reserved;
    uint16_t reserved2;
};

struct DceRpcCoSynId
{
    Uuid if_uuid;
    uint32_t if_version;
};

struct DceRpcCoContElem
{
    uint16_t p_cont_id;
    uint8_t n_transfer_syn;  /* number of transfer syntaxes */
    uint8_t reserved;
    DceRpcCoSynId abstract_syntax;
};

struct DceRpcCoBindAck
{
    uint16_t max_xmit_frag;
    uint16_t max_recv_frag;
    uint32_t assoc_group_id;
    uint16_t sec_addr_len;
};

struct DceRpcCoContResult
{
    uint16_t result;
    uint16_t reason;
    DceRpcCoSynId transfer_syntax;
};

struct DceRpcCoAuthVerifier
{
    uint8_t auth_type;
    uint8_t auth_level;
    uint8_t auth_pad_length;
    uint8_t auth_reserved;
    uint32_t auth_context_id;
};

struct DceRpcCoRequest
{
    uint32_t alloc_hint;
    uint16_t context_id;
    uint16_t opnum;
};

struct DceRpcCoResponse
{
    uint32_t alloc_hint;
    uint16_t context_id;
    uint8_t cancel_count;
    uint8_t reserved;
};

struct DceRpcCoContResultList
{
    uint8_t n_results;
    uint8_t reserved;
    uint16_t reserved2;
};

typedef DceRpcCoBind DceRpcCoAltCtx;
typedef DceRpcCoBindAck DceRpcCoAltCtxResp;

#pragma pack()

struct DCE2_CoFragTracker
{
    DCE2_Buffer* cli_stub_buf;
    DCE2_Buffer* srv_stub_buf;

    int opnum;    /* Opnum that is ultimately used for request */
    int ctx_id;   /* Context id that is ultimately used for request */

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

    /* Keeps track of fragmentation buffer and frag specific data */
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

/*
 * Connection oriented
 */
enum DceRpcCoPfcFlags
{
    DCERPC_CO_PFC_FLAGS__FIRST_FRAG = 0x01,
    DCERPC_CO_PFC_FLAGS__LAST_FRAG = 0x02,
    DCERPC_CO_PFC_FLAGS__PENDING_CANCEL = 0x04,
    DCERPC_CO_PFC_FLAGS__RESERVED_1 = 0x08,
    DCERPC_CO_PFC_FLAGS__CONC_MPX = 0x10,
    DCERPC_CO_PFC_FLAGS__DID_NOT_EXECUTE = 0x20,
    DCERPC_CO_PFC_FLAGS__MAYBE = 0x40,
    DCERPC_CO_PFC_FLAGS__OBJECT_UUID = 0x80
};

enum DCE2_CoCtxState
{
    DCE2_CO_CTX_STATE__ACCEPTED,
    DCE2_CO_CTX_STATE__REJECTED,
    DCE2_CO_CTX_STATE__PENDING
};

struct DCE2_CoCtxIdNode
{
    uint16_t ctx_id;           /* The context id */
    Uuid iface;                /* The presentation syntax uuid for the interface */
    uint16_t iface_vers_maj;   /* The major version of the interface */
    uint16_t iface_vers_min;   /* The minor version of the interface */

    /* Whether or not the server accepted or rejected the client bind/alter context
     * request.  Initially set to pending until server response */
    DCE2_CoCtxState state;
};

enum DceRpcCoAuthLevelType
{
    DCERPC_CO_AUTH_LEVEL__NONE = 1,
    DCERPC_CO_AUTH_LEVEL__CONNECT,
    DCERPC_CO_AUTH_LEVEL__CALL,
    DCERPC_CO_AUTH_LEVEL__PKT,
    DCERPC_CO_AUTH_LEVEL__PKT_INTEGRITY,
    DCERPC_CO_AUTH_LEVEL__PKT_PRIVACY
};

enum DceRpcCoContDefResult
{
    DCERPC_CO_CONT_DEF_RESULT__ACCEPTANCE = 0,
    DCERPC_CO_CONT_DEF_RESULT__USER_REJECTION,
    DCERPC_CO_CONT_DEF_RESULT__PROVIDER_REJECTION
};

enum DCE2_CoRpktType
{
    DCE2_CO_RPKT_TYPE__SEG,
    DCE2_CO_RPKT_TYPE__FRAG,
    DCE2_CO_RPKT_TYPE__ALL
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

inline uint8_t DceRpcCoNumCtxItems(const DceRpcCoBind* cob)
{
    return cob->n_context_elem;
}

inline uint16_t DceRpcCoContElemCtxId(const DceRpcCoHdr* co, const DceRpcCoContElem* coce)
{
    return DceRpcNtohs(&coce->p_cont_id, DceRpcCoByteOrder(co));
}

inline uint8_t DceRpcCoContElemNumTransSyntaxes(const DceRpcCoContElem* coce)
{
    return coce->n_transfer_syn;
}

inline const Uuid* DceRpcCoContElemIface(const DceRpcCoContElem* coce)
{
    return &coce->abstract_syntax.if_uuid;
}

inline uint16_t DceRpcCoContElemIfaceVersMaj(const DceRpcCoHdr* co, const DceRpcCoContElem* coce)
{
    return (uint16_t)(DceRpcNtohl(&coce->abstract_syntax.if_version, DceRpcCoByteOrder(co)) &
           0x0000ffff);
}

inline uint16_t DceRpcCoContElemIfaceVersMin(const DceRpcCoHdr* co, const DceRpcCoContElem* coce)
{
    return (uint16_t)(DceRpcNtohl(&coce->abstract_syntax.if_version, DceRpcCoByteOrder(co)) >> 16);
}

inline uint16_t DceRpcCoBindAckMaxRecvFrag(const DceRpcCoHdr* co, const DceRpcCoBindAck* coba)
{
    return DceRpcNtohs(&coba->max_recv_frag, DceRpcCoByteOrder(co));
}

inline uint16_t DceRpcCoSecAddrLen(const DceRpcCoHdr* co, const DceRpcCoBindAck* coba)
{
    return DceRpcNtohs(&coba->sec_addr_len, DceRpcCoByteOrder(co));
}

inline uint16_t DceRpcCoContRes(const DceRpcCoHdr* co, const DceRpcCoContResult* cocr)
{
    return DceRpcNtohs(&cocr->result, DceRpcCoByteOrder(co));
}

inline int DceRpcCoObjectFlag(const DceRpcCoHdr* co)
{
    return co->pfc_flags & DCERPC_CO_PFC_FLAGS__OBJECT_UUID;
}

inline int DceRpcCoFirstFrag(const DceRpcCoHdr* co)
{
    return co->pfc_flags & DCERPC_CO_PFC_FLAGS__FIRST_FRAG;
}

inline int DceRpcCoLastFrag(const DceRpcCoHdr* co)
{
    return co->pfc_flags & DCERPC_CO_PFC_FLAGS__LAST_FRAG;
}

inline uint16_t DceRpcCoAuthLen(const DceRpcCoHdr* co)
{
    return DceRpcNtohs(&co->auth_length, DceRpcCoByteOrder(co));
}

inline uint8_t DceRpcCoAuthLevel(const DceRpcCoAuthVerifier* coav)
{
    return coav->auth_level;
}

inline uint16_t DceRpcCoAuthPad(const DceRpcCoAuthVerifier* coav)
{
    return coav->auth_pad_length;
}

inline uint16_t DceRpcCoCtxIdResp(const DceRpcCoHdr* co, const DceRpcCoResponse* cor)
{
    return DceRpcNtohs(&cor->context_id, DceRpcCoByteOrder(co));
}

inline uint16_t DceRpcCoBindMaxXmitFrag(const DceRpcCoHdr* co, const DceRpcCoBind* cob)
{
    return DceRpcNtohs(&cob->max_xmit_frag, DceRpcCoByteOrder(co));
}

inline uint8_t DceRpcCoContNumResults(const DceRpcCoContResultList* cocrl)
{
    return cocrl->n_results;
}

inline uint32_t DceRpcCoCallId(const DceRpcCoHdr* co)
{
    return DceRpcNtohl(&co->call_id, DceRpcCoByteOrder(co));
}

inline uint16_t DceRpcCoOpnum(const DceRpcCoHdr* co, const DceRpcCoRequest* cor)
{
    return DceRpcNtohs(&cor->opnum, DceRpcCoByteOrder(co));
}

inline uint16_t DceRpcCoCtxId(const DceRpcCoHdr* co, const DceRpcCoRequest* cor)
{
    return DceRpcNtohs(&cor->context_id, DceRpcCoByteOrder(co));
}

void DCE2_CoInitTracker(DCE2_CoTracker*);
void DCE2_CoProcess(DCE2_SsnData*, DCE2_CoTracker*,
    const uint8_t*, uint16_t);
void DCE2_CoInitRdata(uint8_t*, int);
void DCE2_CoCleanTracker(DCE2_CoTracker*);

#endif

