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

// dce_co.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_co.h"

#include "utils/util.h"

#include "dce_smb.h"
#include "dce_smb_module.h"
#include "dce_smb_utils.h"
#include "dce_tcp.h"
#include "dce_tcp_module.h"

using namespace snort;

static THREAD_LOCAL int co_reassembled = 0;

/********************************************************************
 * Function: DCE2_CoInitTracker()
 *
 * Initializes fields in the connection-oriented tracker to
 * sentinels.  Many decisions are made based on whether or not
 * these fields have been set.
 *
 ********************************************************************/
void DCE2_CoInitTracker(DCE2_CoTracker* cot)
{
    if (cot == nullptr)
        return;

    cot->max_xmit_frag = DCE2_SENTINEL;
    cot->data_byte_order = DCE2_SENTINEL;
    cot->ctx_id = DCE2_SENTINEL;
    cot->opnum = DCE2_SENTINEL;
    cot->call_id = DCE2_SENTINEL;
    cot->stub_data = nullptr;
    cot->got_bind = 0;

    cot->frag_tracker.opnum = DCE2_SENTINEL;
    cot->frag_tracker.ctx_id = DCE2_SENTINEL;
    cot->frag_tracker.expected_call_id = DCE2_SENTINEL;
    cot->frag_tracker.expected_opnum = DCE2_SENTINEL;
    cot->frag_tracker.expected_ctx_id = DCE2_SENTINEL;
}

/********************************************************************
 * Function: DCE2_CoResetFragTracker()
 *
 * Resets frag tracker fields after having reassembled.
 *
 ********************************************************************/
static inline void DCE2_CoResetFragTracker(DCE2_CoFragTracker* ft)
{
    if (ft == nullptr)
        return;

    ft->opnum = DCE2_SENTINEL;
    ft->ctx_id = DCE2_SENTINEL;
    ft->expected_call_id = DCE2_SENTINEL;
    ft->expected_ctx_id = DCE2_SENTINEL;
    ft->expected_opnum = DCE2_SENTINEL;
}

/********************************************************************
 * Function: DCE2_CoResetTracker()
 *
 * Resets fields that are transient for requests after the bind or
 * alter context.  The context id and opnum are dependent on the
 * request and in the case of fragmented requests are set until all
 * fragments are received.  If we got a full request or all of the
 * fragments, these should be reset.
 *
 ********************************************************************/
static inline void DCE2_CoResetTracker(DCE2_CoTracker* cot)
{
    if (cot == nullptr)
        return;

    cot->ctx_id = DCE2_SENTINEL;
    cot->opnum = DCE2_SENTINEL;
    cot->call_id = DCE2_SENTINEL;
    cot->stub_data = nullptr;

    DCE2_CoResetFragTracker(&cot->frag_tracker);
}

/********************************************************************
 * Function: DCE2_CoCleanTracker()
 *
 * Destroys all dynamically allocated data associated with
 * connection-oriented tracker.
 *
 ********************************************************************/
void DCE2_CoCleanTracker(DCE2_CoTracker* cot)
{
    if (cot == nullptr)
        return;

    DCE2_BufferDestroy(cot->frag_tracker.cli_stub_buf);
    cot->frag_tracker.cli_stub_buf = nullptr;

    DCE2_BufferDestroy(cot->frag_tracker.srv_stub_buf);
    cot->frag_tracker.srv_stub_buf = nullptr;

    DCE2_BufferDestroy(cot->cli_seg.buf);
    cot->cli_seg.buf = nullptr;

    DCE2_BufferDestroy(cot->srv_seg.buf);
    cot->srv_seg.buf = nullptr;

    DCE2_ListDestroy(cot->ctx_ids);
    cot->ctx_ids = nullptr;

    DCE2_QueueDestroy(cot->pending_ctx_ids);
    cot->pending_ctx_ids = nullptr;

    DCE2_CoInitTracker(cot);
}

/********************************************************************
 * Function: DCE2_CoSetRdata()
 *
 * Sets relevant fields in the defragmentation reassembly packet
 * based on data gathered from the session and reassembly phase.
 * The reassembly buffer used is big enough for the headers.
 *
 ********************************************************************/
static inline void DCE2_CoSetRdata(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    uint8_t* co_ptr, uint16_t stub_len)
{
    DceRpcCoHdr* co_hdr = (DceRpcCoHdr*)co_ptr;
    /* If we've set the fragment tracker context id or opnum, use them. */
    uint16_t ctx_id =
        (cot->frag_tracker.ctx_id != DCE2_SENTINEL) ?
        (uint16_t)cot->frag_tracker.ctx_id : (uint16_t)cot->ctx_id;
    uint16_t opnum =
        (cot->frag_tracker.opnum != DCE2_SENTINEL) ?
        (uint16_t)cot->frag_tracker.opnum : (uint16_t)cot->opnum;

    if (DCE2_SsnFromClient(sd->wire_pkt))
    {
        DceRpcCoRequest* co_req = (DceRpcCoRequest*)((uint8_t*)co_hdr + sizeof(DceRpcCoHdr));
        /* Doesn't really matter if this wraps ... it is basically just for presentation */
        uint16_t flen = sizeof(DceRpcCoHdr) + sizeof(DceRpcCoRequest) + stub_len;

        co_hdr->frag_length = DceRpcHtons(&flen, DCERPC_BO_FLAG__LITTLE_ENDIAN);
        co_req->context_id = DceRpcHtons(&ctx_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);
        co_req->opnum = DceRpcHtons(&opnum, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    }
    else
    {
        DceRpcCoResponse* co_resp = (DceRpcCoResponse*)((uint8_t*)co_hdr + sizeof(DceRpcCoHdr));
        uint16_t flen = sizeof(DceRpcCoHdr) + sizeof(DceRpcCoResponse) + stub_len;

        co_hdr->frag_length = DceRpcHtons(&flen, DCERPC_BO_FLAG__LITTLE_ENDIAN);
        co_resp->context_id = DceRpcHtons(&ctx_id, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    }
}

/********************************************************************
 * Function: DCE2_CoInitRdata()
 *
 * Initializes header of defragmentation reassembly packet.
 * Sets relevant fields in header that will not have to change
 * from reassembly to reassembly.  The reassembly buffer used is
 * big enough for the header.
 *
 ********************************************************************/
void DCE2_CoInitRdata(uint8_t* co_ptr, int dir)
{
    DceRpcCoHdr* co_hdr = (DceRpcCoHdr*)co_ptr;

    /* Set some relevant fields.  These should never get reset */
    co_hdr->pversion.major = DCERPC_PROTO_MAJOR_VERS__5;
    co_hdr->pfc_flags = (DCERPC_CO_PFC_FLAGS__FIRST_FRAG | DCERPC_CO_PFC_FLAGS__LAST_FRAG);
    co_hdr->packed_drep[0] = DCE2_LITTLE_ENDIAN;   /* Little endian */

    if (dir == PKT_FROM_CLIENT)
        co_hdr->ptype = DCERPC_PDU_TYPE__REQUEST;
    else
        co_hdr->ptype = DCERPC_PDU_TYPE__RESPONSE;
}

static inline DCE2_CoSeg* DCE2_CoGetSegPtr(DCE2_SsnData* sd, DCE2_CoTracker* cot)
{
    if (DCE2_SsnFromServer(sd->wire_pkt))
        return &cot->srv_seg;

    return &cot->cli_seg;
}

/********************************************************************
 * Function: DCE2_CoSetIface()
 *
 * Sets the interface UUID for the rules options.  Looks in the
 * context id list.  If nothing found there, it looks in the pending
 * list (in case we never saw the server response because of
 * missed packets) to see if something is there.
 *
 ********************************************************************/
static DCE2_Ret DCE2_CoSetIface(DCE2_SsnData* sd, DCE2_CoTracker* cot, uint16_t ctx_id)
{
    /* This should be set if we've gotten a Bind */
    if (cot->ctx_ids == nullptr)
        return DCE2_RET__ERROR;
    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_ctx);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_ctx);
    }
    // FIXIT-M add HTTP, UDP cases when these are ported
    // same for all other instances of profiling

    DCE2_CoCtxIdNode* ctx_id_node =
        (DCE2_CoCtxIdNode*)DCE2_ListFind(cot->ctx_ids, (void*)(uintptr_t)ctx_id);

    if (ctx_id_node == nullptr)  /* context id not found in list */
    {
        /* See if it's in the queue.  An easy evasion would be to stagger the writes
         * and reads such that we see a request before seeing the server bind ack */
        if (cot->pending_ctx_ids != nullptr)
        {
            for (ctx_id_node = (DCE2_CoCtxIdNode*)DCE2_QueueFirst(cot->pending_ctx_ids);
                ctx_id_node != nullptr;
                ctx_id_node = (DCE2_CoCtxIdNode*)DCE2_QueueNext(cot->pending_ctx_ids))
            {
                if (ctx_id_node->ctx_id == ctx_id)
                    break;
            }
        }

        if (ctx_id_node == nullptr)
        {
            return DCE2_RET__ERROR;
        }
    }

    if (ctx_id_node->state == DCE2_CO_CTX_STATE__REJECTED)
    {
        return DCE2_RET__ERROR;
    }

    DCE2_CopyUuid(&sd->ropts.iface, &ctx_id_node->iface, DCERPC_BO_FLAG__NONE);
    sd->ropts.iface_vers_maj = ctx_id_node->iface_vers_maj;
    sd->ropts.iface_vers_min = ctx_id_node->iface_vers_min;

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_CoSetRopts()
 *
 * Sets values necessary for the rule options.
 *
 ********************************************************************/
static inline void DCE2_CoSetRopts(DCE2_SsnData* sd, DCE2_CoTracker* cot, const
    DceRpcCoHdr* co_hdr, Packet* p)
{
    DCE2_CoFragTracker* ft = &cot->frag_tracker;
    int opnum = (ft->opnum != DCE2_SENTINEL) ? ft->opnum : cot->opnum;
    int ctx_id = (ft->ctx_id != DCE2_SENTINEL) ? ft->ctx_id : cot->ctx_id;

    int data_byte_order =
        (cot->data_byte_order != DCE2_SENTINEL) ?
        cot->data_byte_order : (int)DceRpcCoByteOrder(co_hdr);

    if (DCE2_CoSetIface(sd, cot, (uint16_t)ctx_id) != DCE2_RET__SUCCESS)
        sd->ropts.first_frag = DCE2_SENTINEL;
    else
        sd->ropts.first_frag = DceRpcCoFirstFrag(co_hdr);

    DceEndianness* endianness = (DceEndianness*)p->endianness;
    endianness->hdr_byte_order = DceRpcCoByteOrder(co_hdr);
    endianness->data_byte_order = data_byte_order;
    sd->ropts.opnum = opnum;
    sd->ropts.stub_data = cot->stub_data;
    endianness->stub_data_offset = cot->stub_data - p->data;
}

static inline dce2CommonStats* dce_get_proto_stats_ptr(DCE2_SsnData* sd)
{
    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        return((dce2CommonStats*)&dce2_tcp_stats);
    }
    else
    {
        return((dce2CommonStats*)&dce2_smb_stats);
    }
    // FIXIT-M add HTTP, UDP cases when these are ported
}

// FIXIT-L revisit to check if early reassembly functionality is required
static inline bool DCE2_GcReassembleEarly(DCE2_SsnData* sd)
{
    void* config = sd->config;
    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        if (((dce2TcpProtoConf*)config)->common.co_reassemble_threshold > 0)
            return true;
    }
    else
    {
        if (((dce2SmbProtoConf*)config)->common.co_reassemble_threshold > 0)
            return true;
    }
    return false;
}

static inline uint16_t DCE2_GcReassembleThreshold(DCE2_SsnData* sd)
{
    void* config = sd->config;
    if (DCE2_GcReassembleEarly(sd))
    {
        if (sd->trans == DCE2_TRANS_TYPE__TCP)
        {
            return ((dce2TcpProtoConf*)config)->common.co_reassemble_threshold;
        }
        else
        {
            return ((dce2SmbProtoConf*)config)->common.co_reassemble_threshold;
        }
    }
    return UINT16_MAX;
}

/********************************************************************
 * Function: DCE2_CoHdrChecks()
 *
 * Checks some relevant fields in the header to make sure they're
 * sane.
 *
 ********************************************************************/
static DCE2_Ret DCE2_CoHdrChecks(DCE2_SsnData* sd, DCE2_CoTracker* cot, const DceRpcCoHdr* co_hdr)
{
    uint16_t frag_len = DceRpcCoFragLen(co_hdr);
    DceRpcPduType pdu_type = DceRpcCoPduType(co_hdr);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (frag_len < sizeof(DceRpcCoHdr))
    {
        /* Assume that DCE/RPC is not running
         * over the SMB named pipe */
        if (sd->trans != DCE2_TRANS_TYPE__SMB)
        {
            // FIXIT-L PORT_IF_NEEDED segment check, same for all cases below
            dce_alert(GID_DCE2, DCE2_CO_FRAG_LEN_LT_HDR,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }

    if (DceRpcCoVersMaj(co_hdr) != DCERPC_PROTO_MAJOR_VERS__5)
    {
        if (sd->trans != DCE2_TRANS_TYPE__SMB)
        {
            dce_alert(GID_DCE2, DCE2_CO_BAD_MAJOR_VERSION,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }

    if (DceRpcCoVersMin(co_hdr) != DCERPC_PROTO_MINOR_VERS__0)
    {
        if (sd->trans != DCE2_TRANS_TYPE__SMB)
        {
            dce_alert(GID_DCE2, DCE2_CO_BAD_MINOR_VERSION,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }
    if (pdu_type >= DCERPC_PDU_TYPE__MAX)
    {
        if (sd->trans != DCE2_TRANS_TYPE__SMB)
        {
            dce_alert(GID_DCE2, DCE2_CO_BAD_PDU_TYPE,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }

    if (DCE2_SsnFromClient(sd->wire_pkt) && (cot->max_xmit_frag != DCE2_SENTINEL))
    {
        if (frag_len > cot->max_xmit_frag)
        {
            dce_alert(GID_DCE2, DCE2_CO_FRAG_GT_MAX_XMIT_FRAG,dce_common_stats);
        }
        else if (!DceRpcCoLastFrag(co_hdr) && (pdu_type == DCERPC_PDU_TYPE__REQUEST)
            && ((((int)cot->max_xmit_frag - DCE2_MAX_XMIT_SIZE_FUZZ) < 0)
            || ((int)frag_len < ((int)cot->max_xmit_frag - DCE2_MAX_XMIT_SIZE_FUZZ))))
        {
            /* If client needs to fragment the DCE/RPC request, it shouldn't be less than the
             * maximum xmit size negotiated. Only if it's not a last fragment. Make this alert
             * only if it is considerably less - have seen legitimate fragments that are just
             * slightly less the negotiated fragment size. */

            dce_alert(GID_DCE2, DCE2_CO_FRAG_LT_MAX_XMIT_FRAG,dce_common_stats);
        }

        /* Continue processing */
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_CoCtxCompare()
 *
 * Callback to context id list for finding the right interface
 * UUID node.  Values passed in are context ids which are used as
 * the keys for the list.
 *
 ********************************************************************/
static int DCE2_CoCtxCompare(const void* a, const void* b)
{
    int x = (int)(uintptr_t)a;
    int y = (int)(uintptr_t)b;

    if (x == y)
        return 0;

    /* Only care about equality for finding */
    return -1;
}

/********************************************************************
 * Function: DCE2_CoCtxFree()
 *
 * Callback to context id list for freeing context id nodes in
 * the list.
 *
 ********************************************************************/
static void DCE2_CoCtxFree(void* data)
{
    if (data == nullptr)
        return;

    snort_free(data);
}

/********************************************************************
 * Function: DCE2_CoInitCtxStorage()
 *
 * Allocates, if necessary, and initializes the context id list
 * and the context id pending queue.
 *
 *
 ********************************************************************/
static inline DCE2_Ret DCE2_CoInitCtxStorage(DCE2_CoTracker* cot)
{
    if (cot == nullptr)
        return DCE2_RET__ERROR;

    if (cot->ctx_ids == nullptr)
    {
        cot->ctx_ids = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_CoCtxCompare, DCE2_CoCtxFree,
            nullptr, DCE2_LIST_FLAG__NO_DUPS);
        if (cot->ctx_ids == nullptr)
            return DCE2_RET__ERROR;
    }

    if (cot->pending_ctx_ids == nullptr)
    {
        cot->pending_ctx_ids = DCE2_QueueNew(DCE2_CoCtxFree);
        if (cot->pending_ctx_ids == nullptr)
        {
            DCE2_ListDestroy(cot->ctx_ids);
            cot->ctx_ids = nullptr;
            return DCE2_RET__ERROR;
        }
    }
    else if (!DCE2_QueueIsEmpty(cot->pending_ctx_ids))
    {
        DCE2_QueueEmpty(cot->pending_ctx_ids);
    }

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_CoEraseCtxIds()
 *
 * Empties out the context id list and the pending context id
 * queue.  Does not free the list and queue - might need to still
 * use them.
 *
 ********************************************************************/
static inline void DCE2_CoEraseCtxIds(DCE2_CoTracker* cot)
{
    if (cot == nullptr)
        return;

    DCE2_QueueEmpty(cot->pending_ctx_ids);
    DCE2_ListEmpty(cot->ctx_ids);
}

static DCE2_CoCtxIdNode* dce_co_process_ctx_id(DCE2_SsnData* sd,DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr,DCE2_Policy policy,
    const uint8_t*& frag_ptr, uint16_t frag_len)
{
    DCE2_CoCtxIdNode* ctx_node;
    DCE2_Ret status;
    uint16_t ctx_id;
    uint8_t num_tsyns;
    const Uuid* iface;
    uint16_t if_vers_maj;
    uint16_t if_vers_min;
    const DceRpcCoContElem* ctx_elem = (const DceRpcCoContElem*)frag_ptr;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    int j;

    if (frag_len < sizeof(DceRpcCoContElem))
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE, dce_common_stats);
        return nullptr;
    }

    ctx_id = DceRpcCoContElemCtxId(co_hdr, ctx_elem);
    num_tsyns = DceRpcCoContElemNumTransSyntaxes(ctx_elem);
    iface = DceRpcCoContElemIface(ctx_elem);
    if_vers_maj = DceRpcCoContElemIfaceVersMaj(co_hdr, ctx_elem);
    if_vers_min = DceRpcCoContElemIfaceVersMin(co_hdr, ctx_elem);

    /* No transfer syntaxes */
    if (num_tsyns == 0)
    {
        dce_alert(GID_DCE2, DCE2_CO_NO_TFER_SYNTAX_SPECFD,dce_common_stats);
        return nullptr;
    }

    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoContElem));

    /* Don't really care about the transfer syntaxes */
    for (j = 0; j < num_tsyns; j++)
    {
        if (frag_len < sizeof(DceRpcCoSynId))
        {
            dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE, dce_common_stats);
            return nullptr;
        }

        DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoSynId));
    }
    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_ctx);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_ctx);
    }

    /* If there is already an accepted node with in the list
     * with this ctx, just return */
    if (policy == DCE2_POLICY__SAMBA_3_0_20)
    {
        ctx_node = (DCE2_CoCtxIdNode*)DCE2_ListFind(cot->ctx_ids, (void*)(uintptr_t)ctx_id);
        if ((ctx_node != nullptr) && (ctx_node->state != DCE2_CO_CTX_STATE__REJECTED))
        {
            return nullptr;
        }
    }

    ctx_node = (DCE2_CoCtxIdNode*)snort_calloc(sizeof(DCE2_CoCtxIdNode));

    /* Add context id to pending queue */
    status = DCE2_QueueEnqueue(cot->pending_ctx_ids, ctx_node);

    if (status != DCE2_RET__SUCCESS)
    {
        snort_free(ctx_node);
        return nullptr;
    }

    /* This node will get moved to the context id list upon server response */
    ctx_node->ctx_id = ctx_id;
    DCE2_CopyUuid(&ctx_node->iface, iface, DceRpcCoByteOrder(co_hdr));
    ctx_node->iface_vers_maj = if_vers_maj;
    ctx_node->iface_vers_min = if_vers_min;
    ctx_node->state = DCE2_CO_CTX_STATE__PENDING;
    return ctx_node;
}

/********************************************************************
 * Function: DCE2_CoCtxReq()
 *
 * Handles parsing the context id list out of the packet.
 * Context ids and associated uuids are stored in a queue and
 * dequeued upon server response.  Server response doesn't
 * indicate by context id which bindings were accepted or
 * rejected, but the index or order they were in in the client
 * bind or alter context, hence the queue.
 *
 ********************************************************************/
static void DCE2_CoCtxReq(DCE2_SsnData* sd, DCE2_CoTracker* cot, const DceRpcCoHdr* co_hdr,
    const uint8_t num_ctx_items, const uint8_t* frag_ptr, uint16_t frag_len)
{
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);
    unsigned int i;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (num_ctx_items == 0)
    {
        dce_alert(GID_DCE2, DCE2_CO_NO_CTX_ITEMS_SPECFD, dce_common_stats);
        return;
    }

    for (i = 0; i < num_ctx_items; i++)
    {
        DCE2_CoCtxIdNode* ctx_node;

        ctx_node = dce_co_process_ctx_id(sd,cot,co_hdr,policy,frag_ptr,frag_len);
        if (ctx_node == nullptr)
        {
            return;
        }

        switch (policy)
        {
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            /* Samba only ever looks at one context item.  Not sure
             * if this is an alertable offense */
            return;

        default:
            break;
        }
    }
}

static void dce_co_process_ctx_result(DCE2_SsnData* sd,DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr,DCE2_Policy policy,
    uint16_t result)
{
    DCE2_CoCtxIdNode* ctx_node, * existing_ctx_node;
    DCE2_Ret status;

    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_ctx);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_ctx);
    }

    /* Dequeue context item in pending queue - this will get put in the permanent
     * context id list or freed */
    ctx_node = (DCE2_CoCtxIdNode*)DCE2_QueueDequeue(cot->pending_ctx_ids);
    if (ctx_node == nullptr)
    {
        return;
    }

    if (result == DCERPC_CO_CONT_DEF_RESULT__ACCEPTANCE)
    {
        ctx_node->state = DCE2_CO_CTX_STATE__ACCEPTED;
        if (DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__BIND_ACK)
            cot->got_bind = 1;
    }
    else
    {
        ctx_node->state = DCE2_CO_CTX_STATE__REJECTED;
        cot->got_bind = 0;
    }

    existing_ctx_node =
        (DCE2_CoCtxIdNode*)DCE2_ListFind(cot->ctx_ids, (void*)(uintptr_t)ctx_node->ctx_id);

    if (existing_ctx_node != nullptr)
    {
        switch (policy)
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (ctx_node->state == DCE2_CO_CTX_STATE__REJECTED)
                break;

            if (existing_ctx_node->state == DCE2_CO_CTX_STATE__REJECTED)
            {
                existing_ctx_node->ctx_id = ctx_node->ctx_id;
                DCE2_CopyUuid(&existing_ctx_node->iface, &ctx_node->iface, DCERPC_BO_FLAG__NONE);
                existing_ctx_node->iface_vers_maj = ctx_node->iface_vers_maj;
                existing_ctx_node->iface_vers_min = ctx_node->iface_vers_min;
                existing_ctx_node->state = ctx_node->state;
            }

            break;

        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            /* Samba actually alters the context.  Windows keeps the old */
            if (ctx_node->state != DCE2_CO_CTX_STATE__REJECTED)
            {
                existing_ctx_node->ctx_id = ctx_node->ctx_id;
                DCE2_CopyUuid(&existing_ctx_node->iface, &ctx_node->iface, DCERPC_BO_FLAG__NONE);
                existing_ctx_node->iface_vers_maj = ctx_node->iface_vers_maj;
                existing_ctx_node->iface_vers_min = ctx_node->iface_vers_min;
                existing_ctx_node->state = ctx_node->state;
            }

            break;

        default:
            break;
        }

        snort_free((void*)ctx_node);
    }
    else
    {
        status = DCE2_ListInsert(cot->ctx_ids, (void*)(uintptr_t)ctx_node->ctx_id,
            (void*)ctx_node);
        if (status != DCE2_RET__SUCCESS)
        {
            snort_free((void*)ctx_node);
            return;
        }
    }
}

/********************************************************************
 * Function: DCE2_CoBindAck()
 *
 * Handles the processing of a server bind ack or a server alter
 * context response since they share the same header.
 * Moves context id items from the pending queue into a list
 * ultimately used by the rule options and sets each context item
 * as accepted or rejected based on the server response.
 *
 ********************************************************************/
static void DCE2_CoBindAck(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr, uint16_t frag_len)
{
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);
    const DceRpcCoBindAck* bind_ack = (const DceRpcCoBindAck*)frag_ptr;
    uint16_t sec_addr_len;
    const uint8_t* ctx_data;
    uint16_t ctx_len;
    uint16_t pad = 0;
    const DceRpcCoContResultList* ctx_list;
    uint8_t num_ctx_results;
    unsigned int i;
    uint16_t max_recv_frag;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (frag_len < sizeof(DceRpcCoBindAck))
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoBindAck));

    /* Set what should be the maximum amount of data a client can send in a fragment */
    max_recv_frag = DceRpcCoBindAckMaxRecvFrag(co_hdr, bind_ack);
    if ((cot->max_xmit_frag == DCE2_SENTINEL) || (max_recv_frag < cot->max_xmit_frag))
        cot->max_xmit_frag = (int)max_recv_frag;

    sec_addr_len = DceRpcCoSecAddrLen(co_hdr, bind_ack);

    ctx_data = frag_ptr;
    ctx_len = frag_len;

    /* First move past secondary address */
    if (ctx_len < sec_addr_len)
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    DCE2_MOVE(ctx_data, ctx_len, sec_addr_len);

    /* padded to 4 octet */
    if ((sizeof(DceRpcCoBindAck) + sec_addr_len) & 3)
        pad = (4 - ((sizeof(DceRpcCoBindAck) + sec_addr_len) & 3));

    if (ctx_len < pad)
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    DCE2_MOVE(ctx_data, ctx_len, pad);

    /* Now we're at the start of the context item results */
    if (ctx_len < sizeof(DceRpcCoContResultList))
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    ctx_list = (const DceRpcCoContResultList*)ctx_data;
    num_ctx_results = DceRpcCoContNumResults(ctx_list);

    DCE2_MOVE(ctx_data, ctx_len, sizeof(DceRpcCoContResultList));

    for (i = 0; i < num_ctx_results; i++)
    {
        const DceRpcCoContResult* ctx_result;
        uint16_t result;

        if (ctx_len < sizeof(DceRpcCoContResult))
        {
            dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
            return;
        }
        ctx_result = (const DceRpcCoContResult*)ctx_data;
        result = DceRpcCoContRes(co_hdr, ctx_result);

        DCE2_MOVE(ctx_data, ctx_len, sizeof(DceRpcCoContResult));

        if (DCE2_QueueIsEmpty(cot->pending_ctx_ids))
            return;

        dce_co_process_ctx_result(sd,cot,co_hdr,policy,result);
    }
}

/********************************************************************
 * Function: DCE2_CoBind()
 *
 * Handles the processing of a client bind request.  There are
 * differences between Windows and Samba and even early Samba in
 * how multiple binds on the session are handled.  Processing of
 * the context id bindings is handed off.
 *
 ********************************************************************/
static void DCE2_CoBind(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr, uint16_t frag_len)
{
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);
    const DceRpcCoBind* bind = (const DceRpcCoBind*)frag_ptr;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (frag_len < sizeof(DceRpcCoBind))
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoBind));

    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        /* Windows will not accept more than one bind */
        if (!DCE2_ListIsEmpty(cot->ctx_ids))
        {
            /* Delete context id list if anything there */
            DCE2_CoEraseCtxIds(cot);
            return;
        }

        /* Byte order of stub data will be that of the bind */
        cot->data_byte_order = DceRpcCoByteOrder(co_hdr);

        break;

    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
        if (cot->got_bind)
            return;

        break;

    case DCE2_POLICY__SAMBA_3_0_20:
        /* Accepts multiple binds */
        break;

    default:
        assert(false);
        return;
    }

    cot->max_xmit_frag = (int)DceRpcCoBindMaxXmitFrag(co_hdr, bind);
    DCE2_CoCtxReq(sd, cot, co_hdr, DceRpcCoNumCtxItems(bind), frag_ptr, frag_len);
}

/********************************************************************
 * Function: DCE2_CoAlterCtx()
 *
 * Handles the processing of a client alter context request.
 * Again, differences in how this is handled - whether we've seen
 * a bind yet or not, altering the data byte order.  Processing
 * of the context id bindings is handed off.
 *
 ********************************************************************/
static void DCE2_CoAlterCtx(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr, uint16_t frag_len)
{
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);
    const DceRpcCoAltCtx* alt_ctx = (const DceRpcCoAltCtx*)frag_ptr;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (frag_len < sizeof(DceRpcCoAltCtx))
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoAltCtx));

    switch (policy)
    {
    case DCE2_POLICY__WIN2000:
    case DCE2_POLICY__WIN2003:
    case DCE2_POLICY__WINXP:
    case DCE2_POLICY__WINVISTA:
    case DCE2_POLICY__WIN2008:
    case DCE2_POLICY__WIN7:
        /* Windows will not accept an alter context before
         * bind and will bind_nak it */
        if (DCE2_ListIsEmpty(cot->ctx_ids))
            return;

        if (cot->data_byte_order != (int)DceRpcCoByteOrder(co_hdr))
        {
            /* This is anomalous behavior.  Alert, but continue processing */
            if (cot->data_byte_order != DCE2_SENTINEL)
                dce_alert(GID_DCE2, DCE2_CO_ALTER_CHANGE_BYTE_ORDER,dce_common_stats);
        }

        break;

    case DCE2_POLICY__SAMBA:
    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        /* Nothing for Samba */
        break;

    default:
        assert(false);
        break;
    }

    /* Alter context is typedef'ed as a bind */
    DCE2_CoCtxReq(sd, cot, co_hdr, DceRpcCoNumCtxItems((const DceRpcCoBind*)alt_ctx), frag_ptr,
        frag_len);
}

static int DCE2_CoGetAuthLen(DCE2_SsnData* sd, const DceRpcCoHdr* co_hdr,
    const uint8_t* frag_ptr, uint16_t frag_len)
{
    const DceRpcCoAuthVerifier* auth_hdr;
    uint16_t auth_len = DceRpcCoAuthLen(co_hdr);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (auth_len == 0)
        return 0;

    auth_len += sizeof(DceRpcCoAuthVerifier);

    /* This means the auth len was bogus */
    if (auth_len > frag_len)
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return -1;
    }

    auth_hdr = (const DceRpcCoAuthVerifier*)(frag_ptr + (frag_len - auth_len));
    if (DceRpcCoAuthLevel(auth_hdr) == DCERPC_CO_AUTH_LEVEL__PKT_PRIVACY)
    {
        /* Data is encrypted - don't inspect */
        return -1;
    }

    auth_len += DceRpcCoAuthPad(auth_hdr);

    /* This means the auth pad len was bogus */
    if (auth_len > frag_len)
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return -1;
    }

    return (int)auth_len;
}

/********************************************************************
 * Function: DCE2_CoGetFragBuf()
 *
 * Returns the appropriate fragmentation buffer.
 *
 ********************************************************************/
static DCE2_Buffer* DCE2_CoGetFragBuf(DCE2_SsnData* sd, DCE2_CoFragTracker* ft)
{
    if (DCE2_SsnFromServer(sd->wire_pkt))
        return ft->srv_stub_buf;

    return ft->cli_stub_buf;
}

/********************************************************************
 * Function: DCE2_CoGetRpktType()
 *
 * Determines the type of reassembly packet we need to use
 * based on the transport and buffer type.
 *
 ********************************************************************/
static DCE2_RpktType DCE2_CoGetRpktType(DCE2_SsnData* sd, DCE2_BufType btype)
{
    DCE2_RpktType rtype = DCE2_RPKT_TYPE__NULL;

    switch (sd->trans)
    {
    case DCE2_TRANS_TYPE__SMB:
        switch (btype)
        {
        case DCE2_BUF_TYPE__SEG:
            rtype = DCE2_RPKT_TYPE__SMB_CO_SEG;
            break;

        case DCE2_BUF_TYPE__FRAG:
            rtype = DCE2_RPKT_TYPE__SMB_CO_FRAG;
            break;

        default:
            assert(false);
            break;
        }
        break;

    case DCE2_TRANS_TYPE__TCP:
        // FIXIT-M add HTTP cases when it is ported
        switch (btype)
        {
        case DCE2_BUF_TYPE__SEG:
            rtype = DCE2_RPKT_TYPE__TCP_CO_SEG;
            break;

        case DCE2_BUF_TYPE__FRAG:
            rtype = DCE2_RPKT_TYPE__TCP_CO_FRAG;
            break;

        default:
            assert(false);
            break;
        }
        break;

    default:
        assert(false);
        break;
    }
    return rtype;
}

/********************************************************************
 * Function: DCE2_CoGetRpkt()
 *
 * Creates a reassembled buffer based on the kind of data
 * (fragment, segment or both) we want to put in the reassembled
 * buffer.
 *
 ********************************************************************/
static Packet* DCE2_CoGetRpkt(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    DCE2_CoRpktType co_rtype, DCE2_RpktType* rtype)
{
    DCE2_CoSeg* seg_buf = DCE2_CoGetSegPtr(sd, cot);
    DCE2_Buffer* frag_buf = DCE2_CoGetFragBuf(sd, &cot->frag_tracker);
    const uint8_t* frag_data = nullptr, * seg_data = nullptr;
    uint32_t frag_len = 0, seg_len = 0;
    Packet* rpkt = nullptr;

    *rtype = DCE2_RPKT_TYPE__NULL;

    switch (co_rtype)
    {
    case DCE2_CO_RPKT_TYPE__ALL:
        if (!DCE2_BufferIsEmpty(frag_buf))
        {
            frag_data = DCE2_BufferData(frag_buf);
            frag_len = DCE2_BufferLength(frag_buf);
        }

        if (!DCE2_BufferIsEmpty(seg_buf->buf))
        {
            seg_data = DCE2_BufferData(seg_buf->buf);
            seg_len = DCE2_BufferLength(seg_buf->buf);
        }

        break;

    case DCE2_CO_RPKT_TYPE__SEG:
        if (!DCE2_BufferIsEmpty(seg_buf->buf))
        {
            seg_data = DCE2_BufferData(seg_buf->buf);
            seg_len = DCE2_BufferLength(seg_buf->buf);
        }

        break;

    case DCE2_CO_RPKT_TYPE__FRAG:
        if (!DCE2_BufferIsEmpty(frag_buf))
        {
            frag_data = DCE2_BufferData(frag_buf);
            frag_len = DCE2_BufferLength(frag_buf);
        }

        break;

    default:
        assert(false);
        return nullptr;
    }

    /* Seg stub data will be added to end of frag data */
    if ((frag_data != nullptr) && (seg_data != nullptr))
    {
        uint16_t hdr_size = sizeof(DceRpcCoHdr) + sizeof(DceRpcCoRequest);

        /* Need to just extract the stub data from the seg buffer
         * if there is enough data there */
        // FIXIT-L PORT_IF_NEEDED seg len check
        const DceRpcCoHdr* co_hdr = (const DceRpcCoHdr*)seg_data;

        /* Don't use it if it's not a request and therefore doesn't
         * belong with the frag data.  This is an insanity check -
         * shouldn't have seg data that's not a request if there are
         * frags queued up */
        if (DceRpcCoPduType(co_hdr) != DCERPC_PDU_TYPE__REQUEST)
        {
            seg_data = nullptr;
            seg_len = 0;
        }
        else
        {
            DCE2_MOVE(seg_data, seg_len, hdr_size);
        }
    }

    if (frag_data != nullptr)
        *rtype = DCE2_CoGetRpktType(sd, DCE2_BUF_TYPE__FRAG);
    else if (seg_data != nullptr)
        *rtype = DCE2_CoGetRpktType(sd, DCE2_BUF_TYPE__SEG);

    if (*rtype == DCE2_RPKT_TYPE__NULL)
        return nullptr;

    if ( frag_data )
    {
        rpkt = DCE2_GetRpkt(sd->wire_pkt, *rtype, frag_data, frag_len);

        if ( rpkt and seg_data )
        {
            /* If this fails, we'll still have the frag data */
            DCE2_AddDataToRpkt(rpkt, seg_data, seg_len);
        }
    }
    else if ( seg_data )
    {
        rpkt = DCE2_GetRpkt(sd->wire_pkt, *rtype, seg_data, seg_len);
    }

    return rpkt;
}

static Packet* dce_co_reassemble(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    DCE2_CoRpktType co_rtype, const DceRpcCoHdr** co_hdr)
{
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);
    int co_hdr_len = DCE2_SsnFromClient(sd->wire_pkt) ? DCE2_MOCK_HDR_LEN__CO_CLI :
        DCE2_MOCK_HDR_LEN__CO_SRV;
    int smb_hdr_len = DCE2_SsnFromClient(sd->wire_pkt) ? DCE2_MOCK_HDR_LEN__SMB_CLI :
        DCE2_MOCK_HDR_LEN__SMB_SRV;

    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_reass);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_reass);
    }

    DCE2_RpktType rpkt_type;
    Packet* rpkt = DCE2_CoGetRpkt(sd, cot, co_rtype, &rpkt_type);
    if (rpkt == nullptr)
    {
        return nullptr;
    }
    uint8_t* wrdata = const_cast<uint8_t*>(rpkt->data);

    switch (rpkt_type)
    {
    case DCE2_RPKT_TYPE__SMB_CO_FRAG:
    case DCE2_RPKT_TYPE__SMB_CO_SEG:
        DCE2_SmbSetRdata((DCE2_SmbSsnData*)sd, wrdata,
            (uint16_t)(rpkt->dsize - smb_hdr_len));

        if (rpkt_type == DCE2_RPKT_TYPE__SMB_CO_FRAG)
        {
            DCE2_CoSetRdata(sd, cot, wrdata + smb_hdr_len,
                (uint16_t)(rpkt->dsize - (smb_hdr_len + co_hdr_len)));

            if (DCE2_SsnFromClient(sd->wire_pkt))
                dce_common_stats->co_cli_frag_reassembled++;
            else
                dce_common_stats->co_srv_frag_reassembled++;
        }
        else
        {
            if (DCE2_SsnFromClient(sd->wire_pkt))
                dce_common_stats->co_cli_seg_reassembled++;
            else
                dce_common_stats->co_srv_seg_reassembled++;
        }

        *co_hdr = (const DceRpcCoHdr*)(rpkt->data + smb_hdr_len);
        cot->stub_data = rpkt->data + smb_hdr_len + co_hdr_len;
        return rpkt;

    case DCE2_RPKT_TYPE__TCP_CO_FRAG:
    case DCE2_RPKT_TYPE__TCP_CO_SEG:
        if (rpkt_type == DCE2_RPKT_TYPE__TCP_CO_FRAG)
        {
            DCE2_CoSetRdata(sd, cot, wrdata, (uint16_t)(rpkt->dsize - co_hdr_len));

            if (DCE2_SsnFromClient(sd->wire_pkt))
                dce_common_stats->co_cli_frag_reassembled++;
            else
                dce_common_stats->co_srv_frag_reassembled++;
        }
        else
        {
            if (DCE2_SsnFromClient(sd->wire_pkt))
                dce_common_stats->co_cli_seg_reassembled++;
            else
                dce_common_stats->co_cli_seg_reassembled++;
        }

        *co_hdr = (const DceRpcCoHdr*)rpkt->data;
        cot->stub_data = rpkt->data + co_hdr_len;
        return rpkt;

    default:
        assert(false);
        return nullptr;
    }
}

/********************************************************************
 * Function: DCE2_CoReassemble()
 *
 * Gets a reassembly packet based on the transport and the type of
 * reassembly we want to do.  Sets rule options and calls detect
 * on the reassembled packet.
 *
 *
 ********************************************************************/
static void DCE2_CoReassemble(DCE2_SsnData* sd, DCE2_CoTracker* cot, DCE2_CoRpktType co_rtype)
{
    const DceRpcCoHdr* co_hdr = nullptr;
    Packet* rpkt = dce_co_reassemble(sd,cot,co_rtype,&co_hdr);

    if ( !rpkt )
        return;

    DCE2_CoSetRopts(sd, cot, co_hdr, rpkt);

    DCE2_Detect(sd);
    co_reassembled = 1;
}

static inline void DCE2_CoFragReassemble(DCE2_SsnData* sd, DCE2_CoTracker* cot)
{
    DCE2_CoReassemble(sd, cot, DCE2_CO_RPKT_TYPE__FRAG);
}

static DCE2_Ret dce_co_handle_frag(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr,
    uint16_t frag_len, DCE2_Buffer* frag_buf,
    uint16_t max_frag_data)
{
    uint32_t size = (frag_len < DCE2_CO__MIN_ALLOC_SIZE) ? DCE2_CO__MIN_ALLOC_SIZE : frag_len;
    DCE2_BufferMinAddFlag mflag = DCE2_BUFFER_MIN_ADD_FLAG__USE;
    DCE2_Ret status;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_frag);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_frag);
    }

    if (DCE2_SsnFromClient(sd->wire_pkt))
    {
        if (frag_len > dce_common_stats->co_cli_max_frag_size)
            dce_common_stats->co_cli_max_frag_size = frag_len;

        if (dce_common_stats->co_cli_min_frag_size == 0 || frag_len <
            dce_common_stats->co_cli_min_frag_size)
            dce_common_stats->co_cli_min_frag_size = frag_len;
    }
    else
    {
        if (frag_len > dce_common_stats->co_srv_max_frag_size)
            dce_common_stats->co_srv_max_frag_size = frag_len;

        if (dce_common_stats->co_srv_min_frag_size == 0 || frag_len <
            dce_common_stats->co_srv_min_frag_size)
            dce_common_stats->co_srv_min_frag_size = frag_len;
    }

    if (frag_buf == nullptr)
    {
        if (DCE2_SsnFromServer(sd->wire_pkt))
        {
            cot->frag_tracker.srv_stub_buf =
                DCE2_BufferNew(size, DCE2_CO__MIN_ALLOC_SIZE);
            frag_buf = cot->frag_tracker.srv_stub_buf;
        }
        else
        {
            cot->frag_tracker.cli_stub_buf =
                DCE2_BufferNew(size, DCE2_CO__MIN_ALLOC_SIZE);
            frag_buf = cot->frag_tracker.cli_stub_buf;
        }

        if (frag_buf == nullptr)
        {
            return DCE2_RET__ERROR;
        }
    }
    /* If there's already data in the buffer and this is a first frag
    * we probably missed packets */
    if (DceRpcCoFirstFrag(co_hdr) && !DCE2_BufferIsEmpty(frag_buf))
    {
        DCE2_CoResetFragTracker(&cot->frag_tracker);
        DCE2_BufferEmpty(frag_buf);
    }

    /* Check for potential overflow */
    if (DCE2_GcMaxFrag((dce2CommonProtoConf*)sd->config) && (frag_len > DCE2_GcMaxFragLen(
        (dce2CommonProtoConf*)sd->config)))
        frag_len = DCE2_GcMaxFragLen((dce2CommonProtoConf*)sd->config);

    if ((DCE2_BufferLength(frag_buf) + frag_len) > max_frag_data)
        frag_len = max_frag_data - (uint16_t)DCE2_BufferLength(frag_buf);

    if (frag_len != 0)
    {
        /* If it's the last fragment we're going to flush so just alloc
         * exactly what we need ... or if there is more data than can fit
         * in the reassembly buffer */
        if (DceRpcCoLastFrag(co_hdr) || (DCE2_BufferLength(frag_buf) == max_frag_data))
            mflag = DCE2_BUFFER_MIN_ADD_FLAG__IGNORE;

        status = DCE2_BufferAddData(frag_buf, frag_ptr,
            frag_len, DCE2_BufferLength(frag_buf), mflag);

        if (status != DCE2_RET__SUCCESS)
        {
            /* memcpy failed - reassemble */
            DCE2_CoFragReassemble(sd, cot);
            DCE2_BufferEmpty(frag_buf);
            return DCE2_RET__ERROR;
        }
    }
    return(DCE2_RET__SUCCESS);
}

/********************************************************************
 * Function: DCE2_CoHandleFrag()
 *
 * Handles adding a fragment to the defragmentation buffer.
 * Does overflow checking.  Maximum length of fragmentation buffer
 * is based on the maximum packet length Snort can handle.
 *
 ********************************************************************/

static void DCE2_CoHandleFrag(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr, uint16_t frag_len)
{
    DCE2_Ret ret_val;
    DCE2_Buffer* frag_buf = DCE2_CoGetFragBuf(sd, &cot->frag_tracker);
    uint16_t max_frag_data;

    /* Check for potential overflow */
    if (sd->trans == DCE2_TRANS_TYPE__SMB)
        max_frag_data = DCE2_GetRpktMaxData(sd, DCE2_RPKT_TYPE__SMB_CO_FRAG);
    else
        max_frag_data = DCE2_GetRpktMaxData(sd, DCE2_RPKT_TYPE__TCP_CO_FRAG);

    ret_val = dce_co_handle_frag(sd, cot,co_hdr, frag_ptr, frag_len,frag_buf,max_frag_data);
    if (ret_val == DCE2_RET__SUCCESS)
    {
        /* Reassemble if we got a last frag ... */
        if (DceRpcCoLastFrag(co_hdr))
        {
            DCE2_CoFragReassemble(sd, cot);
            DCE2_BufferEmpty(frag_buf);

            /* Set this for the server response since response doesn't
             * contain client opnum used */
            cot->opnum = cot->frag_tracker.opnum;
            DCE2_CoResetFragTracker(&cot->frag_tracker);

            /* Return early - rule opts will be set in reassembly handler */
            return;
        }
        else if (DCE2_BufferLength(frag_buf) == max_frag_data)
        {
            /* ... or can't fit any more data in the buffer
             * Don't reset frag tracker */
            DCE2_CoFragReassemble(sd, cot);
            DCE2_BufferEmpty(frag_buf);
            return;
        }
    }
}

/********************************************************************
 * Function: DCE2_CoRequest()
 *
 * Handles a DCE/RPC request from the client.  This is were the
 * client actually asks the server to do stuff on it's behalf.
 * If it's a first/last fragment, set relevant rule option
 * data and return. If it's a true fragment, do some target
 * based futzing to set the right opnum and context id for
 * the to be reassembled packet.
 *
 *
 ********************************************************************/
static void DCE2_CoRequest(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr, uint16_t frag_len)
{
    const DceRpcCoRequest* rhdr = (const DceRpcCoRequest*)frag_ptr;
    uint16_t req_size = sizeof(DceRpcCoRequest);
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    /* Account for possible object uuid */
    if (DceRpcCoObjectFlag(co_hdr))
        req_size += sizeof(Uuid);

    if (frag_len < req_size)
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
        return;
    }

    switch (policy)
    {
    /* After 3.0.37 up to 3.5.2 byte order of stub data is always
     * interpreted as little endian */
    case DCE2_POLICY__SAMBA:
        cot->data_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        break;

    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        cot->data_byte_order = DceRpcCoByteOrder(co_hdr);
        break;

    default:
        break;
    }

    /* Move past header */
    DCE2_MOVE(frag_ptr, frag_len, req_size);

    /* If for some reason we had some fragments queued */
    if (DceRpcCoFirstFrag(co_hdr) && !DceRpcCoLastFrag(co_hdr)
        && !DCE2_BufferIsEmpty(cot->frag_tracker.cli_stub_buf))
    {
        DCE2_CoFragReassemble(sd, cot);
        DCE2_BufferEmpty(cot->frag_tracker.cli_stub_buf);
        DCE2_CoResetFragTracker(&cot->frag_tracker);
    }

    cot->stub_data = frag_ptr;
    cot->opnum = DceRpcCoOpnum(co_hdr, rhdr);
    cot->ctx_id = DceRpcCoCtxId(co_hdr, rhdr);
    cot->call_id = DceRpcCoCallId(co_hdr);

    if (DceRpcCoFirstFrag(co_hdr) && DceRpcCoLastFrag(co_hdr))
    {
        int auth_len = DCE2_CoGetAuthLen(sd, co_hdr, frag_ptr, frag_len);
        if (auth_len == -1)
            return;
        DCE2_CoSetRopts(sd, cot, co_hdr, sd->wire_pkt);
    }
    else
    {
        DCE2_CoFragTracker* ft = &cot->frag_tracker;
        int auth_len = DCE2_CoGetAuthLen(sd, co_hdr, frag_ptr, frag_len);

        dce_common_stats->co_req_fragments++;

        if (auth_len == -1)
            return;

        if (DCE2_BufferIsEmpty(ft->cli_stub_buf))
        {
            ft->expected_opnum = cot->opnum;
            ft->expected_ctx_id = cot->ctx_id;
            ft->expected_call_id = cot->call_id;
        }
        else
        {
            /* Don't return for these, because we can still process and servers
             * will still accept and deal with the anomalies in their own way */
            if ((ft->expected_opnum != DCE2_SENTINEL) &&
                (ft->expected_opnum != cot->opnum))
            {
                dce_alert(GID_DCE2, DCE2_CO_FRAG_DIFF_OPNUM,dce_common_stats);
            }

            if ((ft->expected_ctx_id != DCE2_SENTINEL) &&
                (ft->expected_ctx_id != cot->ctx_id))
            {
                dce_alert(GID_DCE2, DCE2_CO_FRAG_DIFF_CTX_ID,dce_common_stats);
            }

            if ((ft->expected_call_id != DCE2_SENTINEL) &&
                (ft->expected_call_id != cot->call_id))
            {
                dce_alert(GID_DCE2, DCE2_CO_FRAG_DIFF_CALL_ID,dce_common_stats);
            }
        }

        /* Possibly set opnum in frag tracker */
        switch (policy)
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            if (DceRpcCoLastFrag(co_hdr))
                ft->opnum = cot->opnum;
            break;

        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (DceRpcCoFirstFrag(co_hdr))
                ft->opnum = cot->opnum;
            break;

        default:
            assert(false);
            break;
        }

        /* Possibly set context id in frag tracker */
        switch (policy)
        {
        case DCE2_POLICY__WIN2000:
        case DCE2_POLICY__WIN2003:
        case DCE2_POLICY__WINXP:
        case DCE2_POLICY__WINVISTA:
        case DCE2_POLICY__WIN2008:
        case DCE2_POLICY__WIN7:
            if (DceRpcCoFirstFrag(co_hdr))
            {
                ft->ctx_id = cot->ctx_id;
            }
            else if ((ft->expected_call_id != DCE2_SENTINEL) &&
                (ft->expected_call_id != cot->call_id))
            {
                /* Server won't accept frag */
                return;
            }

            break;

        case DCE2_POLICY__SAMBA:
        case DCE2_POLICY__SAMBA_3_0_37:
        case DCE2_POLICY__SAMBA_3_0_22:
        case DCE2_POLICY__SAMBA_3_0_20:
            if (DceRpcCoLastFrag(co_hdr))
            {
                ft->ctx_id = cot->ctx_id;
            }

            break;

        default:
            assert(false);
            break;
        }

        DCE2_CoSetRopts(sd, cot, co_hdr, sd->wire_pkt);

        /* If we're configured to do defragmentation */
        if (DCE2_GcDceDefrag((dce2CommonProtoConf*)sd->config))
        {
            /* Don't want to include authentication data in fragment */
            DCE2_CoHandleFrag(sd, cot, co_hdr, frag_ptr,
                (uint16_t)(frag_len - (uint16_t)auth_len));
        }
    }
}

/********************************************************************
 * Function: DCE2_CoResponse()
 *
 * Handles a DCE/RPC response from the server.
 * Samba responds to SMB bind write, request write before read with
 * a response to the request and doesn't send a bind ack.  Get the
 * context id from the pending context id list and put in stable
 * list.
 *

 ********************************************************************/
static void DCE2_CoResponse(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr, const uint8_t* frag_ptr, uint16_t frag_len)
{
    const DceRpcCoResponse* rhdr = (const DceRpcCoResponse*)frag_ptr;
    uint16_t ctx_id;
    DCE2_Policy policy = DCE2_SsnGetServerPolicy(sd);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    if (frag_len < sizeof(DceRpcCoResponse))
    {
        dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);

        return;
    }

    switch (policy)
    {
    case DCE2_POLICY__SAMBA:
        cot->data_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        break;

    case DCE2_POLICY__SAMBA_3_0_37:
    case DCE2_POLICY__SAMBA_3_0_22:
    case DCE2_POLICY__SAMBA_3_0_20:
        cot->data_byte_order = DceRpcCoByteOrder(co_hdr);
        break;

    default:
        break;
    }

    ctx_id = DceRpcCoCtxIdResp(co_hdr, rhdr);

    /* If pending queue is not empty, add this context id as accepted and all
     * others as pending */
    while (!DCE2_QueueIsEmpty(cot->pending_ctx_ids))
    {
        DCE2_Ret status;
        DCE2_CoCtxIdNode* ctx_node = (DCE2_CoCtxIdNode*)DCE2_QueueDequeue(cot->pending_ctx_ids);

        if (ctx_node == nullptr)
        {
            return;
        }

        if (ctx_node->ctx_id == ctx_id)
            ctx_node->state = DCE2_CO_CTX_STATE__ACCEPTED;

        status = DCE2_ListInsert(cot->ctx_ids, (void*)(uintptr_t)ctx_node->ctx_id,
            (void*)ctx_node);
        if (status != DCE2_RET__SUCCESS)
        {
            /* Might be a duplicate in there already.  If there is we would have used it
             * anyway before looking at the pending queue.  Just get rid of it */
            snort_free((void*)ctx_node);
            return;
        }
    }

    /* Move past header */
    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoResponse));

    /* If for some reason we had some fragments queued */
    if (DceRpcCoFirstFrag(co_hdr) && !DCE2_BufferIsEmpty(cot->frag_tracker.srv_stub_buf))
    {
        DCE2_CoFragReassemble(sd, cot);
        DCE2_BufferEmpty(cot->frag_tracker.srv_stub_buf);
        DCE2_CoResetFragTracker(&cot->frag_tracker);
    }

    cot->stub_data = frag_ptr;
    /* Opnum not in response header - have to use previous client's */
    cot->ctx_id = ctx_id;
    cot->call_id = DceRpcCoCallId(co_hdr);

    if (DceRpcCoFirstFrag(co_hdr) && DceRpcCoLastFrag(co_hdr))
    {
        int auth_len = DCE2_CoGetAuthLen(sd, co_hdr, frag_ptr, frag_len);

        if (auth_len == -1)
            return;
        DCE2_CoSetRopts(sd, cot, co_hdr, sd->wire_pkt);
    }
    else
    {
        //DCE2_CoFragTracker *ft = &cot->frag_tracker;
        int auth_len = DCE2_CoGetAuthLen(sd, co_hdr, frag_ptr, frag_len);

        dce_common_stats->co_resp_fragments++;
        if (auth_len == -1)
            return;

        DCE2_CoSetRopts(sd, cot, co_hdr, sd->wire_pkt);

        /* If we're configured to do defragmentation */
        if (DCE2_GcDceDefrag((dce2CommonProtoConf*)sd->config))
        {
            DCE2_CoHandleFrag(sd, cot, co_hdr, frag_ptr,
                (uint16_t)(frag_len - (uint16_t)auth_len));
        }
    }
}

/********************************************************************
 * Function: DCE2_CoDecode()
 *
 * Main processing for the DCE/RPC pdu types.  Most are not
 * implemented as, currently, they are not necessary and only
 * stats are kept for them.  Important are the bind, alter context
 * and request.
 *
 ********************************************************************/
static void DCE2_CoDecode(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const uint8_t* frag_ptr, uint16_t frag_len)
{
    /* Already checked that we have enough data for header */
    const DceRpcCoHdr* co_hdr = (const DceRpcCoHdr*)frag_ptr;
    int pdu_type = DceRpcCoPduType(co_hdr);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    /* We've got the main header.  Move past it to the
     * start of the pdu */
    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoHdr));

    /* Client specific pdu types - some overlap with server */
    if (DCE2_SsnFromClient(sd->wire_pkt))
    {
        switch (pdu_type)
        {
        case DCERPC_PDU_TYPE__BIND:
            dce_common_stats->co_bind++;

            /* Make sure context id list and queue are initialized */
            if (DCE2_CoInitCtxStorage(cot) != DCE2_RET__SUCCESS)
                return;

            DCE2_CoBind(sd, cot, co_hdr, frag_ptr, frag_len);

            break;

        case DCERPC_PDU_TYPE__ALTER_CONTEXT:
            dce_common_stats->co_alter_ctx++;

            if (DCE2_CoInitCtxStorage(cot) != DCE2_RET__SUCCESS)
                return;

            DCE2_CoAlterCtx(sd, cot, co_hdr, frag_ptr, frag_len);

            break;

        case DCERPC_PDU_TYPE__REQUEST:
            dce_common_stats->co_request++;

            if (DCE2_ListIsEmpty(cot->ctx_ids) &&
                DCE2_QueueIsEmpty(cot->pending_ctx_ids))
            {
                return;
            }

            DCE2_CoRequest(sd, cot, co_hdr, frag_ptr, frag_len);

            break;

        case DCERPC_PDU_TYPE__AUTH3:
            dce_common_stats->co_auth3++;
            break;

        case DCERPC_PDU_TYPE__CO_CANCEL:
            dce_common_stats->co_cancel++;
            break;

        case DCERPC_PDU_TYPE__ORPHANED:
            dce_common_stats->co_orphaned++;
            break;

        case DCERPC_PDU_TYPE__MICROSOFT_PROPRIETARY_OUTLOOK2003_RPC_OVER_HTTP:
            dce_common_stats->co_ms_pdu++;
            break;

        default:
            dce_common_stats->co_other_req++;
            break;
        }
    }
    else
    {
        switch (pdu_type)
        {
        case DCERPC_PDU_TYPE__BIND_ACK:
        case DCERPC_PDU_TYPE__ALTER_CONTEXT_RESP:
            if (pdu_type == DCERPC_PDU_TYPE__BIND_ACK)
            {
                dce_common_stats->co_bind_ack++;
            }
            else
            {
                dce_common_stats->co_alter_ctx_resp++;
            }

            if (DCE2_QueueIsEmpty(cot->pending_ctx_ids))
                return;

            /* Bind ack and alter context response have the same
             * header structure, just different pdu type */
            DCE2_CoBindAck(sd, cot, co_hdr, frag_ptr, frag_len);

            /* Got the bind/alter response - clear out the pending queue */
            DCE2_QueueEmpty(cot->pending_ctx_ids);

            break;

        case DCERPC_PDU_TYPE__BIND_NACK:
            dce_common_stats->co_bind_nack++;

            /* Bind nack in Windows seems to blow any previous context away */
            switch (DCE2_SsnGetServerPolicy(sd))
            {
            case DCE2_POLICY__WIN2000:
            case DCE2_POLICY__WIN2003:
            case DCE2_POLICY__WINXP:
            case DCE2_POLICY__WINVISTA:
            case DCE2_POLICY__WIN2008:
            case DCE2_POLICY__WIN7:
                DCE2_CoEraseCtxIds(cot);
                break;

            default:
                break;
            }

            cot->got_bind = 0;

            break;

        case DCERPC_PDU_TYPE__RESPONSE:
            dce_common_stats->co_response++;
            DCE2_CoResponse(sd, cot, co_hdr, frag_ptr, frag_len);
            break;

        case DCERPC_PDU_TYPE__FAULT:
            dce_common_stats->co_fault++;

            /* Clear out the client side */
            DCE2_QueueEmpty(cot->pending_ctx_ids);
            DCE2_BufferEmpty(cot->cli_seg.buf);
            DCE2_BufferEmpty(cot->frag_tracker.cli_stub_buf);

            DCE2_CoResetTracker(cot);

            break;

        case DCERPC_PDU_TYPE__SHUTDOWN:
            dce_common_stats->co_shutdown++;
            break;

        case DCERPC_PDU_TYPE__REJECT:
            dce_common_stats->co_reject++;

            DCE2_QueueEmpty(cot->pending_ctx_ids);

            break;

        case DCERPC_PDU_TYPE__MICROSOFT_PROPRIETARY_OUTLOOK2003_RPC_OVER_HTTP:
            dce_common_stats->co_ms_pdu++;
            break;

        default:
            dce_common_stats->co_other_resp++;
            break;
        }
    }
}

/********************************************************************
 * Function: DCE2_CoSegEarlyRequest()
 *
 * Used to set rule option data if we are doing an early
 * reassembly on data in the segmentation buffer.  If we are
 * taking directly from the segmentation buffer, none of the
 * rule option data will be set since processing doesn't get to
 * that point.  Only do if this is a Request PDU.
 *
 ********************************************************************/
static DCE2_Ret DCE2_CoSegEarlyRequest(DCE2_CoTracker* cot,
    const uint8_t* seg_ptr, uint32_t seg_len)
{
    uint16_t req_size = sizeof(DceRpcCoRequest);

    if (seg_len < sizeof(DceRpcCoHdr))
        return DCE2_RET__ERROR;

    const DceRpcCoHdr* co_hdr = (const DceRpcCoHdr*)seg_ptr;
    DCE2_MOVE(seg_ptr, seg_len, sizeof(DceRpcCoHdr));

    if (DceRpcCoPduType(co_hdr) != DCERPC_PDU_TYPE__REQUEST)
        return DCE2_RET__ERROR;

    const DceRpcCoRequest* rhdr = (const DceRpcCoRequest*)seg_ptr;

    /* Account for possible object uuid */
    if (DceRpcCoObjectFlag(co_hdr))
        req_size += sizeof(Uuid);

    if (seg_len < req_size)
        return DCE2_RET__ERROR;

    cot->opnum = DceRpcCoOpnum(co_hdr, rhdr);
    cot->ctx_id = DceRpcCoCtxId(co_hdr, rhdr);
    cot->call_id = DceRpcCoCallId(co_hdr);

    return DCE2_RET__SUCCESS;
}

/********************************************************************
 * Function: DCE2_CoEarlyReassemble()
 *
 * Checks to see if we should send a reassembly packet based on
 * the current data in fragmentation and segmentation buffers
 * to the detection engine.  Whether we do or not is based on
 * whether or not we are configured to do so.  The number of bytes
 * in the fragmentation and segmentation buffers are calculated
 * and if they exceed the amount we are configured for, we
 * reassemble.
 *
 ********************************************************************/
static void DCE2_CoEarlyReassemble(DCE2_SsnData* sd, DCE2_CoTracker* cot)
{
    DCE2_Buffer* frag_buf = DCE2_CoGetFragBuf(sd, &cot->frag_tracker);

    if (DCE2_SsnFromServer(sd->wire_pkt))
        return;

    if (!DCE2_BufferIsEmpty(frag_buf))
    {
        uint32_t bytes = DCE2_BufferLength(frag_buf);
        uint32_t seg_bytes = 0;

        if (!DCE2_BufferIsEmpty(cot->cli_seg.buf))
        {
            uint16_t hdr_size = sizeof(DceRpcCoHdr) + sizeof(DceRpcCoRequest);

            // FIXIT-L PORT_IF_NEEDED header size check
            DceRpcCoHdr* co_hdr = (DceRpcCoHdr*)DCE2_BufferData(cot->cli_seg.buf);

            if (DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__REQUEST)
            {
                seg_bytes = DCE2_BufferLength(cot->cli_seg.buf) - hdr_size;

                if ((UINT32_MAX - bytes) < seg_bytes)
                    seg_bytes = UINT32_MAX - bytes;

                bytes += seg_bytes;
            }
        }

        if (bytes >= DCE2_GcReassembleThreshold(sd))
        {
            if (seg_bytes == 0)
            {
                DCE2_CoReassemble(sd, cot, DCE2_CO_RPKT_TYPE__FRAG);
            }
            else
            {
                DCE2_CoReassemble(sd, cot, DCE2_CO_RPKT_TYPE__ALL);
            }
        }
    }
    else if (!DCE2_BufferIsEmpty(cot->cli_seg.buf))
    {
        uint32_t bytes = DCE2_BufferLength(cot->cli_seg.buf);

        if (bytes >= DCE2_GcReassembleThreshold(sd))
        {
            DCE2_Ret status;

            status = DCE2_CoSegEarlyRequest(cot, DCE2_BufferData(cot->cli_seg.buf), bytes);
            if (status != DCE2_RET__SUCCESS)
            {
                return;
            }

            DCE2_CoReassemble(sd, cot, DCE2_CO_RPKT_TYPE__SEG);
        }
    }
}

/********************************************************************
 * Function: DCE2_CoGetSegRpkt()
 *
 * Gets and returns a reassembly packet based on a segmentation
 * buffer.
 *
 ********************************************************************/
static Packet* DCE2_CoGetSegRpkt(DCE2_SsnData* sd,
    const uint8_t* data_ptr, uint32_t data_len)
{
    Packet* rpkt = nullptr;
    int smb_hdr_len = DCE2_SsnFromClient(sd->wire_pkt) ? DCE2_MOCK_HDR_LEN__SMB_CLI :
        DCE2_MOCK_HDR_LEN__SMB_SRV;

    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_reass);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_reass);
    }

    switch (sd->trans)
    {
    case DCE2_TRANS_TYPE__SMB:
        rpkt = DCE2_GetRpkt(sd->wire_pkt, DCE2_RPKT_TYPE__SMB_CO_SEG, data_ptr, data_len);

        if ( !rpkt )
            return nullptr;

        DCE2_SmbSetRdata((DCE2_SmbSsnData*)sd, const_cast<uint8_t*>(rpkt->data),
            (uint16_t)(rpkt->dsize - smb_hdr_len));
        break;

    case DCE2_TRANS_TYPE__TCP:
        // FIXIT-M add HTTP cases when it is ported
        rpkt = DCE2_GetRpkt(sd->wire_pkt, DCE2_RPKT_TYPE__TCP_CO_SEG, data_ptr, data_len);
        break;

    default:
        assert(false);
        break;
    }

    return rpkt;
}

/********************************************************************
 * Function: DCE2_CoSegDecode()
 *
 * Creates a reassembled packet from the segmentation buffer and
 * sends off to be decoded.  It's also detected on since the
 * detection engine has yet to see this data.
 *
 ********************************************************************/
static void DCE2_CoSegDecode(DCE2_SsnData* sd, DCE2_CoTracker* cot, DCE2_CoSeg* seg)
{
    const uint8_t* frag_ptr = nullptr;
    uint16_t frag_len = 0;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);
    int smb_hdr_len = DCE2_SsnFromClient(sd->wire_pkt) ? DCE2_MOCK_HDR_LEN__SMB_CLI :
        DCE2_MOCK_HDR_LEN__SMB_SRV;

    if (DCE2_SsnFromClient(sd->wire_pkt))
        dce_common_stats->co_cli_seg_reassembled++;
    else
        dce_common_stats->co_srv_seg_reassembled++;

    Packet* rpkt = DCE2_CoGetSegRpkt(sd, DCE2_BufferData(seg->buf), DCE2_BufferLength(seg->buf));

    // FIXIT-M don't toss data until success response to
    // allow for retransmission of last segment of pdu. if
    // we don't do it here 2 things break:
    // (a) we can't alert on this packet; and
    // (b) subsequent pdus aren't desegmented correctly.
    DCE2_BufferEmpty(seg->buf);

    if (rpkt == nullptr)
        return;

    /* Set the start of the connection oriented pdu to where it
     * is in the reassembled packet */
    switch (sd->trans)
    {
    case DCE2_TRANS_TYPE__SMB:
        frag_ptr = rpkt->data + smb_hdr_len;
        frag_len = rpkt->dsize - smb_hdr_len;
        break;

    case DCE2_TRANS_TYPE__TCP:
        // FIXIT-M add HTTP cases when it is ported
        frag_ptr = rpkt->data;
        frag_len = rpkt->dsize;
        break;

    default:
        assert(false);
        return;
    }

    /* All is good.  Decode the pdu */
    DCE2_CoDecode(sd, cot, frag_ptr, frag_len);

    /* Call detect since this is a reassembled packet that the
     * detection engine hasn't seen yet */
    if (!co_reassembled)
        DCE2_Detect(sd);
}

static DCE2_Ret DCE2_HandleSegmentation(DCE2_Buffer* seg_buf, const uint8_t* data_ptr,
    uint16_t data_len, uint32_t need_len, uint16_t* data_used)
{
    uint32_t copy_len;
    DCE2_Ret status;

/* Initialize in case we return early without adding
     * any data to the buffer */
    *data_used = 0;

    if (seg_buf == nullptr)
        return DCE2_RET__ERROR;

    /* Don't need anything - call it desegmented.  Really return
     * an error - this shouldn't happen */
    if (need_len == 0)
        return DCE2_RET__ERROR;

    /* Already have enough data for need */
    if (DCE2_BufferLength(seg_buf) >= need_len)
        return DCE2_RET__SUCCESS;

    /* No data and need length > 0 - must still be segmented */
    if (data_len == 0)
        return DCE2_RET__SEG;

    /* Already know that need length is greater than buffer length */
    copy_len = need_len - DCE2_BufferLength(seg_buf);
    if (copy_len > data_len)
        copy_len = data_len;

    status = DCE2_BufferAddData(seg_buf, data_ptr, copy_len,
        DCE2_BufferLength(seg_buf), DCE2_BUFFER_MIN_ADD_FLAG__USE);

    if (status != DCE2_RET__SUCCESS)
        return DCE2_RET__ERROR;

    assert (copy_len <= data_len);

    *data_used = (uint16_t)copy_len;

    if (DCE2_BufferLength(seg_buf) == need_len)
        return DCE2_RET__SUCCESS;

    return DCE2_RET__SEG;
}

/********************************************************************
 * Function: DCE2_CoHandleSegmentation()
 *
 * Wrapper around DCE2_HandleSegmentation() to allocate a new
 * buffer object if necessary.
 *
 ********************************************************************/
static DCE2_Ret DCE2_CoHandleSegmentation(DCE2_SsnData* sd, DCE2_CoSeg* seg,
    const uint8_t* data_ptr, uint16_t data_len, uint16_t need_len, uint16_t* data_used)
{
    DCE2_Ret status;

    if (sd->trans == DCE2_TRANS_TYPE__TCP)
    {
        Profile profile(dce2_tcp_pstat_co_seg);
    }
    else
    {
        Profile profile(dce2_smb_pstat_co_seg);
    }

    if (seg == nullptr)
    {
        return DCE2_RET__ERROR;
    }

    if (seg->buf == nullptr)
    {
        seg->buf = DCE2_BufferNew(need_len, DCE2_CO__MIN_ALLOC_SIZE);
        if (seg->buf == nullptr)
        {
            return DCE2_RET__ERROR;
        }
    }

    status = DCE2_HandleSegmentation(seg->buf,
        data_ptr, data_len, need_len, data_used);

    return status;
}

/********************************************************************
 * Function: DCE2_CoProcess()
 *
 * Main entry point for connection-oriented DCE/RPC processing.
 * Since there can be more than one DCE/RPC pdu in the packet, it
 * loops through the packet data until none is left.  It handles
 * transport layer segmentation and buffers data until it gets the
 * full pdu, then hands off to pdu processing.
 *
 *
 ********************************************************************/
void DCE2_CoProcess(DCE2_SsnData* sd, DCE2_CoTracker* cot,
    const uint8_t* data_ptr, uint16_t data_len)
{
    DCE2_CoSeg* seg = DCE2_CoGetSegPtr(sd, cot);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);
    uint32_t num_frags = 0;

    dce_common_stats->co_pdus++;
    co_reassembled = 0;

    while (data_len > 0)
    {
        num_frags++;

        /* Fast track full fragments */
        if (DCE2_BufferIsEmpty(seg->buf))
        {
            const uint8_t* frag_ptr = data_ptr;
            uint16_t frag_len;
            uint16_t data_used;

            /* Not enough data left for a header.  Buffer it and return */
            if (data_len < sizeof(DceRpcCoHdr))
            {
                DCE2_CoHandleSegmentation(sd, seg, data_ptr, data_len, sizeof(DceRpcCoHdr),
                    &data_used);

                /* Just break out of loop in case early detect is enabled */
                break;
            }

            if (DCE2_CoHdrChecks(sd, cot, (const DceRpcCoHdr*)data_ptr) != DCE2_RET__SUCCESS)
                return;

            frag_len = DceRpcCoFragLen((const DceRpcCoHdr*)data_ptr);

            /* Not enough data left for the pdu. */
            if (data_len < frag_len)
            {
                /* Set frag length so we don't have to check it again in seg code */
                seg->frag_len = frag_len;

                DCE2_CoHandleSegmentation(sd, seg, data_ptr, data_len, frag_len, &data_used);
                goto dce2_coprocess_exit;
            }

            DCE2_MOVE(data_ptr, data_len, frag_len);

            /* Got a full DCE/RPC pdu */
            DCE2_CoDecode(sd, cot, frag_ptr, frag_len);

            /* If we're configured to do defragmentation only detect on first frag
             * since we'll detect on reassembled */
            if (!DCE2_GcDceDefrag((dce2CommonProtoConf*)sd->config) || ((num_frags == 1) &&
                !co_reassembled))
                DCE2_Detect(sd);

            /* Reset if this is a last frag */
            if (DceRpcCoLastFrag((const DceRpcCoHdr*)frag_ptr))
                num_frags = 0;
        }
        else  /* We've already buffered data */
        {
            uint16_t data_used = 0;

            // Need more data to get header
            if (DCE2_BufferLength(seg->buf) < sizeof(DceRpcCoHdr))
            {
                DCE2_Ret status = DCE2_CoHandleSegmentation(sd, seg, data_ptr, data_len,
                    sizeof(DceRpcCoHdr), &data_used);

                /* Still not enough for header */
                if (status != DCE2_RET__SUCCESS)
                    break;

                /* Move the length of the amount of data we used to get header */
                DCE2_MOVE(data_ptr, data_len, data_used);

                if (DCE2_CoHdrChecks(sd, cot, (DceRpcCoHdr*)DCE2_BufferData(seg->buf)) !=
                    DCE2_RET__SUCCESS)
                {
                    int data_back;
                    DCE2_BufferEmpty(seg->buf);
                    /* Move back to original packet header */
                    data_back = -data_used;
                    DCE2_MOVE(data_ptr, data_len, data_back);
                    /*Check the original packet*/
                    if (DCE2_CoHdrChecks(sd, cot, (const DceRpcCoHdr*)data_ptr) !=
                        DCE2_RET__SUCCESS)
                        return;
                    else
                    {
                        /*Only use the original packet, ignore the data in seg_buffer*/
                        num_frags = 0;
                        continue;
                    }
                }

                seg->frag_len = DceRpcCoFragLen((DceRpcCoHdr*)DCE2_BufferData(seg->buf));
            }

            /* Need more data for full pdu */
            if (DCE2_BufferLength(seg->buf) < seg->frag_len)
            {
                DCE2_Ret status = DCE2_CoHandleSegmentation(sd, seg, data_ptr, data_len,
                    seg->frag_len, &data_used);

                /* Still not enough */
                if (status != DCE2_RET__SUCCESS)
                    break;

                DCE2_MOVE(data_ptr, data_len, data_used);
            }

            /* Do this before calling DCE2_CoSegDecode since it will empty
             * seg buffer */
            if (DceRpcCoLastFrag((const DceRpcCoHdr*)seg->buf->data))
                num_frags = 0;

            /* Got the full DCE/RPC pdu. Need to create new packet before decoding */
            DCE2_CoSegDecode(sd, cot, seg);

            if ( !data_used )
                break;
        }
    }

dce2_coprocess_exit:
    if (DCE2_GcReassembleEarly(sd) && !co_reassembled)
        DCE2_CoEarlyReassemble(sd, cot);
}

