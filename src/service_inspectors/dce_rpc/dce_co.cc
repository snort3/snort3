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

// dce_co.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#include "dce_co.h"
#include "dce_tcp.h"
#include "dce_smb.h"
#include "dce_list.h"
#include "dce_utils.h"
#include "profiler/profiler.h"
#include "main/snort_debug.h"
#include "log/messages.h"

THREAD_LOCAL int co_reassembled = 0;

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
    DCE2_CoCtxIdNode* ctx_id_node;

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

    ctx_id_node = (DCE2_CoCtxIdNode*)DCE2_ListFind(cot->ctx_ids, (void*)(uintptr_t)ctx_id);
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
    DceRpcCoHdr* co_hdr)
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

    sd->ropts.hdr_byte_order = DceRpcCoByteOrder(co_hdr);
    sd->ropts.data_byte_order = data_byte_order;
    sd->ropts.opnum = opnum;
    sd->ropts.stub_data = cot->stub_data;
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
        /* Assume we autodetected incorrectly or that DCE/RPC is not running
         * over the SMB named pipe */
        if (!DCE2_SsnAutodetected(sd) && (sd->trans != DCE2_TRANS_TYPE__SMB))
        {
            //FIXIT-M add segment check
            dce_alert(GID_DCE2, DCE2_CO_FRAG_LEN_LT_HDR,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }

    if (DceRpcCoVersMaj(co_hdr) != DCERPC_PROTO_MAJOR_VERS__5)
    {
        if (!DCE2_SsnAutodetected(sd) && (sd->trans != DCE2_TRANS_TYPE__SMB))
        {
            //FIXIT-M add segment check
            dce_alert(GID_DCE2, DCE2_CO_BAD_MAJOR_VERSION,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }

    if (DceRpcCoVersMin(co_hdr) != DCERPC_PROTO_MINOR_VERS__0)
    {
        if (!DCE2_SsnAutodetected(sd) && (sd->trans != DCE2_TRANS_TYPE__SMB))
        {
            //FIXIT-M add segment check
            dce_alert(GID_DCE2, DCE2_CO_BAD_MINOR_VERSION,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }
    if (pdu_type >= DCERPC_PDU_TYPE__MAX)
    {
        if (!DCE2_SsnAutodetected(sd) && (sd->trans != DCE2_TRANS_TYPE__SMB))
        {
            //FIXIT-M add segment check

            dce_alert(GID_DCE2, DCE2_CO_BAD_PDU_TYPE,dce_common_stats);
        }

        return DCE2_RET__ERROR;
    }

    if (DCE2_SsnFromClient(sd->wire_pkt) && (cot->max_xmit_frag != DCE2_SENTINEL))
    {
        if (frag_len > cot->max_xmit_frag)
        {
            //FIXIT-M add segment check
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

            //FIXIT-M add segment check
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

    free(data);
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

static DCE2_CoCtxIdNode* dce_process_ctx_id(DCE2_SsnData* sd,DCE2_CoTracker* cot,
    const DceRpcCoHdr* co_hdr,DCE2_Policy policy,
    const uint8_t* frag_ptr, uint16_t frag_len)
{
    DCE2_CoCtxIdNode* ctx_node;
    DCE2_Ret status;
    uint16_t ctx_id;
    uint8_t num_tsyns;
    const Uuid* iface;
    uint16_t if_vers_maj;
    uint16_t if_vers_min;
    DceRpcCoContElem* ctx_elem = (DceRpcCoContElem*)frag_ptr;
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

    ctx_node = (DCE2_CoCtxIdNode*)calloc(sizeof(DCE2_CoCtxIdNode),1);
    if (ctx_node == nullptr)
    {
        return nullptr;
    }

    /* Add context id to pending queue */
    status = DCE2_QueueEnqueue(cot->pending_ctx_ids, ctx_node);
    if (status != DCE2_RET__SUCCESS)
    {
        free(ctx_node);
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

        ctx_node = dce_process_ctx_id(sd,cot,co_hdr,policy,frag_ptr,frag_len);
        if (ctx_node == nullptr)
        {
            return;
        }

        DebugFormat(DEBUG_DCE_COMMON, "Added Context item to queue.\n"
            " Context id: %u\n"
            " Interface: %s\n"
            " Interface major version: %u\n"
            " Interface minor version: %u\n",
            ctx_node->ctx_id,
            DCE2_UuidToStr(&ctx_node->iface, DCERPC_BO_FLAG__NONE),
            ctx_node->iface_vers_maj, ctx_node->iface_vers_min);

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

static void dce_process_ctx_result(DCE2_SsnData* sd,DCE2_CoTracker* cot,
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
     * context id list or free'd */
    ctx_node = (DCE2_CoCtxIdNode*)DCE2_QueueDequeue(cot->pending_ctx_ids);
    if (ctx_node == nullptr)
    {
        LogMessage("%s(%d) Failed to dequeue a context id node.\n",
            __FILE__, __LINE__);
        return;
    }

    DebugFormat(DEBUG_DCE_COMMON, "Adding Context item to context item list.\n"
        " Context id: %u\n"
        " Interface: %s\n"
        " Interface major version: %u\n"
        " Interface minor version: %u\n",
        ctx_node->ctx_id,
        DCE2_UuidToStr(&ctx_node->iface, DCERPC_BO_FLAG__NONE),
        ctx_node->iface_vers_maj, ctx_node->iface_vers_min);

    if (result == DCERPC_CO_CONT_DEF_RESULT__ACCEPTANCE)
    {
        DebugMessage(DEBUG_DCE_COMMON, "Server accepted context item.\n");
        ctx_node->state = DCE2_CO_CTX_STATE__ACCEPTED;
        if (DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__BIND_ACK)
            cot->got_bind = 1;
    }
    else
    {
        DebugMessage(DEBUG_DCE_COMMON, "Server rejected context item.\n");
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

        free((void*)ctx_node);
    }
    else
    {
        status = DCE2_ListInsert(cot->ctx_ids, (void*)(uintptr_t)ctx_node->ctx_id,
            (void*)ctx_node);
        if (status != DCE2_RET__SUCCESS)
        {
            free((void*)ctx_node);
            DebugMessage(DEBUG_DCE_COMMON,
                "Failed to add context id node to list.\n");
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
    DceRpcCoBindAck* bind_ack = (DceRpcCoBindAck*)frag_ptr;
    uint16_t sec_addr_len;
    const uint8_t* ctx_data;
    uint16_t ctx_len;
    uint16_t pad = 0;
    DceRpcCoContResultList* ctx_list;
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

    ctx_list = (DceRpcCoContResultList*)ctx_data;
    num_ctx_results = DceRpcCoContNumResults(ctx_list);

    DCE2_MOVE(ctx_data, ctx_len, sizeof(DceRpcCoContResultList));

    for (i = 0; i < num_ctx_results; i++)
    {
        DceRpcCoContResult* ctx_result;
        uint16_t result;

        if (ctx_len < sizeof(DceRpcCoContResult))
        {
            dce_alert(GID_DCE2, DCE2_CO_REM_FRAG_LEN_LT_SIZE,dce_common_stats);
            return;
        }
        ctx_result = (DceRpcCoContResult*)ctx_data;
        result = DceRpcCoContRes(co_hdr, ctx_result);

        DCE2_MOVE(ctx_data, ctx_len, sizeof(DceRpcCoContResult));

        if (DCE2_QueueIsEmpty(cot->pending_ctx_ids))
            return;

        dce_process_ctx_result(sd,cot,co_hdr,policy,result);
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
    DceRpcCoBind* bind = (DceRpcCoBind*)frag_ptr;
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
        LogMessage("%s(%d) Invalid policy: %d\n",
            __FILE__, __LINE__, policy);
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
    DceRpcCoAltCtx* alt_ctx = (DceRpcCoAltCtx*)frag_ptr;
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
        LogMessage("%s(%d) Invalid policy: %d\n",
            __FILE__, __LINE__, policy);
        break;
    }

    /* Alter context is typedef'ed as a bind */
    DCE2_CoCtxReq(sd, cot, co_hdr, DceRpcCoNumCtxItems((DceRpcCoBind*)alt_ctx), frag_ptr,
        frag_len);
}

static int DCE2_CoGetAuthLen(DCE2_SsnData* sd, const DceRpcCoHdr* co_hdr,
    const uint8_t* frag_ptr, uint16_t frag_len)
{
    DceRpcCoAuthVerifier* auth_hdr;
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

    auth_hdr = (DceRpcCoAuthVerifier*)(frag_ptr + (frag_len - auth_len));
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
    DceRpcCoRequest* rhdr = (DceRpcCoRequest*)frag_ptr;
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

    //FIXIT-M frag stuff

    cot->stub_data = frag_ptr;
    cot->opnum = DceRpcCoOpnum(co_hdr, rhdr);
    cot->ctx_id = DceRpcCoCtxId(co_hdr, rhdr);
    cot->call_id = DceRpcCoCallId(co_hdr);

    if (DceRpcCoFirstFrag(co_hdr) && DceRpcCoLastFrag(co_hdr))
    {
        int auth_len = DCE2_CoGetAuthLen(sd, co_hdr, frag_ptr, frag_len);
        DebugMessage(DEBUG_DCE_COMMON, "First and last fragment.\n");
        if (auth_len == -1)
            return;
        DCE2_CoSetRopts(sd, cot, co_hdr);
    }
    else
    {
        //FIXIT-M frag stuff
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
    DceRpcCoResponse* rhdr = (DceRpcCoResponse*)frag_ptr;
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
            LogMessage("%s(%d) Failed to dequeue a context id node.\n",
                __FILE__, __LINE__);
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
            free((void*)ctx_node);
            return;
        }
    }

    /* Move past header */
    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoResponse));

    //FIXIT-M frag stuff

    cot->stub_data = frag_ptr;
    /* Opnum not in response header - have to use previous client's */
    cot->ctx_id = ctx_id;
    cot->call_id = DceRpcCoCallId(co_hdr);

    if (DceRpcCoFirstFrag(co_hdr) && DceRpcCoLastFrag(co_hdr))
    {
        int auth_len = DCE2_CoGetAuthLen(sd, co_hdr, frag_ptr, frag_len);
        DebugMessage(DEBUG_DCE_COMMON, "First and last fragment.\n");
        if (auth_len == -1)
            return;
        DCE2_CoSetRopts(sd, cot, co_hdr);
    }
    else
    {
        /* FIXIT-M frag stuff */
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
    const DceRpcCoHdr* co_hdr = (DceRpcCoHdr*)frag_ptr;
    int pdu_type = DceRpcCoPduType(co_hdr);
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    /* We've got the main header.  Move past it to the
     * start of the pdu */
    DCE2_MOVE(frag_ptr, frag_len, sizeof(DceRpcCoHdr));

    DebugMessage(DEBUG_DCE_COMMON, "PDU type: ");

    /* Client specific pdu types - some overlap with server */
    if (DCE2_SsnFromClient(sd->wire_pkt))
    {
        switch (pdu_type)
        {
        case DCERPC_PDU_TYPE__BIND:
            DebugMessage(DEBUG_DCE_COMMON, "Bind\n");
            dce_common_stats->co_bind++;

            /* Make sure context id list and queue are initialized */
            if (DCE2_CoInitCtxStorage(cot) != DCE2_RET__SUCCESS)
                return;

            DCE2_CoBind(sd, cot, co_hdr, frag_ptr, frag_len);

            break;

        case DCERPC_PDU_TYPE__ALTER_CONTEXT:
            DebugMessage(DEBUG_DCE_COMMON, "Alter Context\n");
            dce_common_stats->co_alter_ctx++;

            if (DCE2_CoInitCtxStorage(cot) != DCE2_RET__SUCCESS)
                return;

            DCE2_CoAlterCtx(sd, cot, co_hdr, frag_ptr, frag_len);

            break;

        case DCERPC_PDU_TYPE__REQUEST:
            DebugMessage(DEBUG_DCE_COMMON, "Request\n");
            dce_common_stats->co_request++;

            if (DCE2_ListIsEmpty(cot->ctx_ids) &&
                DCE2_QueueIsEmpty(cot->pending_ctx_ids))
            {
                return;
            }

            DCE2_CoRequest(sd, cot, co_hdr, frag_ptr, frag_len);

            break;

        case DCERPC_PDU_TYPE__AUTH3:
            DebugMessage(DEBUG_DCE_COMMON, "Auth3\n");
            dce_common_stats->co_auth3++;
            break;

        case DCERPC_PDU_TYPE__CO_CANCEL:
            DebugMessage(DEBUG_DCE_COMMON, "Cancel\n");
            dce_common_stats->co_cancel++;
            break;

        case DCERPC_PDU_TYPE__ORPHANED:
            DebugMessage(DEBUG_DCE_COMMON, "Orphaned\n");
            dce_common_stats->co_orphaned++;
            break;

        case DCERPC_PDU_TYPE__MICROSOFT_PROPRIETARY_OUTLOOK2003_RPC_OVER_HTTP:
            DebugMessage(DEBUG_DCE_COMMON, "Microsoft Request To Send RPC over HTTP\n");
            dce_common_stats->co_ms_pdu++;
            break;

        default:
            DebugFormat(DEBUG_DCE_COMMON, "Unknown (0x%02x)\n", pdu_type);
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
                DebugMessage(DEBUG_DCE_COMMON, "Bind Ack\n");
                dce_common_stats->co_bind_ack++;
            }
            else
            {
                DebugMessage(DEBUG_DCE_COMMON, "Alter Context Response\n");
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
            DebugMessage(DEBUG_DCE_COMMON, "Bind Nack\n");
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
            DebugMessage(DEBUG_DCE_COMMON, "Response\n");
            dce_common_stats->co_response++;
            DCE2_CoResponse(sd, cot, co_hdr, frag_ptr, frag_len);
            break;

        case DCERPC_PDU_TYPE__FAULT:
            DebugMessage(DEBUG_DCE_COMMON, "Fault\n");
            dce_common_stats->co_fault++;

            /* Clear out the client side */
            DCE2_QueueEmpty(cot->pending_ctx_ids);
            DCE2_BufferEmpty(cot->cli_seg.buf);
            DCE2_BufferEmpty(cot->frag_tracker.cli_stub_buf);

            DCE2_CoResetTracker(cot);

            break;

        case DCERPC_PDU_TYPE__SHUTDOWN:
            DebugMessage(DEBUG_DCE_COMMON, "Shutdown\n");
            dce_common_stats->co_shutdown++;
            break;

        case DCERPC_PDU_TYPE__REJECT:
            DebugMessage(DEBUG_DCE_COMMON, "Reject\n");
            dce_common_stats->co_reject++;

            DCE2_QueueEmpty(cot->pending_ctx_ids);

            break;

        case DCERPC_PDU_TYPE__MICROSOFT_PROPRIETARY_OUTLOOK2003_RPC_OVER_HTTP:
            DebugMessage(DEBUG_DCE_COMMON, "Microsoft Request To Send RPC over HTTP\n");
            dce_common_stats->co_ms_pdu++;
            break;

        default:
            DebugFormat(DEBUG_DCE_COMMON, "Unknown (0x%02x)\n", pdu_type);
            dce_common_stats->co_other_resp++;
            break;
        }
    }
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
    uint32_t num_frags = 0;
    dce2CommonStats* dce_common_stats = dce_get_proto_stats_ptr(sd);

    dce_common_stats->co_pdus++;

    co_reassembled = 0;

    while (data_len > 0)
    {
        num_frags++;

        DebugFormat(DEBUG_DCE_COMMON, "DCE/RPC message number: %u\n", num_frags);

        /* Fast track full fragments */
        if (DCE2_BufferIsEmpty(seg->buf))
        {
            const uint8_t* frag_ptr = data_ptr;
            uint16_t frag_len;

            /* Not enough data left for a header.  Buffer it and return */
            if (data_len < sizeof(DceRpcCoHdr))
            {
                // FIXIT-M add logic for this case
                break;
            }

            if (DCE2_CoHdrChecks(sd, cot, (DceRpcCoHdr*)data_ptr) != DCE2_RET__SUCCESS)
                return;

            frag_len = DceRpcCoFragLen((DceRpcCoHdr*)data_ptr);

            /* Not enough data left for the pdu. */
            if (data_len < frag_len)
            {
                // FIXIT-M add logic for this case
                break;
            }

            DCE2_MOVE(data_ptr, data_len, frag_len);

            /* Got a full DCE/RPC pdu */
            DCE2_CoDecode(sd, cot, frag_ptr, frag_len);

            /* If we're configured to do defragmentation only detect on first frag
             * since we'll detect on reassembled */
            if (!DCE2_GcDceDefrag((dce2CommonProtoConf*)sd->config) ||
                ((num_frags == 1) && !co_reassembled))
                DCE2_Detect(sd);

            /* Reset if this is a last frag */
            if (DceRpcCoLastFrag((DceRpcCoHdr*)frag_ptr))
                num_frags = 0;
        }
        else  /* We've already buffered data */
        {
            // FIXIT-M add logic for this case
        }
    }

    // FIXIT-M add reassemble logic
}

