//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2008-2013 Sourcefire, Inc.
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

// dce_udp_processing.cc author Todd Wease
// modifications for snort3 by Maya Dagon <mdagon@cisco.com>

// Module for handling connectionless DCE/RPC processing.  Provides
// functionality for tracking sub-sessions or activities within a
// connectionless conversation and for tracking and reassembling fragments
// within each activity.  Also sets appropriate data for use with
// preprocessor rule options.

#include "dce_udp.h"

#include "flow/session.h"
#include "main/snort_debug.h"
#include "utils/util.h"

#include "dce_common.h"
#include "dce_udp_module.h"

/********************************************************************
 * Macros
 ********************************************************************/
#define DCE2_CL__MAX_SEQ_NUM  UINT32_MAX

/********************************************************************
 * Structures
 ********************************************************************/
struct DCE2_ClFragTracker
{
    Uuid iface;          /* only set on first fragment received */
    uint32_t iface_vers; /* only set on first fragment received */
    int opnum;           /* set to that of first fragment, i.e fragment number == 0.
                          * initialize to a sentinel */
    int data_byte_order; /* set to that of first fragment, i.e fragment number == 0.
                          * initialize to sentinel */

    DCE2_List* frags;         /* sorted by fragment number */
    int num_expected_frags;   /* set when we get last frag */
};

struct DCE2_ClActTracker
{
    Uuid act;
    uint32_t seq_num;
    uint8_t seq_num_invalid;

    DCE2_ClFragTracker frag_tracker;
};

/********************************************************************
 * Private function prototypes
 ********************************************************************/
static DCE2_Ret DCE2_ClHdrChecks(DCE2_SsnData*, const DceRpcClHdr*);
static DCE2_ClActTracker* DCE2_ClGetActTracker(DCE2_ClTracker*, DceRpcClHdr*);
static DCE2_ClActTracker* DCE2_ClInsertActTracker(DCE2_ClTracker*, DceRpcClHdr*);
static void DCE2_ClRequest(DCE2_SsnData*, DCE2_ClActTracker*, DceRpcClHdr*,
    const uint8_t*, uint16_t);

/* Callbacks */
static void DCE2_ClActDataFree(void*);
static void DCE2_ClActKeyFree(void*);

// Main entry point for connectionless DCE/RPC processing.  Gets
// the activity tracker associated with this session and passes
// along to client or server handling.
void DCE2_ClProcess(DCE2_SsnData* sd, DCE2_ClTracker* clt)
{
    DceRpcClHdr* cl_hdr;
    DCE2_ClActTracker* at;
    const uint8_t* data_ptr = sd->wire_pkt->data;
    uint16_t data_len = sd->wire_pkt->dsize;

    DebugMessage(DEBUG_DCE_UDP, "Cl processing ...\n");

    if (data_len < sizeof(DceRpcClHdr))
    {
        // FIXIT-M  currently we always do autodetect. Uncomment once
        // detect/autodetect is supported.
/*
        if (!DCE2_SsnAutodetected(sd))
             dce_alert(GID_DCE2,  DCE2_CL_DATA_LT_HDR, (dce2CommonStats*)&dce2_udp_stats);
*/
        return;
    }

    cl_hdr = (DceRpcClHdr*)data_ptr;

    DCE2_MOVE(data_ptr, data_len, sizeof(DceRpcClHdr));

    if (DCE2_ClHdrChecks(sd, cl_hdr) != DCE2_RET__SUCCESS)
        return;

    Profile profile(dce2_udp_pstat_cl_acts);
    at = DCE2_ClGetActTracker(clt, cl_hdr);
    if (at == nullptr)
        return;

    if (DCE2_SsnFromClient(sd->wire_pkt))
    {
        switch (DceRpcClPduType(cl_hdr))
        {
        case DCERPC_PDU_TYPE__REQUEST:
            DebugMessage(DEBUG_DCE_UDP, "Request\n");
            dce2_udp_stats.cl_request++;
            DCE2_ClRequest(sd, at, cl_hdr, data_ptr, data_len);
            break;

        case DCERPC_PDU_TYPE__ACK:
            DebugMessage(DEBUG_DCE_UDP, "Ack\n");
            dce2_udp_stats.cl_ack++;
            break;

        case DCERPC_PDU_TYPE__CL_CANCEL:
            DebugMessage(DEBUG_DCE_UDP, "Cancel\n");
            dce2_udp_stats.cl_cancel++;
            break;

        case DCERPC_PDU_TYPE__FACK:
            DebugMessage(DEBUG_DCE_UDP, "Fack\n");
            dce2_udp_stats.cl_cli_fack++;
            break;

        case DCERPC_PDU_TYPE__PING:
            DebugMessage(DEBUG_DCE_UDP, "Ping\n");
            dce2_udp_stats.cl_ping++;
            break;

        case DCERPC_PDU_TYPE__RESPONSE:
        {
            DebugMessage(DEBUG_DCE_UDP, "Response from client.  Changing stream direction.");
            Packet* p = sd->wire_pkt;
            ip::IpApi* ip_api = &p->ptrs.ip_api;

            p->flow->session->update_direction(SSN_DIR_FROM_SERVER,
                ip_api->get_src(),
                p->ptrs.sp);

            break;
        }
        default:
            DebugMessage(DEBUG_DCE_UDP, "Other pdu type\n");
            dce2_udp_stats.cl_other_req++;
            break;
        }
    }
    else
    {
        switch (DceRpcClPduType(cl_hdr))
        {
        case DCERPC_PDU_TYPE__RESPONSE:
            DebugMessage(DEBUG_DCE_UDP, "Response\n");
            dce2_udp_stats.cl_response++;
            break;

        case DCERPC_PDU_TYPE__REJECT:
            DebugMessage(DEBUG_DCE_UDP, "Reject\n");
            dce2_udp_stats.cl_reject++;

            if (DceRpcClSeqNum(cl_hdr) == at->seq_num)
            {
                // FIXIT-M uncomment once fragments is ported
                //DCE2_ClResetFragTracker(&at->frag_tracker);
                at->seq_num_invalid = 1;
            }

            break;

        case DCERPC_PDU_TYPE__CANCEL_ACK:
            DebugMessage(DEBUG_DCE_UDP, "Cancel Ack\n");
            dce2_udp_stats.cl_cancel_ack++;
            break;

        case DCERPC_PDU_TYPE__FACK:
            DebugMessage(DEBUG_DCE_UDP, "Fack\n");
            dce2_udp_stats.cl_srv_fack++;
            break;

        case DCERPC_PDU_TYPE__FAULT:
            DebugMessage(DEBUG_DCE_UDP, "Fault\n");
            dce2_udp_stats.cl_fault++;
            break;

        case DCERPC_PDU_TYPE__NOCALL:
            DebugMessage(DEBUG_DCE_UDP, "No call\n");
            dce2_udp_stats.cl_nocall++;
            break;

        case DCERPC_PDU_TYPE__WORKING:
            DebugMessage(DEBUG_DCE_UDP, "Working\n");
            dce2_udp_stats.cl_working++;
            break;

        default:
            DebugMessage(DEBUG_DCE_UDP, "Other pdu type\n");
            dce2_udp_stats.cl_other_resp++;
            break;
        }
    }
}

// Checks to make sure header fields are sane.  If they aren't,
// alert on the header anomaly.  If we've autodetected the session,
// however, don't alert, but set a header anomaly flag, so we can
// re-autodetect on the next go around.
static DCE2_Ret DCE2_ClHdrChecks(DCE2_SsnData*, const DceRpcClHdr* cl_hdr)
{
    if (DceRpcClRpcVers(cl_hdr) != DCERPC_PROTO_MAJOR_VERS__4)
    {
        // FIXIT-M  currently we always do autodetect. Uncomment once
        // detect/autodetect is supported.
        /* If we autodetected the session, we probably guessed wrong */
        /* if (!DCE2_SsnAutodetected(sd))
            dce_alert(GID_DCE2, DCE2_CL_BAD_MAJOR_VERSION, (dce2CommonStats*)&dce2_udp_stats);
        */
        return DCE2_RET__ERROR;
    }

    if (DceRpcClPduType(cl_hdr) >= DCERPC_PDU_TYPE__MAX)
    {
        // FIXIT-M  currently we always do autodetect. Uncomment once
        // detect/autodetect is supported.
/*
        if (!DCE2_SsnAutodetected(sd))
            dce_alert(GID_DCE2, DCE2_CL_BAD_PDU_TYPE, (dce2CommonStats*)&dce2_udp_stats);
*/
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// Searches for activity tracker in list using activity UUID in
// packet.
static DCE2_ClActTracker* DCE2_ClGetActTracker(DCE2_ClTracker* clt, DceRpcClHdr* cl_hdr)
{
    DCE2_ClActTracker* at = nullptr;

    /* Try to find a currently active activity tracker */
    if (clt->act_trackers != nullptr)
    {
        Uuid uuid;

        DCE2_CopyUuid(&uuid, &cl_hdr->act_id, DceRpcClByteOrder(cl_hdr));
        at = (DCE2_ClActTracker*)DCE2_ListFind(clt->act_trackers, (void*)&uuid);
    }
    else
    {
        /* Create a new activity tracker list */
        clt->act_trackers = DCE2_ListNew(DCE2_LIST_TYPE__SPLAYED, DCE2_UuidCompare,
            DCE2_ClActDataFree, DCE2_ClActKeyFree,
            DCE2_LIST_FLAG__NO_DUPS);
        if (clt->act_trackers == nullptr)
            return nullptr;
    }

    /* Didn't find a currently active activity tracker */
    if (at == nullptr)
    {
        /* Insert a new activity tracker */
        at = DCE2_ClInsertActTracker(clt, cl_hdr);
        if (at == nullptr)
            return nullptr;
    }

    return at;
}

static DCE2_ClActTracker* DCE2_ClInsertActTracker(DCE2_ClTracker* clt, DceRpcClHdr* cl_hdr)
{
    Uuid* uuid = (Uuid*)snort_calloc(sizeof(Uuid));
    DCE2_ClActTracker* at = (DCE2_ClActTracker*)snort_calloc(sizeof(DCE2_ClActTracker));

    DCE2_CopyUuid(uuid, &cl_hdr->act_id, DceRpcClByteOrder(cl_hdr));
    DCE2_CopyUuid(&at->act, &cl_hdr->act_id, DceRpcClByteOrder(cl_hdr));

    DCE2_Ret status = DCE2_ListInsert(clt->act_trackers, (void*)uuid, (void*)at);
    if (status != DCE2_RET__SUCCESS)
    {
        snort_free((void*)uuid);
        snort_free((void*)at);
        return nullptr;
    }

    return at;
}

static void DCE2_ClRequest(DCE2_SsnData* sd, DCE2_ClActTracker* at, DceRpcClHdr* cl_hdr,
    const uint8_t*, uint16_t)
{
    const uint32_t seq_num = DceRpcClSeqNum(cl_hdr);

    DebugMessage(DEBUG_DCE_UDP, "Processing Request ...\n");

    if (seq_num > at->seq_num)
    {
        /* This is the normal case where the sequence number is incremented
         * for each request.  Set the new sequence number and mark it valid. */
        at->seq_num = seq_num;
        at->seq_num_invalid = 0;

        /* If there are any fragments, the new sequence number invalidates
         * all of the frags that might be currently stored. */
        // FIXIT-M uncomment when porting fragments support
        // DCE2_ClResetFragTracker(&at->frag_tracker);
    }
    else if ((seq_num < at->seq_num) || at->seq_num_invalid)
    {
        return;
    }

    DCE2_ResetRopts(&sd->ropts);

    if (!DceRpcClFrag(cl_hdr))
    {
        // FIXIT-M add fragments cleanup

        if (seq_num != DCE2_CL__MAX_SEQ_NUM)
        {
            /* This sequence number is now invalid. 0xffffffff is the end of
             * the sequence number space and can be reused */
            at->seq_num_invalid = 1;
        }
        else
        {
            /* Got the last sequence number in the sequence number space */
            dce2_udp_stats.cl_max_seqnum++;
        }
    } // FIXIT-M add else - fragments path

    /* Cache relevant values for rule option processing */
    sd->ropts.first_frag = DceRpcClFirstFrag(cl_hdr);
    DCE2_CopyUuid(&sd->ropts.iface, DceRpcClIface(cl_hdr), DceRpcClByteOrder(cl_hdr));
    sd->ropts.iface_vers = DceRpcClIfaceVers(cl_hdr);
    sd->ropts.opnum = DceRpcClOpnum(cl_hdr);
    sd->ropts.stub_data = (uint8_t*)cl_hdr + sizeof(DceRpcClHdr);
    DceEndianness* endianness = (DceEndianness*)sd->wire_pkt->endianness;
    endianness->hdr_byte_order = DceRpcClByteOrder(cl_hdr);
    endianness->data_byte_order = DceRpcClByteOrder(cl_hdr);
    DCE2_Detect(sd);
}

static void DCE2_ClActDataFree(void* data)
{
    DCE2_ClActTracker* at = (DCE2_ClActTracker*)data;

    if (at == nullptr)
        return;

    DCE2_ListDestroy(at->frag_tracker.frags);
    at->frag_tracker.frags = nullptr;
    snort_free((void*)at);
}

static void DCE2_ClActKeyFree(void* key)
{
    if (key == nullptr)
        return;

    snort_free(key);
}

