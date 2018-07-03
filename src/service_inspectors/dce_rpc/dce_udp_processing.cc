//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_udp.h"

#include "flow/session.h"
#include "main/snort_debug.h"
#include "utils/safec.h"
#include "utils/util.h"

#include "dce_common.h"
#include "dce_udp_module.h"

using namespace snort;

/********************************************************************
 * Macros
 ********************************************************************/
#define DCE2_CL__MAX_SEQ_NUM  UINT32_MAX

/********************************************************************
 * Structures
 ********************************************************************/
struct DCE2_ClFragNode
{
    uint32_t frag_number;
    uint16_t frag_len;
    uint8_t* frag_data;
};

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
static DCE2_ClActTracker* DCE2_ClGetActTracker(DCE2_ClTracker*, const DceRpcClHdr*);
static DCE2_ClActTracker* DCE2_ClInsertActTracker(DCE2_ClTracker*, const DceRpcClHdr*);
static void DCE2_ClRequest(DCE2_SsnData*, DCE2_ClActTracker*, const DceRpcClHdr*,
    const uint8_t*, uint16_t);
static void DCE2_ClHandleFrag(DCE2_SsnData*, DCE2_ClActTracker*,
    const DceRpcClHdr*, const uint8_t*, uint16_t);
static void DCE2_ClFragReassemble(DCE2_SsnData*, DCE2_ClActTracker*, const DceRpcClHdr*);
static void DCE2_ClResetFragTracker(DCE2_ClFragTracker*);
static void DCE2_ClSetRdata(DCE2_ClActTracker*, const DceRpcClHdr*, uint8_t*, uint16_t);

/* Callbacks */
static void DCE2_ClActDataFree(void*);
static void DCE2_ClActKeyFree(void*);
static int DCE2_ClFragCompare(const void*, const void*);
static void DCE2_ClFragDataFree(void*);

// Main entry point for connectionless DCE/RPC processing.  Gets
// the activity tracker associated with this session and passes
// along to client or server handling.
void DCE2_ClProcess(DCE2_SsnData* sd, DCE2_ClTracker* clt)
{
    const DceRpcClHdr* cl_hdr;
    DCE2_ClActTracker* at;
    const uint8_t* data_ptr = sd->wire_pkt->data;
    uint16_t data_len = sd->wire_pkt->dsize;

    if (data_len < sizeof(DceRpcClHdr))
    {
        dce_alert(GID_DCE2,  DCE2_CL_DATA_LT_HDR, (dce2CommonStats*)&dce2_udp_stats);
        return;
    }

    cl_hdr = (const DceRpcClHdr*)data_ptr;

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
            dce2_udp_stats.cl_request++;
            DCE2_ClRequest(sd, at, cl_hdr, data_ptr, data_len);
            break;

        case DCERPC_PDU_TYPE__ACK:
            dce2_udp_stats.cl_ack++;
            break;

        case DCERPC_PDU_TYPE__CL_CANCEL:
            dce2_udp_stats.cl_cancel++;
            break;

        case DCERPC_PDU_TYPE__FACK:
            dce2_udp_stats.cl_cli_fack++;
            break;

        case DCERPC_PDU_TYPE__PING:
            dce2_udp_stats.cl_ping++;
            break;

        case DCERPC_PDU_TYPE__RESPONSE:
        {
            trace_log(dce_udp, "Response from client.  Changing stream direction.\n");
            Packet* p = sd->wire_pkt;
            ip::IpApi* ip_api = &p->ptrs.ip_api;

            p->flow->session->update_direction(SSN_DIR_FROM_SERVER,
                ip_api->get_src(),
                p->ptrs.sp);

            break;
        }
        default:
            dce2_udp_stats.cl_other_req++;
            break;
        }
    }
    else
    {
        switch (DceRpcClPduType(cl_hdr))
        {
        case DCERPC_PDU_TYPE__RESPONSE:
            dce2_udp_stats.cl_response++;
            break;

        case DCERPC_PDU_TYPE__REJECT:
            dce2_udp_stats.cl_reject++;

            if (DceRpcClSeqNum(cl_hdr) == at->seq_num)
            {
                DCE2_ClResetFragTracker(&at->frag_tracker);
                at->seq_num_invalid = 1;
            }

            break;

        case DCERPC_PDU_TYPE__CANCEL_ACK:
            dce2_udp_stats.cl_cancel_ack++;
            break;

        case DCERPC_PDU_TYPE__FACK:
            dce2_udp_stats.cl_srv_fack++;
            break;

        case DCERPC_PDU_TYPE__FAULT:
            dce2_udp_stats.cl_fault++;
            break;

        case DCERPC_PDU_TYPE__NOCALL:
            dce2_udp_stats.cl_nocall++;
            break;

        case DCERPC_PDU_TYPE__WORKING:
            dce2_udp_stats.cl_working++;
            break;

        default:
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
        dce_alert(GID_DCE2, DCE2_CL_BAD_MAJOR_VERSION, (dce2CommonStats*)&dce2_udp_stats);
        return DCE2_RET__ERROR;
    }

    if (DceRpcClPduType(cl_hdr) >= DCERPC_PDU_TYPE__MAX)
    {
        dce_alert(GID_DCE2, DCE2_CL_BAD_PDU_TYPE, (dce2CommonStats*)&dce2_udp_stats);
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

// Searches for activity tracker in list using activity UUID in
// packet.
static DCE2_ClActTracker* DCE2_ClGetActTracker(DCE2_ClTracker* clt, const DceRpcClHdr* cl_hdr)
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
    }

    return at;
}

static DCE2_ClActTracker* DCE2_ClInsertActTracker(DCE2_ClTracker* clt, const DceRpcClHdr* cl_hdr)
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

static void DCE2_ClRequest(DCE2_SsnData* sd, DCE2_ClActTracker* at, const DceRpcClHdr* cl_hdr,
    const uint8_t* data_ptr, uint16_t data_len)
{
    const uint32_t seq_num = DceRpcClSeqNum(cl_hdr);

    if (seq_num > at->seq_num)
    {
        /* This is the normal case where the sequence number is incremented
         * for each request.  Set the new sequence number and mark it valid. */
        at->seq_num = seq_num;
        at->seq_num_invalid = 0;

        /* If there are any fragments, the new sequence number invalidates
         * all of the frags that might be currently stored. */
        DCE2_ClResetFragTracker(&at->frag_tracker);
    }
    else if ((seq_num < at->seq_num) || at->seq_num_invalid)
    {
        return;
    }

    DCE2_ResetRopts(sd, nullptr);

    if (!DceRpcClFrag(cl_hdr))  /* It's a full request */
    {
        if ((at->frag_tracker.frags != nullptr) &&
            !DCE2_ListIsEmpty(at->frag_tracker.frags))
        {
            /* If we get a full request, i.e. not a frag, any frags
             * we have collected are invalidated */
            DCE2_ClResetFragTracker(&at->frag_tracker);
        }
        else if (seq_num != DCE2_CL__MAX_SEQ_NUM)
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
    }
    else  /* It's a frag */
    {
        dce2_udp_stats.cl_fragments++;
        if (DCE2_GcDceDefrag((dce2CommonProtoConf*)sd->config))
        {
            DCE2_ClHandleFrag(sd, at, cl_hdr, data_ptr, data_len);
            return;
        }
    }

    /* Cache relevant values for rule option processing */
    sd->ropts.first_frag = DceRpcClFirstFrag(cl_hdr);
    DCE2_CopyUuid(&sd->ropts.iface, DceRpcClIface(cl_hdr), DceRpcClByteOrder(cl_hdr));
    sd->ropts.iface_vers = DceRpcClIfaceVers(cl_hdr);
    sd->ropts.opnum = DceRpcClOpnum(cl_hdr);
    sd->ropts.stub_data = (const uint8_t*)cl_hdr + sizeof(DceRpcClHdr);
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

// Handles connectionless fragments.  Creates a new fragment list
// if necessary and inserts fragment into list.  Sets rule option
// values based on the fragment.
static void DCE2_ClHandleFrag(DCE2_SsnData* sd, DCE2_ClActTracker* at, const DceRpcClHdr* cl_hdr,
    const uint8_t* data_ptr, uint16_t data_len)
{
    DCE2_ClFragTracker* ft = &at->frag_tracker;
    DCE2_ClFragNode* fn;
    uint16_t frag_len;
    int status;

    Profile profile(dce2_udp_pstat_cl_frag);

    /* If the frag length is less than data length there might be authentication
     * data that we don't want to include, otherwise just set to data len */
    if (DceRpcClLen(cl_hdr) < data_len)
        frag_len = DceRpcClLen(cl_hdr);
    else
        frag_len = data_len;

    if (frag_len == 0)
    {
        return;
    }

    if (frag_len > dce2_udp_stats.cl_max_frag_size)
        dce2_udp_stats.cl_max_frag_size = frag_len;

    if (DCE2_GcMaxFrag((dce2CommonProtoConf*)sd->config)
        && (frag_len > DCE2_GcMaxFragLen((dce2CommonProtoConf*)sd->config)))
        frag_len = DCE2_GcMaxFragLen((dce2CommonProtoConf*)sd->config);

    if (ft->frags == nullptr)
    {
        /* Create new list if we don't have one already */
        ft->frags = DCE2_ListNew(DCE2_LIST_TYPE__SORTED, DCE2_ClFragCompare, DCE2_ClFragDataFree,
            nullptr, DCE2_LIST_FLAG__NO_DUPS | DCE2_LIST_FLAG__INS_TAIL);

        if (ft->frags == nullptr)
        {
            return;
        }
    }
    else
    {
        /* If we already have a fragment in the list with the same fragment number,
         * that fragment will take precedence over this fragment and this fragment
         * will not be used by the server */
        fn = (DCE2_ClFragNode*)DCE2_ListFind(ft->frags, (void*)(uintptr_t)DceRpcClFragNum(cl_hdr));
        if (fn != nullptr)
        {
            return;
        }
    }

    /* Create a new frag node to insert into the list */
    fn = (DCE2_ClFragNode*)snort_calloc(sizeof(DCE2_ClFragNode));
    fn->frag_number = DceRpcClFragNum(cl_hdr);
    fn->frag_len = frag_len;

    /* Allocate space for the fragment data */
    fn->frag_data = (uint8_t*)snort_calloc(frag_len);

    /* Copy the fragment data in the packet to the space just allocated */
    memcpy(fn->frag_data, data_ptr, frag_len);

    if (DCE2_ListIsEmpty(ft->frags))
    {
        /* If this is the first fragment we've received, set interface uuid */
        DCE2_CopyUuid(&ft->iface, DceRpcClIface(cl_hdr), DceRpcClByteOrder(cl_hdr));
        ft->iface_vers = DceRpcClIfaceVers(cl_hdr);
    }

    if (DceRpcClLastFrag(cl_hdr))
    {
        /* Set number of expected frags on last frag */
        ft->num_expected_frags = DceRpcClFragNum(cl_hdr) + 1;
    }
    else if (DceRpcClFirstFrag(cl_hdr))
    {
        /* Set opum and byte order on first frag */
        ft->opnum = DceRpcClOpnum(cl_hdr);
        ft->data_byte_order = DceRpcClByteOrder(cl_hdr);
    }

    /* Insert frag node into the list */
    status = DCE2_ListInsert(ft->frags, (void*)(uintptr_t)fn->frag_number, (void*)fn);
    if (status != DCE2_RET__SUCCESS)
    {
        snort_free((void*)fn->frag_data);
        snort_free((void*)fn);

        DCE2_ClFragReassemble(sd, at, cl_hdr);
        return;
    }

    /* Fragment number field in header is uint16_t */
    if ((ft->num_expected_frags != DCE2_SENTINEL) &&
        (uint16_t)ft->frags->num_nodes == (uint16_t)ft->num_expected_frags)
    {
        /* We got all of the frags - reassemble */
        DCE2_ClFragReassemble(sd, at, cl_hdr);
        at->seq_num_invalid = 1;

        return;
    }

    /* Cache relevant values for rule option processing */
    sd->ropts.first_frag = DceRpcClFirstFrag(cl_hdr);
    DCE2_CopyUuid(&sd->ropts.iface, &ft->iface, DCERPC_BO_FLAG__NONE);
    sd->ropts.iface_vers = ft->iface_vers;
    DceEndianness* endianness = (DceEndianness*)sd->wire_pkt->endianness;
    endianness->hdr_byte_order = DceRpcClByteOrder(cl_hdr);

    if (ft->data_byte_order != DCE2_SENTINEL)
        endianness->data_byte_order = ft->data_byte_order;
    else
        endianness->data_byte_order = DceRpcClByteOrder(cl_hdr);

    if (ft->opnum != DCE2_SENTINEL)
        sd->ropts.opnum = ft->opnum;
    else
        sd->ropts.opnum = DceRpcClOpnum(cl_hdr);

    sd->ropts.stub_data = (const uint8_t*)cl_hdr + sizeof(DceRpcClHdr);

    DCE2_Detect(sd);
}

/********************************************************************
 * Function: DCE2_ClFragCompare()
 *
 * Callback to fragment list for sorting the nodes in the list
 * by fragment number.  Values passed in are the fragment numbers.
 *
 * Arguments:
 *  const void *
 *      First fragment number to compare.
 *  const void *
 *      Second fragment number to compare.
 *
 * Returns:
 *  int
 *       1 if first value is greater than second value
 *      -1 if first value is less than second value
 *       0 if first value equals second value
 *
 ********************************************************************/
static int DCE2_ClFragCompare(const void* a, const void* b)
{
    const int x = (int)(uintptr_t)a;
    const int y = (int)(uintptr_t)b;

    if (x > y)
        return 1;
    if (x < y)
        return -1;

    return 0;
}

// Reassembles fragments into reassembly buffer and copies to
// reassembly packet.
static void DCE2_ClFragReassemble(
    DCE2_SsnData* sd, DCE2_ClActTracker* at, const DceRpcClHdr* cl_hdr)
{
    uint8_t dce2_cl_rbuf[IP_MAXPACKET];
    DCE2_ClFragTracker* ft = &at->frag_tracker;
    const uint8_t* rdata = dce2_cl_rbuf;
    uint16_t rlen = sizeof(dce2_cl_rbuf);
    DCE2_ClFragNode* fnode;
    uint32_t stub_len = 0;

    Profile profile(dce2_udp_pstat_cl_reass);

    for (fnode = (DCE2_ClFragNode*)DCE2_ListFirst(ft->frags);
        fnode != nullptr;
        fnode = (DCE2_ClFragNode*)DCE2_ListNext(ft->frags))
    {
        if (fnode->frag_len > rlen)
            break;

        memcpy(const_cast<uint8_t*>(rdata), fnode->frag_data, fnode->frag_len);
        DCE2_MOVE(rdata, rlen, fnode->frag_len);
        stub_len += fnode->frag_len;
    }

    Packet* rpkt = DCE2_GetRpkt(
        sd->wire_pkt, DCE2_RPKT_TYPE__UDP_CL_FRAG, dce2_cl_rbuf, stub_len);

    if ( !rpkt )
        return;

    DCE2_ClSetRdata(at, cl_hdr, const_cast<uint8_t*>(rpkt->data),
        (uint16_t)(rpkt->dsize - DCE2_MOCK_HDR_LEN__CL));

    const uint8_t* stub_data = rpkt->data + DCE2_MOCK_HDR_LEN__CL;

    /* Cache relevant values for rule option processing */
    sd->ropts.first_frag = 1;
    DCE2_CopyUuid(&sd->ropts.iface, &ft->iface, DCERPC_BO_FLAG__NONE);
    sd->ropts.iface_vers = ft->iface_vers;
    DceEndianness* endianness = (DceEndianness*)sd->wire_pkt->endianness;
    endianness->hdr_byte_order = DceRpcClByteOrder(cl_hdr);

    if (ft->data_byte_order != DCE2_SENTINEL)
        endianness->data_byte_order = ft->data_byte_order;
    else
        endianness->data_byte_order = DceRpcClByteOrder(cl_hdr);

    if (ft->opnum != DCE2_SENTINEL)
        sd->ropts.opnum = ft->opnum;
    else
        sd->ropts.opnum = DceRpcClOpnum(cl_hdr);

    sd->ropts.stub_data = stub_data;

    DCE2_Detect(sd);

    dce2_udp_stats.cl_frag_reassembled++;
}

// Callback to fragment list for freeing data kept in list.  Need
// to free the frag node and the data attached to it.
static void DCE2_ClFragDataFree(void* data)
{
    DCE2_ClFragNode* fn = (DCE2_ClFragNode*)data;

    if (fn == nullptr)
        return;

    if (fn->frag_data != nullptr)
        snort_free((void*)fn->frag_data);

    snort_free((void*)fn);
}

// Destroys the fragment tracker's fragment list and resets opnum,
// byte order and number of expected frags to a sentinel.
static void DCE2_ClResetFragTracker(DCE2_ClFragTracker* ft)
{
    if (ft == nullptr)
        return;

    if (ft->frags != nullptr)
    {
        DCE2_ListDestroy(ft->frags);
        ft->frags = nullptr;
    }

    ft->opnum = DCE2_SENTINEL;
    ft->data_byte_order = DCE2_SENTINEL;
    ft->num_expected_frags = DCE2_SENTINEL;
}

void DCE2_ClInitRdata(uint8_t* buf)
{
    DceRpcClHdr* cl_hdr = (DceRpcClHdr*)buf;

    /* Set some relevant fields.  These should never get reset */
    cl_hdr->rpc_vers = DCERPC_PROTO_MAJOR_VERS__4;
    cl_hdr->ptype = DCERPC_PDU_TYPE__REQUEST;
    cl_hdr->drep[0] = 0x10;   /* Little endian */
}

// Sets relevant data fields in the reassembly packet.
static void DCE2_ClSetRdata(DCE2_ClActTracker* at, const DceRpcClHdr* pkt_cl_hdr,
    uint8_t* cl_ptr, uint16_t stub_len)
{
    DCE2_ClFragTracker* ft = &at->frag_tracker;
    DceRpcClHdr* cl_hdr = (DceRpcClHdr*)cl_ptr;
    const uint16_t opnum = (ft->opnum != DCE2_SENTINEL) ? (uint16_t)ft->opnum : DceRpcClOpnum(
        pkt_cl_hdr);

    cl_hdr->len = DceRpcHtons(&stub_len, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    DCE2_CopyUuid(&cl_hdr->object, &pkt_cl_hdr->object, DceRpcClByteOrder(cl_hdr));
    DCE2_CopyUuid(&cl_hdr->if_id, &ft->iface, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    DCE2_CopyUuid(&cl_hdr->act_id, &at->act, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    cl_hdr->if_vers = DceRpcHtonl(&ft->iface_vers, DCERPC_BO_FLAG__LITTLE_ENDIAN);
    cl_hdr->opnum = DceRpcHtons(&opnum, DCERPC_BO_FLAG__LITTLE_ENDIAN);
}

