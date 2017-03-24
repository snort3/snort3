//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// dce_tcp_paf.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_tcp_paf.h"

#include "main/snort_debug.h"

#include "dce_tcp.h"

/*********************************************************************
 * Function: dce2_tcp_paf()
 *
 * Purpose: The DCE/RPC over TCP PAF callback.
 *          Inspects a byte at a time changing state.  At state 4
 *          gets byte order of PDU.  At states 8 and 9 gets
 *          fragment length and sets flush point if no more data.
 *          Otherwise accumulates flush points because there can
 *          be multiple PDUs in a single TCP segment (evasion case).
 *
 *********************************************************************/
static StreamSplitter::Status dce2_tcp_paf(DCE2_PafTcpData* ds, Flow* flow, const uint8_t* data,
    uint32_t len, uint32_t flags, uint32_t* fp)
{
    uint32_t n = 0;
    int start_state;
    StreamSplitter::Status ps = StreamSplitter::SEARCH;
    uint32_t tmp_fp = 0;
    DCE2_TcpSsnData* sd = get_dce2_tcp_session_data(flow);

    int num_requests = 0;

    DebugFormat(DEBUG_DCE_TCP, "%s\n", DCE2_DEBUG__PAF_START_MSG_TCP);
    DebugFormat(DEBUG_DCE_TCP, "TCP: %u bytes of data\n", len);

#ifdef DEBUG_MSGS
    if (flags & PKT_FROM_CLIENT)
        DebugMessage(DEBUG_DCE_TCP, "Packet from Client\n");
    else
        DebugMessage(DEBUG_DCE_TCP, "Packet from Server\n");
#endif

    if (dce2_paf_abort(flow, (DCE2_SsnData*)sd))
    {
        DebugFormat(DEBUG_DCE_TCP, "%s\n", DCE2_DEBUG__PAF_END_MSG);
        return StreamSplitter::ABORT;
    }

    if (sd == nullptr)
    {
        bool autodetected = false;
        DebugMessage(DEBUG_DCE_TCP, "No session data - autodetecting\n");

        if (len >= sizeof(DceRpcCoHdr))
        {
            DceRpcCoHdr* co_hdr = (DceRpcCoHdr*)data;

            if ((DceRpcCoVersMaj(co_hdr) == DCERPC_PROTO_MAJOR_VERS__5)
                && (DceRpcCoVersMin(co_hdr) == DCERPC_PROTO_MINOR_VERS__0)
                && (((flags & PKT_FROM_CLIENT)
                && DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__BIND)
                || ((flags & PKT_FROM_SERVER)
                && DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__BIND_ACK))
                && (DceRpcCoFragLen(co_hdr) >= sizeof(DceRpcCoHdr)))
            {
                autodetected = true;
                DebugMessage(DEBUG_DCE_TCP, "Autodetected!\n");
            }
        }
        else if ((*data == DCERPC_PROTO_MAJOR_VERS__5) && (flags & PKT_FROM_CLIENT))
        {
            autodetected = true;
            DebugMessage(DEBUG_DCE_TCP, "Autodetected!\n");
        }

        if (!autodetected)
        {
            DebugMessage(DEBUG_DCE_TCP, "Couldn't autodetect - aborting\n");
            DebugFormat(DEBUG_DCE_TCP, "%s\n", DCE2_DEBUG__PAF_END_MSG);
            return StreamSplitter::ABORT;
        }
    }

    DebugFormat(DEBUG_DCE_TCP, "Start state: %d\n", ds->paf_state);
    start_state = (uint8_t)ds->paf_state;

    while (n < len)
    {
        DebugFormatNoFileLine(DEBUG_DCE_TCP, " State %d : 0x%02x\n", ds->paf_state, data[n]);

        switch (ds->paf_state)
        {
        case DCE2_PAF_TCP_STATES__4:      // Get byte order
            ds->byte_order = DceRpcByteOrder(data[n]);
            ds->paf_state = (DCE2_PafTcpStates)(((int)ds->paf_state) + 1);
            if (ds->byte_order == DCERPC_BO_FLAG__LITTLE_ENDIAN)
            {
                DebugFormatNoFileLine(DEBUG_DCE_TCP, "%s","Byte order: Little endian\n");
            }
            else
            {
                DebugFormatNoFileLine(DEBUG_DCE_TCP, "%s","Byte order: Big endian\n");
            }
            break;
        case DCE2_PAF_TCP_STATES__8:
            DebugFormatNoFileLine(DEBUG_DCE_TCP, "%s", "First byte of fragment length\n");
            if (ds->byte_order == DCERPC_BO_FLAG__LITTLE_ENDIAN)
                ds->frag_len = data[n];
            else
                ds->frag_len = data[n] << 8;
            ds->paf_state = (DCE2_PafTcpStates)(((int)ds->paf_state) + 1);
            break;
        case DCE2_PAF_TCP_STATES__9:
            DebugFormatNoFileLine(DEBUG_DCE_TCP, "%s", "Second byte of fragment length\n");
            if (ds->byte_order == DCERPC_BO_FLAG__LITTLE_ENDIAN)
                ds->frag_len |= data[n] << 8;
            else
                ds->frag_len |= data[n];

            /* If we get a bad frag length abort */
            if (ds->frag_len < sizeof(DceRpcCoHdr))
            {
                DebugFormatNoFileLine(DEBUG_DCE_TCP, "%s\n", DCE2_DEBUG__PAF_END_MSG);
                return StreamSplitter::ABORT;
            }

            DebugFormatNoFileLine(DEBUG_DCE_TCP, "Fragment length: %hu\n", ds->frag_len);

            /* Increment n here so we can continue */
            n += ds->frag_len - (uint8_t)ds->paf_state;
            num_requests++;
            /* Might have multiple PDUs in one segment.  If the last PDU is partial,
             * flush just before it */
            if ((num_requests == 1) || (n <= len))
                tmp_fp += ds->frag_len;
            DebugFormatNoFileLine(DEBUG_DCE_TCP, "Requests: %d\n", num_requests);
            ds->paf_state = DCE2_PAF_TCP_STATES__0;
            continue;      // we incremented n already
        default:
            ds->paf_state = (DCE2_PafTcpStates)(((int)ds->paf_state) + 1);
            break;
        }

        n++;
    }

    if (tmp_fp != 0)
    {
        *fp = tmp_fp - start_state;
        DebugFormat(DEBUG_DCE_TCP, "Setting flush point: %u\n", *fp);
        DebugFormat(DEBUG_DCE_TCP, "%s\n", DCE2_DEBUG__PAF_END_MSG);
        return StreamSplitter::FLUSH;
    }

    DebugFormat(DEBUG_DCE_TCP, "%s\n", DCE2_DEBUG__PAF_END_MSG);
    return ps;
}

Dce2TcpSplitter::Dce2TcpSplitter(bool c2s) : StreamSplitter(c2s)
{
    state.paf_state = DCE2_PAF_TCP_STATES__0;
    state.byte_order = DCERPC_BO_FLAG__NONE;
    state.frag_len = 0;
}

StreamSplitter::Status Dce2TcpSplitter::scan(
    Flow* flow, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    DCE2_PafTcpData* pfdata = &state;
    return dce2_tcp_paf(pfdata, flow, data, len, flags, fp);
}

