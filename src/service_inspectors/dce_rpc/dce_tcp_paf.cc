//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "dce_common.h"
#include "dce_tcp.h"

using namespace snort;

Dce2TcpSplitter::Dce2TcpSplitter(bool c2s) :   StreamSplitter(c2s)
{
    state.paf_state = DCE2_PAF_TCP_STATES__0;
    state.byte_order = DCERPC_BO_FLAG__NONE;
    state.frag_len = 0;
    state.autodetected = false;
}

/*********************************************************************
 * Purpose: The DCE/RPC over TCP PAF callback.
 *          Inspects a byte at a time changing state.  At state 4
 *          gets byte order of PDU.  At states 8 and 9 gets
 *          fragment length and sets flush point if no more data.
 *          Otherwise accumulates flush points because there can
 *          be multiple PDUs in a single TCP segment (evasion case).
 *
 *********************************************************************/
StreamSplitter::Status Dce2TcpSplitter::scan(
    Packet* pkt, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    DCE2_TcpSsnData* sd = get_dce2_tcp_session_data(pkt->flow);

    if (dce2_paf_abort((DCE2_SsnData*)sd))
        return StreamSplitter::ABORT;

    uint32_t n = 0;
    uint32_t new_fp = 0;
    int start_state = (uint8_t)state.paf_state;
    int num_requests = 0;

    while (n < len)
    {
        switch (state.paf_state)
        {
        case DCE2_PAF_TCP_STATES__0:    // Major version
            if (!sd && !state.autodetected) // Autodetection validation
            {
                if (data[n] != DCERPC_PROTO_MAJOR_VERS__5)
                    return StreamSplitter::ABORT;
                if (len < sizeof(DceRpcCoHdr) && (flags & PKT_FROM_CLIENT))
                    state.autodetected = true;
            }
            break;
        case DCE2_PAF_TCP_STATES__1:    // Minor version
            if (!sd && !state.autodetected) // Autodetection validation
            {
                if (data[n] != DCERPC_PROTO_MINOR_VERS__0)
                    return StreamSplitter::ABORT;
            }
            break;
        case DCE2_PAF_TCP_STATES__2:    // PDU type
            if (!sd && !state.autodetected) // Autodetection validation
            {
                if (((flags & PKT_FROM_CLIENT) && data[n] != DCERPC_PDU_TYPE__BIND) ||
                    ((flags & PKT_FROM_SERVER) && data[n] != DCERPC_PDU_TYPE__BIND_ACK))
                    return StreamSplitter::ABORT;
            }
            break;
        case DCE2_PAF_TCP_STATES__4:    // Byte order
            state.byte_order = DceRpcByteOrder(data[n]);
            break;
        case DCE2_PAF_TCP_STATES__8:    // First byte of fragment length
            if (state.byte_order == DCERPC_BO_FLAG__LITTLE_ENDIAN)
                state.frag_len = data[n];
            else
                state.frag_len = data[n] << 8;
            break;
        case DCE2_PAF_TCP_STATES__9:    // Second byte of fragment length
            if (state.byte_order == DCERPC_BO_FLAG__LITTLE_ENDIAN)
                state.frag_len |= data[n] << 8;
            else
                state.frag_len |= data[n];

            /* Abort if we get a bad frag length */
            if (state.frag_len < sizeof(DceRpcCoHdr))
            {
                if (sd)
                    dce_alert(GID_DCE2, DCE2_CO_FRAG_LEN_LT_HDR, (dce2CommonStats*)&dce2_tcp_stats,
                        *(DCE2_SsnData*)sd);
                return StreamSplitter::ABORT;
            }

            /* In the non-degenerate case, we can now declare that we think this looks like DCE */
            if (!state.autodetected)
                state.autodetected = true;

            /* Increment n here so we can continue */
            n += state.frag_len - (uint8_t)state.paf_state;
            num_requests++;
            /* Might have multiple PDUs in one segment.  If the last PDU is partial,
             * flush just before it */
            if ((num_requests == 1) || (n <= len))
                new_fp += state.frag_len;

            state.paf_state = DCE2_PAF_TCP_STATES__0;
            continue;      // we incremented n and set the state already
        default:
            break;
        }

        state.paf_state = (DCE2_PafTcpStates)(((int)state.paf_state) + 1);
        n++;
    }

    if (new_fp != 0)
    {
        *fp = new_fp - start_state;
        return StreamSplitter::FLUSH;
    }

    return StreamSplitter::SEARCH;
}

