//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb_paf.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_module.h"
#include "dce_smb_paf.h"
#include "dce_smb.h"
#include "trace/trace_api.h"
#include "utils/util.h"

namespace
{
inline void DCE2_SMB_PAF_SHIFT(uint64_t& x64, const uint8_t& x8)
{
    x64 <<= 8;
    x64 |= (uint64_t)x8;
}
}

using namespace snort;

/*********************************************************************
 * Function: DCE2_PafSmbIsValidNetbiosHdr()
 *
 * Purpose: Validates that the NetBIOS header is valid.  If in
 *          junk states, header type must be Session Message.
 *
 *********************************************************************/
static inline bool DCE2_PafSmbIsValidNetbiosHdr(uint32_t nb_hdr, bool junk, uint32_t smb_id,
    uint32_t* nb_len, uint32_t* nbs_hdr_out = nullptr)
{
    uint8_t type = (uint8_t)(nb_hdr >> 24);
    uint8_t bit = (uint8_t)((nb_hdr & 0x00ff0000) >> 16);
    uint32_t nbs_hdr = htonl(nb_hdr);

    if (junk)
    {
        if (type != NBSS_SESSION_TYPE__MESSAGE)
            return false;
    }
    else
    {
        if ( !NbssIsKnownCtrlType(type) )
            return false;
    }
    //The bit should be checked only for SMB1, because the length in NetBIOS header should not
    // exceed 0x1FFFF.
    //See [MS-SMB] 2.1 Transport. There is no such limit for SMB2 or SMB3
    if (smb_id == DCE2_SMB_ID)
    {
        if ((bit != 0x00) and (bit != 0x01))
            return false;
    }
    NbssHdr nb_struct;
    memcpy(&nb_struct, &nbs_hdr, sizeof(nb_struct));
    const NbssHdr* nb = &nb_struct;

    // Keep-alives are header-only even when their advertised length is nonzero.
    // Validate the fixed trailer size of every other control frame before a
    // flush point exists.  This has to happen here rather than in
    // DCE2_NbssHdrChecks(): the inspector only runs once the pseudo-packet has
    // been built and the detection pass bound to it, so rejecting there saves nothing.
    if ( !junk and !NbssIsEmptyCtrl(nb) and !NbssIsValidCtrlLen(nb) )
    {
        dce2_smb_stats.smb_nbss_hdr_rejected++;
        return false;
    }

    if ( nbs_hdr_out )
        *nbs_hdr_out = nbs_hdr;

    if ( NbssIsEmptyCtrl(nb) )
        *nb_len = 0;
    else if (smb_id == DCE2_SMB2_ID)
        *nb_len = NbssLen2(nb);
    else
        *nb_len = NbssLen(nb);

    return true;
}

// A flush carries any accumulated empty frames out with it, from either the
// state 3 or the state 7 path, so both sites must clear the accumulator.
static inline void DCE2_PafSmbEndBatch(DCE2_PafSmbData* ss)
{
    if ( ss->empty_nbss_bytes )
    {
        dce2_smb_stats.smb_empty_nbss_batches++;
        ss->empty_nbss_bytes = 0;
    }
}

/*********************************************************************
 * Function: DCE2_SmbPaf()
 *
 * Purpose: The DCE/RPC over SMB PAF callback.
 *          Inspects a byte at a time changing state and shifting
 *          bytes onto the 64bit nb_hdr member.  At state 3
 *          determines if NetBIOS header is valid and if so sets
 *          flush point.  If not valid goes to states 4-7 where
 *          there is the possibility that junk data was inserted
 *          before request/response.  Needs to validate SMB ID at
 *          this point.  At state 7 determines if NetBIOS header
 *          is valid and that the SMB ID is present.  Stays in
 *          state 7 until this is the case.
 *
 *********************************************************************/
static StreamSplitter::Status dce2_smb_paf(DCE2_PafSmbData* ss, Flow* flow, const uint8_t* data,
    uint32_t len, uint32_t, uint32_t* fp, uint32_t batch_max)
{
    uint32_t n = 0;
    StreamSplitter::Status ps = StreamSplitter::SEARCH;
    const SmbNtHdr* nt_hdr = nullptr;
    uint32_t nb_len = 0;

    const DCE2_SsnData* sd = get_dce2_session_data(flow);

    if ( dce2_paf_abort(sd) )
    {
        return StreamSplitter::ABORT;
    }

    while (n < len)
    {
        switch (ss->paf_state)
        {
        case DCE2_PAF_SMB_STATES__0:
            ss->nb_hdr = (uint64_t)data[n];
            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        case DCE2_PAF_SMB_STATES__3:
        {
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);
            //(data + n + 1) points to the SMB header protocol identifier
            //(0xFF,'SMB' or 0xFE,'SMB'), which follows the NetBIOS header
            if (len >= DCE2_SMB_ID_SIZE + n + 1) // NetBIOS header and 4 bytes SMB header
                nt_hdr = reinterpret_cast<const SmbNtHdr*>(data + n + 1);
            else
                nt_hdr = nullptr;   // nt_hdr is loop-scoped; don't reuse a prior frame's
            uint32_t smb_id = nt_hdr ? SmbId(nt_hdr) : 0;
            uint32_t nbs_hdr_val = 0;
            if (DCE2_PafSmbIsValidNetbiosHdr((uint32_t)ss->nb_hdr, false, smb_id,
                &nb_len, &nbs_hdr_val))
            {
                // Keep-alive frames carry no SMB message. Accumulate them and
                // let the next real message -- or the cap -- carry them out.
                if (NbssIsEmptyCtrl(reinterpret_cast<const NbssHdr*>(&nbs_hdr_val)) and
                    ss->empty_nbss_bytes + sizeof(NbssHdr) < batch_max)
                {
                    ss->empty_nbss_bytes += sizeof(NbssHdr);
                    ss->paf_state = DCE2_PAF_SMB_STATES__0;
                    break;
                }
                DCE2_PafSmbEndBatch(ss);

                *fp = (nb_len + sizeof(NbssHdr) + n) - ss->paf_state;
                ss->paf_state = DCE2_PAF_SMB_STATES__0;
                return StreamSplitter::FLUSH;
            }

            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        }
        case DCE2_PAF_SMB_STATES__7:
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);

            //ss->nb_hdr is the value to 4 bytes of NetBIOS header + 4 bytes of
            //SMB header protocol identifier. Use both halves directly so a
            //protocol identifier that spans scan buffers remains valid.
            if (!DCE2_PafSmbIsValidNetbiosHdr((uint32_t)(ss->nb_hdr >> 32), true,
                (uint32_t)ss->nb_hdr, &nb_len) || nb_len < DCE2_SMB_ID_SIZE)
            {
                break;
            }
            if (((uint32_t)ss->nb_hdr != DCE2_SMB_ID)
                && ((uint32_t)ss->nb_hdr != DCE2_SMB2_ID))
            {
                break;
            }

            DCE2_PafSmbEndBatch(ss);
            *fp = (nb_len + sizeof(NbssHdr) + n) - ss->paf_state;
            ss->paf_state = DCE2_PAF_SMB_STATES__0;

            return StreamSplitter::FLUSH;
        default:
            DCE2_SMB_PAF_SHIFT(ss->nb_hdr, data[n]);
            ss->paf_state = (DCE2_PafSmbStates)(((int)ss->paf_state) + 1);
            break;
        }

        n++;
    }

    return ps;
}

Dce2SmbSplitter::Dce2SmbSplitter(bool c2s) :   StreamSplitter(c2s)
{
    state.paf_state = DCE2_PAF_SMB_STATES__0;
    state.nb_hdr = 0;
    state.empty_nbss_bytes = 0;
}

StreamSplitter::Status Dce2SmbSplitter::scan(
    Packet* pkt, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    DCE2_PafSmbData* pfdata = &state;
    // Cap the batch at max()/16 so a batch stays small relative to paf_max.
    // Floor at 256 bytes (64 keep-alives) as minimum meaningful batch.
    uint32_t paf_max = max(pkt->flow);
    uint32_t batch_max = (paf_max / 16 > 256) ? paf_max / 16 : 256;
    StreamSplitter::Status ps = dce2_smb_paf(pfdata, pkt->flow, data, len, flags, fp, batch_max);
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, pkt,
        "Dce2SmbSplitter scan with length %u, status %d and fp %u\n", len, ps, *fp);
    return ps;
}
